using System.Buffers.Binary;
using System.Formats.Tar;
using System.Security.Cryptography;
using System.Text.Json;
using LancerNexus.Download;
using LancerNexus.Updater;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Download.Tests;

public sealed class DownloadUpdaterIntegrationTests
{
    [Fact]
    public async Task SignedClientAndNapPackagesFlowFromServerIntoOneActivatedRelease()
    {
        var root = Path.Combine(Path.GetTempPath(), "lancer-download-updater-e2e-" + Guid.NewGuid().ToString("N"));
        var manifestRoot = Path.Combine(root, "manifests");
        var artifactRoot = Path.Combine(root, "artifacts");
        var cacheRoot = Path.Combine(root, "cache");
        var clientBytes = CreateClientArchive();
        var hash = Convert.ToHexString(SHA256.HashData(clientBytes)).ToLowerInvariant();
        var clientArtifactPath = Path.Combine(artifactRoot, "sha256", hash[..2], hash);
        var dataBytes = CreateNapPackage("synthetic/game-data.txt", "synthetic NAP game data"u8.ToArray());
        var dataHash = Convert.ToHexString(SHA256.HashData(dataBytes)).ToLowerInvariant();
        var dataArtifactPath = Path.Combine(artifactRoot, "sha256", dataHash[..2], dataHash);
        Directory.CreateDirectory(Path.GetDirectoryName(clientArtifactPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(dataArtifactPath)!);
        Directory.CreateDirectory(cacheRoot);
        await File.WriteAllBytesAsync(clientArtifactPath, clientBytes);
        await File.WriteAllBytesAsync(dataArtifactPath, dataBytes);

        var package = new UpdatePackage("client", "1.0.0", $"artifacts/{hash[..2]}/{hash}",
            clientBytes.Length, hash, true, "tar.zst");
        var dataPackage = new UpdatePackage("core", "1.0.0", $"artifacts/{dataHash[..2]}/{dataHash}",
            dataBytes.Length, dataHash, true, "nap")
        {
            ContentVersion = 1,
            Priority = 100,
            MountOrder = 1
        };
        var now = DateTime.UtcNow;
        var platform = OperatingSystem.IsWindows() ? "win" : "linux";
        var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
        var manifest = new UpdateManifest(1, 1, "stable", platform, "x64", "1.0.0", "1.0.0", 1,
            now.AddMinutes(-1), now.AddHours(1), [package, dataPackage])
        {
            BuildId = "synthetic-build-1",
            DataManifestId = "synthetic-data-1",
            Capabilities = ["client_version_hello_v1"]
        };
        var privateKey = new Ed25519PrivateKeyParameters(Enumerable.Repeat((byte)7, 32).ToArray(), 0);
        var publicKey = privateKey.GeneratePublicKey().GetEncoded();
        var signedPayload = ManifestCanonicalizer.Serialize(manifest);
        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        signer.BlockUpdate(signedPayload, 0, signedPayload.Length);
        var envelope = new SignedManifest(Convert.ToBase64String(signedPayload),
        [
            new ManifestSignature("integration-key", "Ed25519", Convert.ToBase64String(signer.GenerateSignature()))
        ]);
        var manifestPath = Path.Combine(manifestRoot, "stable", $"{platform}-x64.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
        await File.WriteAllBytesAsync(manifestPath, JsonSerializer.SerializeToUtf8Bytes(envelope, TrustRoot.JsonOptions));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Download:ManifestRoot"] = manifestRoot,
            ["Download:ArtifactRoot"] = artifactRoot,
            ["Download:Platform"] = platform,
            ["Download:Architecture"] = "x64"
        });
        var app = DownloadServer.Build(builder);
        try
        {
            await app.StartAsync();
            var manifestUri = new Uri("https://downloads.example.test/v1/channels/stable/manifest");
            var artifactBaseUri = new Uri("https://downloads.example.test/v1/");
            var options = new UpdaterOptions(manifestUri, "stable", platform, "x64", "unused-trust-root.json",
                ArtifactBaseUri: artifactBaseUri, CachePath: cacheRoot, InstallRootPath: Path.Combine(root, "install"));
            var trustRoot = new TrustRoot(1, 1,
                [new TrustedKey("integration-key", "Ed25519", Convert.ToBase64String(publicKey))], 1);

            UpdateManifest verifiedManifest;
            using (var handler = Rewriter(app.GetTestServer().CreateHandler()))
            {
                var downloadedEnvelope = await ManifestClient.LoadAsync(manifestUri, CancellationToken.None, handler);
                verifiedManifest = ManifestVerifier.Validate(downloadedEnvelope, trustRoot, options, DateTime.UtcNow);
                Assert.Equal("1.0.0", verifiedManifest.ClientVersion);
            }

            string downloadedPath;
            using (var handler = Rewriter(app.GetTestServer().CreateHandler()))
                downloadedPath = await ArtifactDownloader.DownloadVerifiedAsync(
                    package, options, CancellationToken.None, handler);
            string downloadedDataPath;
            using (var handler = Rewriter(app.GetTestServer().CreateHandler()))
                downloadedDataPath = await ArtifactDownloader.DownloadVerifiedAsync(
                    dataPackage, options, CancellationToken.None, handler);
            Assert.Equal(clientBytes, await File.ReadAllBytesAsync(downloadedPath));
            Assert.Equal(hash + ".package", Path.GetFileName(downloadedPath));
            Assert.Equal(dataBytes, await File.ReadAllBytesAsync(downloadedDataPath));
            Assert.Equal(dataHash + ".package", Path.GetFileName(downloadedDataPath));

            var staged = await ReleaseStager.StageClientAsync(
                verifiedManifest, package, downloadedPath, options, CancellationToken.None);
            Assert.True(File.Exists(Path.Combine(staged, executableName)));
            Assert.Equal("synthetic client executable"u8.ToArray(),
                await File.ReadAllBytesAsync(Path.Combine(staged, executableName)));
            Assert.Equal("client payload"u8.ToArray(),
                await File.ReadAllBytesAsync(Path.Combine(staged, "assets", "marker.dat")));
            Assert.True(File.Exists(Path.Combine(staged, "client-version.json")));

            await DataPackageStager.WriteSnapshotAsync(staged, verifiedManifest, options.OptionalDataPackages,
                new Dictionary<string, string> { [dataPackage.Id] = downloadedDataPath }, CancellationToken.None);
            var snapshotPath = Path.Combine(staged, "packages", "active.json");
            Assert.True(File.Exists(snapshotPath));
            var stagedNapPath = Path.Combine(staged, "packages", "content", dataHash + ".nap");
            Assert.Equal(dataBytes, await File.ReadAllBytesAsync(stagedNapPath));
            var napMetadata = NapPackageVerifier.VerifyFile(stagedNapPath);
            Assert.Equal((ulong)1, napMetadata.ContentVersion);
            Assert.Equal(["synthetic/game-data.txt"], napMetadata.EntryPaths);
            var activeRelease = ReleaseActivator.Activate(staged, verifiedManifest, package, options);
            Assert.True(Directory.Exists(activeRelease));
            Assert.True(ReleaseActivator.IsCurrentVerified(verifiedManifest, package, options));
            Assert.True(File.Exists(Path.Combine(options.InstallRootPath, "current.json")));
        }
        finally
        {
            await app.DisposeAsync();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] CreateNapPackage(string entryPath, byte[] content)
    {
        var path = System.Text.Encoding.UTF8.GetBytes(entryPath);
        var contentHash = SHA256.HashData(content);
        using var indexStream = new MemoryStream();
        using (var index = new BinaryWriter(indexStream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            index.Write("NAPIDX1\0"u8);
            index.Write((uint)1);
            index.Write((ushort)path.Length);
            index.Write(path);
            index.Write((byte)0);
            index.Write((ulong)content.Length);
            index.Write(contentHash);
            index.Write((uint)1);
            index.Write((uint)0);
        }
        var indexBytes = indexStream.ToArray();
        var chunkOffset = 128L + indexBytes.Length;
        var payloadOffset = chunkOffset + 64;
        var header = new byte[128];
        new byte[] { 0x4c, 0x4e, 0x41, 0x50, 0x00, 0x0d, 0x0a, 0x1a }.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(10), 128);
        Guid.NewGuid().TryWriteBytes(header.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(32), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(40), 1024);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(48), 128);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(56), (ulong)indexBytes.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(64), (ulong)chunkOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(72), 64);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(80), (ulong)payloadOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(88), (ulong)content.Length);
        SHA256.HashData(indexBytes).CopyTo(header, 96);

        var chunk = new byte[64];
        contentHash.CopyTo(chunk, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(32), (ulong)content.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(40), (ulong)content.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(48), (ulong)payloadOffset);
        using var archive = new MemoryStream();
        archive.Write(header);
        archive.Write(indexBytes);
        archive.Write(chunk);
        archive.Write(content);
        return archive.ToArray();
    }

    private static byte[] CreateClientArchive()
    {
        var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
        using var tarBytes = new MemoryStream();
        using (var tar = new TarWriter(tarBytes, TarEntryFormat.Pax, leaveOpen: true))
        {
            WriteEntry(tar, $"client-1.0.0/{executableName}", "synthetic client executable"u8.ToArray());
            WriteEntry(tar, "client-1.0.0/assets/marker.dat", "client payload"u8.ToArray());
        }

        using var compressed = new MemoryStream();
        using (var zstd = new ZstdSharp.CompressionStream(compressed, 3, 0, leaveOpen: true))
            tarBytes.WriteTo(zstd);
        return compressed.ToArray();
    }

    private static void WriteEntry(TarWriter tar, string name, byte[] bytes)
    {
        var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(bytes),
            Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
        };
        tar.WriteEntry(entry);
        entry.DataStream.Dispose();
    }

    private static HttpMessageHandler Rewriter(HttpMessageHandler inner) => new HttpsTestHostHandler(inner);

    private sealed class HttpsTestHostHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri ?? throw new InvalidOperationException("Request URI is missing.");
            if (uri.Scheme != Uri.UriSchemeHttps || uri.Host != "downloads.example.test")
                throw new InvalidOperationException("Unexpected test download origin.");
            request.RequestUri = new Uri("http://localhost" + uri.PathAndQuery);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
