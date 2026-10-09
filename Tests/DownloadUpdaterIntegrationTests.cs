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
    public async Task SignedClientDownloadFlowsFromServerThroughVerificationIntoReleaseStaging()
    {
        var root = Path.Combine(Path.GetTempPath(), "lancer-download-updater-e2e-" + Guid.NewGuid().ToString("N"));
        var manifestRoot = Path.Combine(root, "manifests");
        var artifactRoot = Path.Combine(root, "artifacts");
        var cacheRoot = Path.Combine(root, "cache");
        var clientBytes = CreateClientArchive();
        var hash = Convert.ToHexString(SHA256.HashData(clientBytes)).ToLowerInvariant();
        var artifactPath = Path.Combine(artifactRoot, "sha256", hash[..2], hash);
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        Directory.CreateDirectory(cacheRoot);
        await File.WriteAllBytesAsync(artifactPath, clientBytes);

        var package = new UpdatePackage("client", "1.0.0", $"artifacts/{hash[..2]}/{hash}",
            clientBytes.Length, hash, true, "tar.zst");
        var now = DateTime.UtcNow;
        var platform = OperatingSystem.IsWindows() ? "win" : "linux";
        var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
        var manifest = new UpdateManifest(1, 1, "stable", platform, "x64", "1.0.0", "1.0.0", 1,
            now.AddMinutes(-1), now.AddHours(1), [package])
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
        var manifestPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
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

            using (var handler = Rewriter(app.GetTestServer().CreateHandler()))
            {
                var downloadedPath = await ArtifactDownloader.DownloadVerifiedAsync(
                    package, options, CancellationToken.None, handler);
                Assert.Equal(clientBytes, await File.ReadAllBytesAsync(downloadedPath));
                Assert.Equal(hash + ".package", Path.GetFileName(downloadedPath));

                var staged = await ReleaseStager.StageClientAsync(
                    verifiedManifest, package, downloadedPath, options, CancellationToken.None);
                Assert.True(File.Exists(Path.Combine(staged, executableName)));
                Assert.Equal("synthetic client executable"u8.ToArray(),
                    await File.ReadAllBytesAsync(Path.Combine(staged, executableName)));
                Assert.Equal("client payload"u8.ToArray(),
                    await File.ReadAllBytesAsync(Path.Combine(staged, "assets", "marker.dat")));
                Assert.True(File.Exists(Path.Combine(staged, "client-version.json")));

                await DataPackageStager.WriteSnapshotAsync(staged, verifiedManifest, options.OptionalDataPackages,
                    new Dictionary<string, string>(), CancellationToken.None);
                var activeRelease = ReleaseActivator.Activate(staged, verifiedManifest, package, options);
                Assert.True(Directory.Exists(activeRelease));
                Assert.True(ReleaseActivator.IsCurrentVerified(verifiedManifest, package, options));
                Assert.True(File.Exists(Path.Combine(options.InstallRootPath, "current.json")));
            }
        }
        finally
        {
            await app.DisposeAsync();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
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
