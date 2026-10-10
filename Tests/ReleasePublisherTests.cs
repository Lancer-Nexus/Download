using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Download;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Download.Tests;

public sealed class ReleasePublisherTests
{
    private static readonly DateTime Now = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task PublisherCliActivatesSignedReleaseAndRejectsVersionReplay()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-cli-" + Guid.NewGuid().ToString("N"));
        try
        {
            var now = DateTime.UtcNow;
            var artifactRoot = Path.Combine(rootPath, "artifacts");
            var sourceRoot = Path.Combine(rootPath, "source");
            var manifestRoot = Path.Combine(rootPath, "manifests");
            var auditRoot = Path.Combine(rootPath, "audit");
            var trustRootPath = Path.Combine(rootPath, "trust-root.json");
            var manifestPath = Path.Combine(rootPath, "manifest.json");
            var content = "Publisher CLI release artifact"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var sourcePath = Path.Combine(sourceRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(sourcePath)!);
            await File.WriteAllBytesAsync(sourcePath, content);

            var package = new UpdatePackage("client", "2.4.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 4, "stable", "linux", "x64", "2.4.0", "1.0.0", 1,
                now.AddMinutes(-1), now.AddHours(1), [package])
            {
                BuildId = "publisher-cli-build",
                DataManifestId = "publisher-cli-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            await File.WriteAllBytesAsync(manifestPath, JsonSerializer.SerializeToUtf8Bytes(envelope, TrustRoot.JsonOptions));
            await File.WriteAllBytesAsync(trustRootPath, JsonSerializer.SerializeToUtf8Bytes(trustRoot, TrustRoot.JsonOptions));

            var first = await RunPublisherAsync(manifestPath, trustRootPath, sourceRoot, artifactRoot,
                manifestRoot, auditRoot);

            Assert.True(first.ExitCode == 0,
                $"Publisher exited with {first.ExitCode}. stdout: {first.StandardOutput} stderr: {first.StandardError}");
            Assert.Contains("Published stable/linux-x64 manifest version 4", first.StandardOutput);
            Assert.Equal(content, await File.ReadAllBytesAsync(Path.Combine(artifactRoot, "sha256", digest[..2], digest)));
            Assert.True(File.Exists(Path.Combine(manifestRoot, "stable", "linux-x64.json")));
            Assert.Equal(2, Directory.GetFiles(auditRoot, "*.json").Length);

            var replay = await RunPublisherAsync(manifestPath, trustRootPath, sourceRoot, artifactRoot,
                manifestRoot, auditRoot);

            Assert.Equal(1, replay.ExitCode);
            Assert.Contains("Manifest-Version muss gegenüber der aktiven Version steigen", replay.StandardError);
            Assert.Equal(2, Directory.GetFiles(auditRoot, "*.json").Length);
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublisherCliReportsMalformedManifestWithoutUnhandledProcessFailure()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-invalid-cli-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(rootPath);
            var manifestPath = Path.Combine(rootPath, "manifest.json");
            await File.WriteAllTextAsync(manifestPath, "{ invalid json");

            var result = await RunPublisherAsync(manifestPath, Path.Combine(rootPath, "unused-trust-root.json"),
                Path.Combine(rootPath, "source"), Path.Combine(rootPath, "artifacts"),
                Path.Combine(rootPath, "manifests"), Path.Combine(rootPath, "audit"));

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("Release publication failed:", result.StandardError);
            Assert.DoesNotContain("Unhandled exception", result.StandardError);
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublishesArtifactsAndRecoversActivationAuditAfterInterruption()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var inputRoot = Path.Combine(rootPath, "input");
            var outputRoot = Path.Combine(rootPath, "served-artifacts");
            var manifests = Path.Combine(rootPath, "manifests");
            var audit = Path.Combine(rootPath, "audit");
            var content = "signed release artifact"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var source = Path.Combine(inputRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            await File.WriteAllBytesAsync(source, content);
            var package = new UpdatePackage("client", "1.0.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
                Now.AddMinutes(-1), Now.AddHours(1), [package])
            {
                BuildId = "publisher-test-build",
                DataManifestId = "publisher-test-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            var options = new UpdaterOptions(new Uri("https://downloads.example.test/v1/channels/stable/manifest"),
                "stable", "linux", "x64", "unused");

            foreach (var publicAuditRoot in new[]
                     {
                         Path.Combine(outputRoot, "audit"),
                         Path.Combine(manifests, "audit")
                     })
            {
                await Assert.ThrowsAsync<InvalidDataException>(() =>
                    ReleasePublisher.PublishAsync(envelope, trustRoot, options, inputRoot, outputRoot,
                        manifests, publicAuditRoot, Now));
            }
            Assert.False(Directory.Exists(outputRoot));

            await ReleasePublisher.PublishAsync(envelope, trustRoot, options, inputRoot, outputRoot, manifests, audit, Now);

            Assert.Equal(content, await File.ReadAllBytesAsync(Path.Combine(outputRoot, "sha256", digest[..2], digest)));
            var activeManifest = Path.Combine(manifests, "stable", "linux-x64.json");
            var activatedBytes = await File.ReadAllBytesAsync(activeManifest);
            Assert.Equal(JsonSerializer.Serialize(envelope, TrustRoot.JsonOptions),
                System.Text.Encoding.UTF8.GetString(activatedBytes));
            var auditRecords = Directory.GetFiles(audit, "*.json").Select(path =>
                JsonDocument.Parse(File.ReadAllBytes(path))).ToArray();
            Assert.Equal(new[] { "activated", "prepared" }, auditRecords
                .Select(record => record.RootElement.GetProperty("event").GetString())
                .Order(StringComparer.Ordinal).ToArray());
            Assert.Single(auditRecords.Select(record => record.RootElement.GetProperty("publicationId").GetString()).Distinct());
            Assert.All(auditRecords, record =>
                Assert.Equal(digest, record.RootElement.GetProperty("packages")[0].GetProperty("sha256").GetString()));
            Assert.All(auditRecords, record =>
                Assert.Contains("Ed25519:publisher-test-key",
                    record.RootElement.GetProperty("signatureKeyIds").EnumerateArray().Select(key => key.GetString())));
            Assert.All(auditRecords, record =>
                Assert.Equal(64, record.RootElement.GetProperty("trustRootSha256").GetString()!.Length));

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ReleasePublisher.PublishAsync(envelope, trustRoot, options, inputRoot, outputRoot, manifests, audit, Now));

            Assert.Equal(activatedBytes, await File.ReadAllBytesAsync(activeManifest));
            Assert.Equal(2, Directory.GetFiles(audit, "*.json").Length);

            var nextPackage = package with { Version = "1.1.0" };
            var nextManifest = manifest with
            {
                Version = 2,
                ClientVersion = "1.1.0",
                Packages = [nextPackage],
                BuildId = "publisher-test-build-2"
            };
            var (nextEnvelope, _) = Sign(nextManifest);
            var blockedAuditRoot = Path.Combine(rootPath, "audit-root-is-a-file");
            await File.WriteAllTextAsync(blockedAuditRoot, "not a directory");
            await Assert.ThrowsAsync<IOException>(() =>
                ReleasePublisher.PublishAsync(nextEnvelope, trustRoot, options, inputRoot, outputRoot,
                    manifests, blockedAuditRoot, Now));
            Assert.Equal(activatedBytes, await File.ReadAllBytesAsync(activeManifest));

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                ReleasePublisher.PublishAsync(nextEnvelope, trustRoot, options, inputRoot, outputRoot,
                    manifests, audit, Now, boundary =>
                    {
                        if (boundary == ReleasePublisher.PublicationBoundary.ManifestActivated)
                            throw new InvalidOperationException("Synthetic interruption after manifest activation.");
                    }, CancellationToken.None));

            Assert.Single(Directory.GetFiles(audit, ".*.activated.pending"));
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ReleasePublisher.PublishAsync(nextEnvelope, trustRoot, options, inputRoot, outputRoot,
                    manifests, audit, Now));

            Assert.Empty(Directory.GetFiles(audit, ".*.activated.pending"));
            var recoveredRecords = Directory.GetFiles(audit, "*.json").Select(path =>
                JsonDocument.Parse(File.ReadAllBytes(path))).ToArray();
            Assert.Equal(2, recoveredRecords.Count(record =>
                record.RootElement.GetProperty("event").GetString() == "activated"));
            Assert.Equal(2, recoveredRecords.Count(record =>
                record.RootElement.GetProperty("event").GetString() == "prepared"));

            var finalPackage = nextPackage with { Version = "1.2.0" };
            var finalManifest = nextManifest with
            {
                Version = 3,
                ClientVersion = "1.2.0",
                Packages = [finalPackage],
                BuildId = "publisher-test-build-3"
            };
            var (finalEnvelope, _) = Sign(finalManifest);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                ReleasePublisher.PublishAsync(finalEnvelope, trustRoot, options, inputRoot, outputRoot,
                    manifests, audit, Now, boundary =>
                    {
                        if (boundary == ReleasePublisher.PublicationBoundary.ActivationAuditPrepared)
                            throw new InvalidOperationException("Synthetic interruption before manifest activation.");
                    }, CancellationToken.None));

            await ReleasePublisher.PublishAsync(finalEnvelope, trustRoot, options, inputRoot, outputRoot,
                manifests, audit, Now);

            Assert.Empty(Directory.GetFiles(audit, ".*.activated.pending"));
            var finalRecords = Directory.GetFiles(audit, "*.json").Select(path =>
                JsonDocument.Parse(File.ReadAllBytes(path))).ToArray();
            Assert.Equal(3, finalRecords.Count(record =>
                record.RootElement.GetProperty("event").GetString() == "activated"));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task InvalidArtifactDoesNotActivateManifestOrReplaceExistingHashPath()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var content = "expected bytes"u8.ToArray();
            var wrongContent = "different bytes"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var inputRoot = Path.Combine(rootPath, "input");
            var outputRoot = Path.Combine(rootPath, "served-artifacts");
            var manifests = Path.Combine(rootPath, "manifests");
            var audit = Path.Combine(rootPath, "audit");
            var source = Path.Combine(inputRoot, "sha256", digest[..2], digest);
            var existing = Path.Combine(outputRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
            await File.WriteAllBytesAsync(source, wrongContent);
            await File.WriteAllBytesAsync(existing, wrongContent);
            var package = new UpdatePackage("client", "1.0.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
                Now.AddMinutes(-1), Now.AddHours(1), [package])
            {
                BuildId = "publisher-test-build",
                DataManifestId = "publisher-test-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            var options = new UpdaterOptions(new Uri("https://downloads.example.test/v1/channels/stable/manifest"),
                "stable", "linux", "x64", "unused");

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ReleasePublisher.PublishAsync(envelope, trustRoot, options, inputRoot, outputRoot, manifests, audit, Now));

            Assert.False(File.Exists(Path.Combine(manifests, "stable", "linux-x64.json")));
            Assert.Equal(wrongContent, await File.ReadAllBytesAsync(existing));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublisherDoesNotWriteThroughArtifactDirectorySymlink()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var content = "symlink target must stay untouched"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var inputRoot = Path.Combine(rootPath, "input");
            var outputRoot = Path.Combine(rootPath, "served-artifacts");
            var manifests = Path.Combine(rootPath, "manifests");
            var audit = Path.Combine(rootPath, "audit");
            var outside = Path.Combine(rootPath, "outside");
            var source = Path.Combine(inputRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            Directory.CreateDirectory(Path.Combine(outputRoot, "sha256"));
            Directory.CreateDirectory(outside);
            await File.WriteAllBytesAsync(source, content);
            Directory.CreateSymbolicLink(Path.Combine(outputRoot, "sha256", digest[..2]), outside);

            var package = new UpdatePackage("client", "1.0.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
                Now.AddMinutes(-1), Now.AddHours(1), [package])
            {
                BuildId = "publisher-symlink-test",
                DataManifestId = "publisher-symlink-test-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            var options = new UpdaterOptions(new Uri("https://downloads.example.test/v1/channels/stable/manifest"),
                "stable", "linux", "x64", "unused");

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishAsync(envelope, trustRoot,
                options, inputRoot, outputRoot, manifests, audit, Now));

            Assert.Empty(Directory.GetFiles(outside));
            Assert.False(File.Exists(Path.Combine(manifests, "stable", "linux-x64.json")));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublisherRejectsAuditRootThatIsASymbolicLink()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var content = "audit must not escape"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var inputRoot = Path.Combine(rootPath, "input");
            var outputRoot = Path.Combine(rootPath, "served-artifacts");
            var manifests = Path.Combine(rootPath, "manifests");
            var auditLink = Path.Combine(rootPath, "audit-link");
            var outside = Path.Combine(rootPath, "outside-audit");
            var source = Path.Combine(inputRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            Directory.CreateDirectory(outside);
            await File.WriteAllBytesAsync(source, content);
            Directory.CreateSymbolicLink(auditLink, outside);

            var package = new UpdatePackage("client", "1.0.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
                Now.AddMinutes(-1), Now.AddHours(1), [package])
            {
                BuildId = "publisher-audit-symlink-test",
                DataManifestId = "publisher-audit-symlink-test-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            var options = new UpdaterOptions(new Uri("https://downloads.example.test/v1/channels/stable/manifest"),
                "stable", "linux", "x64", "unused");

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishAsync(envelope, trustRoot,
                options, inputRoot, outputRoot, manifests, auditLink, Now));

            Assert.Empty(Directory.GetFiles(outside));
            Assert.False(Directory.Exists(outputRoot));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublisherRejectsSymlinkedPublicationLockWithoutChangingItsTarget()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var content = "publication lock target must stay unchanged"u8.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            var inputRoot = Path.Combine(rootPath, "input");
            var outputRoot = Path.Combine(rootPath, "served-artifacts");
            var manifests = Path.Combine(rootPath, "manifests");
            var audit = Path.Combine(rootPath, "audit");
            var source = Path.Combine(inputRoot, "sha256", digest[..2], digest);
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            await File.WriteAllBytesAsync(source, content);
            var target = Path.Combine(rootPath, "outside-lock-target");
            const string targetContents = "preserve this lock target";
            await File.WriteAllTextAsync(target, targetContents);
            var activeDirectory = Path.Combine(manifests, "stable");
            Directory.CreateDirectory(activeDirectory);
            var activePath = Path.Combine(activeDirectory, "linux-x64.json");
            File.CreateSymbolicLink(activePath + ".publish.lock", target);

            var package = new UpdatePackage("client", "1.0.0", $"artifacts/{digest[..2]}/{digest}",
                content.Length, digest, true, "tar.zst");
            var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
                Now.AddMinutes(-1), Now.AddHours(1), [package])
            {
                BuildId = "publisher-lock-symlink-test",
                DataManifestId = "publisher-lock-symlink-test-data",
                Capabilities = ["client_version_hello_v1"]
            };
            var (envelope, trustRoot) = Sign(manifest);
            var options = new UpdaterOptions(new Uri("https://downloads.example.test/v1/channels/stable/manifest"),
                "stable", "linux", "x64", "unused");

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishAsync(envelope, trustRoot,
                options, inputRoot, outputRoot, manifests, audit, Now));

            Assert.Equal(targetContents, await File.ReadAllTextAsync(target));
            Assert.False(File.Exists(activePath));
            Assert.False(Directory.Exists(audit));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task PublishesVerifiedRootMetadataAppendOnlyAndAuditsActivation()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-root-" + Guid.NewGuid().ToString("N"));
        try
        {
            var manifestRoot = Path.Combine(rootPath, "manifests");
            var auditRoot = Path.Combine(rootPath, "audit");
            var (rootMetadata, bootstrapRoot) = SignedRootSuccessor();
            var destination = Path.Combine(manifestRoot, "root", "1.json");

            await ReleasePublisher.PublishRootMetadataAsync(rootMetadata, bootstrapRoot,
                manifestRoot, auditRoot, Now);

            var published = await File.ReadAllBytesAsync(destination);
            Assert.Equal(rootMetadata, published);
            var auditRecords = Directory.GetFiles(auditRoot, "*.json").Select(path =>
                JsonDocument.Parse(File.ReadAllBytes(path))).ToArray();
            Assert.Equal(new[] { "activated", "prepared" }, auditRecords
                .Select(record => record.RootElement.GetProperty("event").GetString())
                .Order(StringComparer.Ordinal).ToArray());
            Assert.All(auditRecords, record =>
                Assert.Equal(1, record.RootElement.GetProperty("rootVersion").GetInt64()));
            Assert.Equal(Convert.ToHexString(SHA256.HashData(published)).ToLowerInvariant(),
                auditRecords.Single(record => record.RootElement.GetProperty("event").GetString() == "activated")
                    .RootElement.GetProperty("rootSha256").GetString());

            await ReleasePublisher.PublishRootMetadataAsync(rootMetadata, bootstrapRoot,
                manifestRoot, auditRoot, Now);
            Assert.Equal(published, await File.ReadAllBytesAsync(destination));
            Assert.Equal(2, Directory.GetFiles(auditRoot, "*.json").Length);

            var (differentRoot, _) = SignedRootSuccessor(seedOffset: 10);
            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishRootMetadataAsync(
                differentRoot, bootstrapRoot, manifestRoot, auditRoot, Now));
            Assert.Equal(published, await File.ReadAllBytesAsync(destination));
            Assert.Equal(2, Directory.GetFiles(auditRoot, "*.json").Length);
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task RootPublisherRejectsSymlinkedRootDirectory()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "release-publisher-root-" + Guid.NewGuid().ToString("N"));
        try
        {
            var manifestRoot = Path.Combine(rootPath, "manifests");
            var outside = Path.Combine(rootPath, "outside");
            Directory.CreateDirectory(outside);
            Directory.CreateDirectory(manifestRoot);
            Directory.CreateSymbolicLink(Path.Combine(manifestRoot, "root"), outside);
            var (rootMetadata, bootstrapRoot) = SignedRootSuccessor();

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishRootMetadataAsync(
                rootMetadata, bootstrapRoot, manifestRoot, Path.Combine(rootPath, "audit"), Now));

            Assert.Empty(Directory.GetFileSystemEntries(outside));
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }

    private static (byte[] Envelope, TrustRoot BootstrapRoot) SignedRootSuccessor(byte seedOffset = 0)
    {
        var oldSigners = new[] { RootSigner((byte)(1 + seedOffset)), RootSigner((byte)(2 + seedOffset)) };
        var newRootSigners = new[] { RootSigner((byte)(3 + seedOffset)), RootSigner((byte)(4 + seedOffset)) };
        var targetSigners = new[] { RootSigner((byte)(5 + seedOffset)) };
        var keys = new JsonObject();
        foreach (var signer in newRootSigners.Concat(targetSigners))
            keys[signer.KeyId] = signer.Key.DeepClone();

        var signed = new JsonObject
        {
            ["_type"] = "root",
            ["spec_version"] = "1.0.36",
            ["consistent_snapshot"] = true,
            ["version"] = 1,
            ["expires"] = Now.AddDays(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["keys"] = keys,
            ["roles"] = new JsonObject
            {
                ["root"] = RootRole(newRootSigners.Select(signer => signer.KeyId), 2),
                ["timestamp"] = RootRole(targetSigners.Select(signer => signer.KeyId), 1),
                ["snapshot"] = RootRole(targetSigners.Select(signer => signer.KeyId), 1),
                ["targets"] = RootRole(targetSigners.Select(signer => signer.KeyId), 1)
            }
        };
        var signedBytes = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var signatures = oldSigners.Select(signer => SignRoot(signer, signedBytes, signer.BootstrapKey.KeyId))
            .Concat(newRootSigners.Select(signer => SignRoot(signer, signedBytes, signer.KeyId)))
            .Select(signature => (JsonNode?)new JsonObject
            {
                ["keyid"] = signature.KeyId,
                ["sig"] = signature.Value
            }).ToArray();
        var envelope = new JsonObject
        {
            ["signed"] = signed,
            ["signatures"] = new JsonArray(signatures)
        };
        var bootstrap = new TrustRoot(1, 2, oldSigners.Select(signer => signer.BootstrapKey).ToArray(), 1);
        return (JsonSerializer.SerializeToUtf8Bytes(envelope), bootstrap);
    }

    private static RootSignerFixture RootSigner(byte seed)
    {
        var privateKey = new Ed25519PrivateKeyParameters(Enumerable.Repeat(seed, 32).ToArray(), 0);
        var publicKey = privateKey.GeneratePublicKey().GetEncoded();
        var key = new JsonObject
        {
            ["keytype"] = "ed25519",
            ["scheme"] = "ed25519",
            ["keyval"] = new JsonObject { ["public"] = Convert.ToHexString(publicKey).ToLowerInvariant() }
        };
        var keyId = Convert.ToHexString(SHA256.HashData(
            ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(key)))).ToLowerInvariant();
        return new RootSignerFixture(privateKey, keyId, key,
            new TrustedKey($"bootstrap-{seed}", "Ed25519", Convert.ToBase64String(publicKey)));
    }

    private static TufRootSignature SignRoot(RootSignerFixture signer, byte[] payload, string keyId)
    {
        var signature = new Ed25519Signer();
        signature.Init(true, signer.PrivateKey);
        signature.BlockUpdate(payload, 0, payload.Length);
        return new TufRootSignature(keyId, Convert.ToHexString(signature.GenerateSignature()).ToLowerInvariant());
    }

    private static JsonObject RootRole(IEnumerable<string> ids, int threshold) => new()
    {
        ["keyids"] = new JsonArray(ids.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()),
        ["threshold"] = threshold
    };

    private sealed record RootSignerFixture(Ed25519PrivateKeyParameters PrivateKey, string KeyId,
        JsonObject Key, TrustedKey BootstrapKey);

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunPublisherAsync(
        string manifestPath, string trustRootPath, string sourceRoot, string artifactRoot,
        string manifestRoot, string auditRoot)
    {
        var publisherAssembly = Path.Combine(AppContext.BaseDirectory, "Publisher.dll");
        Assert.True(File.Exists(publisherAssembly), $"Publisher assembly not found: {publisherAssembly}");
        var startInfo = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add(publisherAssembly);
        foreach (var (option, path) in new[]
                 {
                     ("--manifest", manifestPath),
                     ("--trust-root", trustRootPath),
                     ("--source-root", sourceRoot),
                     ("--artifact-root", artifactRoot),
                     ("--manifest-root", manifestRoot),
                     ("--audit-root", auditRoot)
                 })
        {
            startInfo.ArgumentList.Add(option);
            startInfo.ArgumentList.Add(path);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Publisher CLI process.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await standardOutput, await standardError);
    }

    private static (SignedManifest Envelope, TrustRoot Root) Sign(UpdateManifest manifest)
    {
        var privateKey = new Ed25519PrivateKeyParameters(Enumerable.Repeat((byte)17, 32).ToArray(), 0);
        var publicKey = privateKey.GeneratePublicKey().GetEncoded();
        var payload = ManifestCanonicalizer.Serialize(manifest);
        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return (new SignedManifest(Convert.ToBase64String(payload),
                [new ManifestSignature("publisher-test-key", "Ed25519", Convert.ToBase64String(signer.GenerateSignature()))]),
            new TrustRoot(1, 1,
                [new TrustedKey("publisher-test-key", "Ed25519", Convert.ToBase64String(publicKey))], 1));
    }
}
