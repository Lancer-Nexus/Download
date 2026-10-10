using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Download;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Download.Tests;

public sealed class TufMetadataPublisherTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task PublishesVerifiedConsistentSnapshotRolesBeforeTimestampAndAuditsActivation()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildFixture();
            var manifestRoot = Path.Combine(root, "manifests");
            var artifactRoot = Path.Combine(root, "artifacts");
            var auditRoot = Path.Combine(root, "audit");
            var targetPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            await File.WriteAllBytesAsync(targetPath, "signed-manifest-envelope"u8.ToArray());

            await ReleasePublisher.PublishTufMetadataAsync(fixture.Timestamp, fixture.Snapshot,
                fixture.Targets, fixture.TrustRoot, artifactRoot, manifestRoot, auditRoot, Now);

            var metadata = Path.Combine(manifestRoot, "metadata");
            Assert.Equal(fixture.Timestamp, await File.ReadAllBytesAsync(Path.Combine(metadata, "timestamp.json")));
            Assert.Equal(fixture.Snapshot, await File.ReadAllBytesAsync(Path.Combine(metadata, "3.snapshot.json")));
            Assert.Equal(fixture.Targets, await File.ReadAllBytesAsync(Path.Combine(metadata, "4.targets.json")));
            Assert.False(File.Exists(Path.Combine(metadata, "snapshot.json")));
            Assert.True(File.Exists(Path.Combine(auditRoot, "tuf-metadata-versions.json")));
            await ReleasePublisher.PublishTufMetadataAsync(fixture.Timestamp, fixture.Snapshot,
                fixture.Targets, fixture.TrustRoot, artifactRoot, manifestRoot, auditRoot, Now);
            var audit = Directory.GetFiles(auditRoot, "*-tuf-*.json").Select(path =>
                JsonDocument.Parse(File.ReadAllBytes(path))).ToArray();
            Assert.Equal(new[] { "activated", "activated", "prepared", "prepared" }, audit
                .Select(record => record.RootElement.GetProperty("event").GetString())
                .Order(StringComparer.Ordinal).ToArray());
            var changedSameVersion = BuildFixture(0x7f);
            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishTufMetadataAsync(
                changedSameVersion.Timestamp, changedSameVersion.Snapshot, changedSameVersion.Targets,
                changedSameVersion.TrustRoot, artifactRoot, manifestRoot, auditRoot, Now));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsBrokenMetadataChainBeforePublishingTimestampOrRoles()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-invalid-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildFixture();
            var changedSnapshot = fixture.Snapshot.ToArray();
            changedSnapshot[^1] ^= 0x01;
            var manifestRoot = Path.Combine(root, "manifests");

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishTufMetadataAsync(
                fixture.Timestamp, changedSnapshot, fixture.Targets, fixture.TrustRoot,
                Path.Combine(root, "artifacts"), manifestRoot, Path.Combine(root, "audit"), Now));

            Assert.False(File.Exists(Path.Combine(manifestRoot, "metadata", "timestamp.json")));
            Assert.False(File.Exists(Path.Combine(manifestRoot, "metadata", "3.snapshot.json")));
            Assert.False(File.Exists(Path.Combine(manifestRoot, "metadata", "4.targets.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RecoversActivatedTimestampAuditAfterInterruption()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-recovery-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildFixture();
            var manifestRoot = Path.Combine(root, "manifests");
            var artifactRoot = Path.Combine(root, "artifacts");
            var auditRoot = Path.Combine(root, "audit");
            var targetPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            await File.WriteAllBytesAsync(targetPath, "signed-manifest-envelope"u8.ToArray());

            await Assert.ThrowsAsync<IOException>(() => ReleasePublisher.PublishTufMetadataAsync(
                fixture.Timestamp, fixture.Snapshot, fixture.Targets, fixture.TrustRoot,
                artifactRoot, manifestRoot, auditRoot, Now,
                boundary =>
                {
                    if (boundary == ReleasePublisher.PublicationBoundary.TufMetadataTimestampActivated)
                        throw new IOException("simulated interruption");
                }, CancellationToken.None));

            var pending = Directory.GetFiles(auditRoot, ".*.tuf-activated.pending");
            Assert.Single(pending);
            Assert.Equal(fixture.Timestamp,
                await File.ReadAllBytesAsync(Path.Combine(manifestRoot, "metadata", "timestamp.json")));

            await ReleasePublisher.PublishTufMetadataAsync(fixture.Timestamp, fixture.Snapshot,
                fixture.Targets, fixture.TrustRoot, artifactRoot, manifestRoot, auditRoot, Now);

            Assert.Empty(Directory.GetFiles(auditRoot, ".*.tuf-activated.pending"));
            Assert.Equal(2, Directory.GetFiles(auditRoot, "*-tuf-activated.json").Length);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UsesFixedSnapshotAndTargetsNamesWhenConsistentSnapshotsAreDisabled()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-unversioned-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildFixture(consistentSnapshot: false);
            var manifestRoot = Path.Combine(root, "manifests");
            var targetPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            await File.WriteAllBytesAsync(targetPath, "signed-manifest-envelope"u8.ToArray());

            await ReleasePublisher.PublishTufMetadataAsync(fixture.Timestamp, fixture.Snapshot,
                fixture.Targets, fixture.TrustRoot, Path.Combine(root, "artifacts"), manifestRoot,
                Path.Combine(root, "audit"), Now);

            var metadata = Path.Combine(manifestRoot, "metadata");
            Assert.True(File.Exists(Path.Combine(metadata, "snapshot.json")));
            Assert.True(File.Exists(Path.Combine(metadata, "targets.json")));
            Assert.False(File.Exists(Path.Combine(metadata, "3.snapshot.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsTargetContentThatDoesNotMatchSignedTargetsBeforeActivation()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-target-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildFixture();
            var manifestRoot = Path.Combine(root, "manifests");
            var targetPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            await File.WriteAllTextAsync(targetPath, "tampered manifest");

            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishTufMetadataAsync(
                fixture.Timestamp, fixture.Snapshot, fixture.Targets, fixture.TrustRoot,
                Path.Combine(root, "artifacts"), manifestRoot, Path.Combine(root, "audit"), Now));

            Assert.False(File.Exists(Path.Combine(manifestRoot, "metadata", "timestamp.json")));
            Assert.False(File.Exists(Path.Combine(manifestRoot, "metadata", "3.snapshot.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PublishesAllVerifiedDelegatedRolesBeforeActivatingTimestamp()
    {
        var root = Path.Combine(Path.GetTempPath(), "tuf-publisher-delegated-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fixture = BuildDelegatedFixture();
            var manifestRoot = Path.Combine(root, "manifests");
            var targetPath = Path.Combine(manifestRoot, "stable", "linux-x64.json");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            await File.WriteAllBytesAsync(targetPath, fixture.TargetContent!);

            await ReleasePublisher.PublishTufMetadataAsync(fixture.Timestamp, fixture.Snapshot, fixture.Targets,
                fixture.DelegatedMetadata!, fixture.TrustRoot, Path.Combine(root, "artifacts"), manifestRoot,
                Path.Combine(root, "audit"), Now);

            var metadataDirectory = Path.Combine(manifestRoot, "metadata");
            Assert.Equal(fixture.DelegatedMetadata!["delegates/channels"],
                await File.ReadAllBytesAsync(Path.Combine(metadataDirectory, "5.delegates", "channels.json")));
            Assert.Equal(fixture.Timestamp, await File.ReadAllBytesAsync(Path.Combine(metadataDirectory, "timestamp.json")));

            var missingRoleRoot = Path.Combine(root, "missing-role");
            await Assert.ThrowsAsync<InvalidDataException>(() => ReleasePublisher.PublishTufMetadataAsync(
                fixture.Timestamp, fixture.Snapshot, fixture.Targets, new Dictionary<string, byte[]>(),
                fixture.TrustRoot, Path.Combine(missingRoleRoot, "artifacts"), Path.Combine(missingRoleRoot, "manifests"),
                Path.Combine(missingRoleRoot, "audit"), Now));
            Assert.False(File.Exists(Path.Combine(missingRoleRoot, "manifests", "metadata", "timestamp.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static TufFixture BuildFixture(byte targetByte = 0x01, bool consistentSnapshot = true)
    {
        var timestampSigner = Signer(0x61);
        var snapshotSigner = Signer(0x62);
        var targetsSigner = Signer(0x63);
        var targetBytes = targetByte == 0x01
            ? "signed-manifest-envelope"u8.ToArray()
            : new[] { targetByte, (byte)0x02, (byte)0x03 };
        var targets = SignMetadata(new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 4,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject
            {
                ["stable/linux-x64.json"] = new JsonObject
                {
                    ["length"] = targetBytes.Length,
                    ["hashes"] = new JsonObject
                    {
                        ["sha256"] = Convert.ToHexString(SHA256.HashData(targetBytes)).ToLowerInvariant()
                    }
                }
            }
        }, targetsSigner);
        var snapshot = SignMetadata(new JsonObject
        {
            ["_type"] = "snapshot",
            ["spec_version"] = "1.0.36",
            ["version"] = 3,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject { ["targets.json"] = MetadataInfo(4, targets) }
        }, snapshotSigner);
        var timestamp = SignMetadata(new JsonObject
        {
            ["_type"] = "timestamp",
            ["spec_version"] = "1.0.36",
            ["version"] = 2,
            ["expires"] = Now.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject { ["snapshot.json"] = MetadataInfo(3, snapshot) }
        }, timestampSigner);
        var trustRoot = new TrustRoot(1, 1, [targetsSigner.TrustedKey], 1)
        {
            RootVersion = 1,
            TimestampRoleKeys = [timestampSigner.TrustedKey],
            TimestampRoleThreshold = 1,
            SnapshotRoleKeys = [snapshotSigner.TrustedKey],
            SnapshotRoleThreshold = 1,
            ConsistentSnapshot = consistentSnapshot
        };
        return new TufFixture(trustRoot, timestamp, snapshot, targets);
    }

    private static TufFixture BuildDelegatedFixture()
    {
        var timestampSigner = Signer(0x71);
        var snapshotSigner = Signer(0x72);
        var targetsSigner = Signer(0x73);
        var delegatedSigner = Signer(0x74);
        var targetBytes = "signed-delegated-manifest-envelope"u8.ToArray();
        var delegatedTargets = SignMetadata(new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 5,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject
            {
                ["stable/linux-x64.json"] = new JsonObject
                {
                    ["length"] = targetBytes.Length,
                    ["hashes"] = new JsonObject
                    {
                        ["sha256"] = Convert.ToHexString(SHA256.HashData(targetBytes)).ToLowerInvariant()
                    }
                }
            }
        }, delegatedSigner);
        var delegatedKey = new JsonObject
        {
            ["keytype"] = "ed25519",
            ["scheme"] = "ed25519",
            ["keyval"] = new JsonObject
            {
                ["public"] = Convert.ToHexString(Convert.FromBase64String(delegatedSigner.TrustedKey.PublicKey)).ToLowerInvariant()
            }
        };
        var targets = SignMetadata(new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 4,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject(),
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject { [delegatedSigner.TrustedKey.KeyId] = delegatedKey },
                ["roles"] = new JsonArray(new JsonObject
                {
                    ["name"] = "delegates/channels",
                    ["keyids"] = new JsonArray(delegatedSigner.TrustedKey.KeyId),
                    ["threshold"] = 1,
                    ["terminating"] = false,
                    ["paths"] = new JsonArray("stable/*")
                })
            }
        }, targetsSigner);
        var snapshot = SignMetadata(new JsonObject
        {
            ["_type"] = "snapshot",
            ["spec_version"] = "1.0.36",
            ["version"] = 3,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject
            {
                ["targets.json"] = MetadataInfo(4, targets),
                ["delegates/channels.json"] = MetadataInfo(5, delegatedTargets)
            }
        }, snapshotSigner);
        var timestamp = SignMetadata(new JsonObject
        {
            ["_type"] = "timestamp",
            ["spec_version"] = "1.0.36",
            ["version"] = 2,
            ["expires"] = Now.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject { ["snapshot.json"] = MetadataInfo(3, snapshot) }
        }, timestampSigner);
        var trustRoot = new TrustRoot(1, 1, [targetsSigner.TrustedKey], 1)
        {
            RootVersion = 1,
            TimestampRoleKeys = [timestampSigner.TrustedKey],
            TimestampRoleThreshold = 1,
            SnapshotRoleKeys = [snapshotSigner.TrustedKey],
            SnapshotRoleThreshold = 1,
            ConsistentSnapshot = true
        };
        return new TufFixture(trustRoot, timestamp, snapshot, targets,
            new Dictionary<string, byte[]> { ["delegates/channels"] = delegatedTargets }, targetBytes);
    }

    private static JsonObject MetadataInfo(long version, byte[] bytes) => new()
    {
        ["version"] = version,
        ["length"] = bytes.Length,
        ["hashes"] = new JsonObject
        {
            ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
        }
    };

    private static byte[] SignMetadata(JsonObject signed, SignerFixture signer)
    {
        var payload = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var signature = new Ed25519Signer();
        signature.Init(true, signer.PrivateKey);
        signature.BlockUpdate(payload, 0, payload.Length);
        var envelope = new JsonObject
        {
            ["signed"] = signed,
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["keyid"] = signer.TrustedKey.KeyId,
                ["sig"] = Convert.ToHexString(signature.GenerateSignature()).ToLowerInvariant()
            })
        };
        return JsonSerializer.SerializeToUtf8Bytes(envelope);
    }

    private static SignerFixture Signer(byte seed)
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
        return new SignerFixture(privateKey,
            new TrustedKey(keyId, "Ed25519", Convert.ToBase64String(publicKey)));
    }

    private sealed record SignerFixture(Ed25519PrivateKeyParameters PrivateKey, TrustedKey TrustedKey);
    private sealed record TufFixture(TrustRoot TrustRoot, byte[] Timestamp, byte[] Snapshot, byte[] Targets,
        Dictionary<string, byte[]>? DelegatedMetadata = null, byte[]? TargetContent = null);
}
