using System.Security.Cryptography;
using System.Text.Json;
using LancerNexus.Updater;

namespace LancerNexus.Download;

/// <summary>Publishes a pre-signed release without access to signing keys.</summary>
public static class ReleasePublisher
{
    internal enum PublicationBoundary { ActivationAuditPrepared, ManifestActivated, TufMetadataTimestampActivated }

    public static async Task PublishRootMetadataAsync(byte[] rootEnvelopeBytes, TrustRoot currentRoot,
        string manifestRoot, string auditRoot, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rootEnvelopeBytes);
        ArgumentNullException.ThrowIfNull(currentRoot);
        if (nowUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Publication time must be UTC.", nameof(nowUtc));
        TufRootRotationVerifier.EnsureCurrent(currentRoot, nowUtc);
        var nextRoot = TufRootRotationVerifier.VerifySuccessor(rootEnvelopeBytes, currentRoot);
        TufRootRotationVerifier.EnsureCurrent(nextRoot, nowUtc);

        var metadataDirectory = Path.GetFullPath(manifestRoot);
        var auditDirectory = Path.GetFullPath(auditRoot);
        EnsureNoReparsePoints(metadataDirectory);
        EnsureNoReparsePoints(auditDirectory);
        EnsureRootsAreSeparate(metadataDirectory, auditDirectory);
        var rootDirectory = Path.Combine(metadataDirectory, "root");
        EnsureNoReparsePoints(rootDirectory);
        Directory.CreateDirectory(rootDirectory);
        EnsureNoReparsePoints(rootDirectory);
        var rootPublishLockPath = Path.Combine(rootDirectory, ".root-publish.lock");
        EnsureNoReparsePoints(rootPublishLockPath);
        using var rootPublishLock = new FileStream(rootPublishLockPath, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        EnsureNoReparsePoints(rootPublishLockPath);
        await RecoverPendingRootAuditRecordsAsync(rootDirectory, auditDirectory, cancellationToken);

        var destination = Path.Combine(rootDirectory, $"{nextRoot.RootVersion}.json");
        EnsureNoReparsePoints(destination);
        var lockPath = destination + ".publish.lock";
        EnsureNoReparsePoints(lockPath);
        using var publishLock = new FileStream(lockPath, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        EnsureNoReparsePoints(lockPath);

        var rootDigest = Convert.ToHexString(SHA256.HashData(rootEnvelopeBytes)).ToLowerInvariant();
        if (File.Exists(destination))
        {
            await using var existing = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var existingDigest = Convert.ToHexString(await SHA256.HashDataAsync(existing, cancellationToken)).ToLowerInvariant();
            if (string.Equals(existingDigest, rootDigest, StringComparison.Ordinal) &&
                await HasActivatedRootAuditRecordAsync(auditDirectory, nextRoot.RootVersion, rootDigest, cancellationToken))
                return;
            if (string.Equals(existingDigest, rootDigest, StringComparison.Ordinal))
                throw new InvalidDataException("Existing TUF root metadata has no matching activated audit record.");
            throw new InvalidDataException("TUF root version already exists with different content.");
        }

        var predecessorPath = Path.Combine(rootDirectory, $"{currentRoot.RootVersion}.json");
        string? predecessorDigest = null;
        if (currentRoot.RootVersion > 0 && File.Exists(predecessorPath))
        {
            EnsureNoReparsePoints(predecessorPath);
            await using var predecessor = new FileStream(predecessorPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            predecessorDigest = Convert.ToHexString(await SHA256.HashDataAsync(predecessor, cancellationToken)).ToLowerInvariant();
        }

        var signatures = ReadRootSignatureKeyIds(rootEnvelopeBytes);
        var publicationId = Guid.NewGuid().ToString("N");
        var audit = new RootPublicationAuditRecord(1, publicationId, "prepared", nowUtc,
            nextRoot.RootVersion, rootDigest, currentRoot.RootVersion, predecessorDigest,
            Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(currentRoot, TrustRoot.JsonOptions)))
                .ToLowerInvariant(), signatures);
        await WriteRootAuditRecordAsync(auditDirectory, audit, cancellationToken);

        var activated = audit with { Event = "activated", CreatedAtUtc = DateTime.UtcNow };
        var pendingPath = PendingRootAuditRecordPath(auditDirectory, publicationId);
        var temporaryPath = Path.Combine(rootDirectory, $".{nextRoot.RootVersion}.{Guid.NewGuid():N}.tmp");
        try
        {
            EnsureNoReparsePoints(temporaryPath);
            await WriteDurableBytesAsync(temporaryPath, rootEnvelopeBytes, cancellationToken);
            await WritePendingRootAuditRecordAsync(auditDirectory, pendingPath, activated, cancellationToken);
            EnsureNoReparsePoints(destination);
            File.Move(temporaryPath, destination);
            EnsureNoReparsePoints(pendingPath);
            File.Move(pendingPath, RootAuditRecordPath(auditDirectory, activated));
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public static Task PublishTufMetadataAsync(byte[] timestampBytes, byte[] snapshotBytes,
        byte[] targetsBytes, TrustRoot trustRoot, string artifactRoot, string manifestRoot,
        string auditRoot, DateTime nowUtc, CancellationToken cancellationToken = default) =>
        PublishTufMetadataAsync(timestampBytes, snapshotBytes, targetsBytes,
            new Dictionary<string, byte[]>(StringComparer.Ordinal), trustRoot, artifactRoot,
            manifestRoot, auditRoot, nowUtc, null, cancellationToken);

    public static Task PublishTufMetadataAsync(byte[] timestampBytes, byte[] snapshotBytes,
        byte[] targetsBytes, IReadOnlyDictionary<string, byte[]> delegatedMetadata, TrustRoot trustRoot,
        string artifactRoot, string manifestRoot, string auditRoot, DateTime nowUtc,
        CancellationToken cancellationToken = default) =>
        PublishTufMetadataAsync(timestampBytes, snapshotBytes, targetsBytes, delegatedMetadata, trustRoot,
            artifactRoot, manifestRoot, auditRoot, nowUtc, null, cancellationToken);

    internal static Task PublishTufMetadataAsync(byte[] timestampBytes, byte[] snapshotBytes,
        byte[] targetsBytes, TrustRoot trustRoot, string artifactRoot, string manifestRoot,
        string auditRoot, DateTime nowUtc, Action<PublicationBoundary>? onBoundary,
        CancellationToken cancellationToken) => PublishTufMetadataAsync(timestampBytes, snapshotBytes,
        targetsBytes, new Dictionary<string, byte[]>(StringComparer.Ordinal), trustRoot, artifactRoot,
        manifestRoot, auditRoot, nowUtc, onBoundary, cancellationToken);

    internal static async Task PublishTufMetadataAsync(byte[] timestampBytes, byte[] snapshotBytes,
        byte[] targetsBytes, IReadOnlyDictionary<string, byte[]> delegatedMetadata, TrustRoot trustRoot,
        string artifactRoot, string manifestRoot,
        string auditRoot, DateTime nowUtc, Action<PublicationBoundary>? onBoundary,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(timestampBytes);
        ArgumentNullException.ThrowIfNull(snapshotBytes);
        ArgumentNullException.ThrowIfNull(targetsBytes);
        ArgumentNullException.ThrowIfNull(delegatedMetadata);
        ArgumentNullException.ThrowIfNull(trustRoot);
        if (nowUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Publication time must be UTC.", nameof(nowUtc));
        TufRootRotationVerifier.EnsureCurrent(trustRoot, nowUtc);

        var metadataRoot = Path.GetFullPath(manifestRoot);
        var artifactDirectory = Path.GetFullPath(artifactRoot);
        var auditDirectory = Path.GetFullPath(auditRoot);
        EnsureNoReparsePoints(artifactDirectory);
        EnsureNoReparsePoints(metadataRoot);
        EnsureNoReparsePoints(auditDirectory);
        EnsureRootsAreSeparate(artifactDirectory, metadataRoot, auditDirectory);
        Directory.CreateDirectory(metadataRoot);
        var metadataDirectory = Path.Combine(metadataRoot, "metadata");
        EnsureNoReparsePoints(metadataDirectory);
        Directory.CreateDirectory(metadataDirectory);
        EnsureNoReparsePoints(metadataDirectory);

        var publishLockPath = Path.Combine(metadataDirectory, ".tuf-publish.lock");
        EnsureNoReparsePoints(publishLockPath);
        using var publishLock = new FileStream(publishLockPath, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        EnsureNoReparsePoints(publishLockPath);
        await RecoverPendingTufMetadataAuditRecordsAsync(metadataDirectory, auditDirectory, cancellationToken);

        var statePath = Path.Combine(auditDirectory, "tuf-metadata-versions.json");
        EnsureNoReparsePoints(statePath);
        var minimumVersions = TufMetadataVersionStore.GetMinimumVersions(statePath, trustRoot);
        var repository = TufRepositoryVerifier.VerifyAllDelegations(trustRoot, timestampBytes, snapshotBytes,
            targetsBytes, delegatedMetadata, nowUtc, minimumVersions);
        await VerifyPublishedTargetsAsync(repository, artifactDirectory, metadataRoot, cancellationToken);

        var snapshotPath = RolePath(metadataDirectory, "snapshot", repository.Versions.Snapshot,
            trustRoot.ConsistentSnapshot);
        var targetsPath = RolePath(metadataDirectory, "targets", repository.Versions.Targets,
            trustRoot.ConsistentSnapshot);
        var timestampPath = Path.Combine(metadataDirectory, "timestamp.json");
        EnsureNoReparsePoints(snapshotPath);
        EnsureNoReparsePoints(targetsPath);
        EnsureNoReparsePoints(timestampPath);
        if (trustRoot.ConsistentSnapshot)
        {
            EnsureImmutableOrSame(snapshotPath, snapshotBytes);
            EnsureImmutableOrSame(targetsPath, targetsBytes);
            foreach (var (role, bytes) in delegatedMetadata)
                EnsureImmutableOrSame(RolePath(metadataDirectory, role,
                    repository.DelegatedRoles[role].Version, true), bytes);
        }

        var publicationId = Guid.NewGuid().ToString("N");
        var digests = new[]
        {
            Convert.ToHexString(SHA256.HashData(timestampBytes)).ToLowerInvariant(),
            repository.SnapshotSha256,
            repository.TargetsSha256
        };
        var record = new TufMetadataPublicationAuditRecord(1, publicationId, "prepared", nowUtc,
            trustRoot.RootVersion, repository.Versions, digests[0], digests[1], digests[2]);
        await WriteTufMetadataAuditRecordAsync(auditDirectory, record, cancellationToken);

        var timestampTemporaryPath = Path.Combine(metadataDirectory, $".timestamp.{Guid.NewGuid():N}.tmp");
        var activated = record with { Event = "activated", CreatedAtUtc = DateTime.UtcNow };
        var pendingAuditPath = Path.Combine(auditDirectory, $".{publicationId}.tuf-activated.pending");
        try
        {
            foreach (var (role, bytes) in delegatedMetadata.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                var delegatedPath = RolePath(metadataDirectory, role, repository.DelegatedRoles[role].Version,
                    trustRoot.ConsistentSnapshot);
                EnsureNoReparsePoints(delegatedPath);
                await WriteRoleFileAsync(delegatedPath, bytes, overwrite: !trustRoot.ConsistentSnapshot,
                    cancellationToken);
            }
            await WriteRoleFileAsync(targetsPath, targetsBytes, overwrite: !trustRoot.ConsistentSnapshot,
                cancellationToken);
            await WriteRoleFileAsync(snapshotPath, snapshotBytes, overwrite: !trustRoot.ConsistentSnapshot,
                cancellationToken);
            // Record accepted versions before exposing the new timestamp pointer. Replaying the
            // same signed bytes is idempotent if activation is interrupted at this boundary.
            TufMetadataVersionStore.Accept(statePath, trustRoot, repository);
            await WriteJsonDurablyAsync(pendingAuditPath, activated, cancellationToken);
            await WriteDurableBytesAsync(timestampTemporaryPath, timestampBytes, cancellationToken);
            EnsureNoReparsePoints(timestampPath);
            File.Move(timestampTemporaryPath, timestampPath, overwrite: true);
            onBoundary?.Invoke(PublicationBoundary.TufMetadataTimestampActivated);
            File.Move(pendingAuditPath, TufMetadataAuditRecordPath(auditDirectory, activated));
        }
        finally
        {
            if (File.Exists(timestampTemporaryPath)) File.Delete(timestampTemporaryPath);
        }
    }

    private static string RolePath(string metadataDirectory, string role, long version, bool consistentSnapshot) =>
        Path.Combine(metadataDirectory, consistentSnapshot ? $"{version}.{role}.json" : $"{role}.json");

    private static async Task VerifyPublishedTargetsAsync(VerifiedTufRepository repository,
        string artifactRoot, string manifestRoot, CancellationToken cancellationToken)
    {
        var verifiedManifestCount = 0;
        foreach (var target in repository.Targets)
        {
            var segments = target.Key.Split('/');
            string path;
            if (segments.Length == 3 && segments[0] == "artifacts" &&
                segments[1].Length == 2 && segments[1].All(Uri.IsHexDigit) &&
                segments[2].Length == 64 && segments[2].All(Uri.IsHexDigit) &&
                string.Equals(segments[1], segments[2][..2], StringComparison.OrdinalIgnoreCase) &&
                string.Equals(segments[2], target.Value.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                path = Path.Combine(artifactRoot, "sha256", segments[1].ToLowerInvariant(),
                    segments[2].ToLowerInvariant());
            }
            else if (segments.Length == 2 && (segments[0] is "stable" or "beta" or "nightly" or "internal") &&
                     (segments[1] is "linux-x64.json" or "linux-arm64.json" or "win-x64.json" or "win-arm64.json"))
            {
                path = Path.Combine(manifestRoot, segments[0], segments[1]);
                verifiedManifestCount++;
            }
            else
            {
                throw new InvalidDataException($"TUF target path '{target.Key}' is outside the published manifest and artifact layout.");
            }

            EnsureNoReparsePoints(path);
            var info = new FileInfo(path);
            if (!info.Exists || info.Length != target.Value.Length)
                throw new InvalidDataException($"Published TUF target '{target.Key}' is missing or has an invalid length.");
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
            if (!string.Equals(digest, target.Value.Sha256, StringComparison.Ordinal))
                throw new InvalidDataException($"Published TUF target '{target.Key}' does not match its signed digest.");
        }
        if (verifiedManifestCount == 0)
            throw new InvalidDataException("TUF targets metadata must declare at least one published channel manifest.");
    }

    private static void EnsureImmutableOrSame(string path, byte[] candidate)
    {
        if (!File.Exists(path)) return;
        var existingDigest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
        var candidateDigest = Convert.ToHexString(SHA256.HashData(candidate)).ToLowerInvariant();
        if (!string.Equals(existingDigest, candidateDigest, StringComparison.Ordinal))
            throw new InvalidDataException("TUF consistent-snapshot metadata version already exists with different content.");
    }

    private static async Task WriteRoleFileAsync(string path, byte[] bytes, bool overwrite,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("TUF metadata destination has no parent directory.");
        EnsureNoReparsePoints(directory);
        Directory.CreateDirectory(directory);
        EnsureNoReparsePoints(directory);
        EnsureNoReparsePoints(path);
        if (File.Exists(path))
        {
            if (!overwrite)
            {
                EnsureImmutableOrSame(path, bytes);
                return;
            }
            var temporary = path + $".{Guid.NewGuid():N}.tmp";
            try
            {
                await WriteDurableBytesAsync(temporary, bytes, cancellationToken);
                EnsureNoReparsePoints(path);
                File.Move(temporary, path, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            return;
        }

        var immutableTemporary = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            await WriteDurableBytesAsync(immutableTemporary, bytes, cancellationToken);
            EnsureNoReparsePoints(path);
            File.Move(immutableTemporary, path);
        }
        catch (IOException) when (File.Exists(path))
        {
            EnsureImmutableOrSame(path, bytes);
        }
        finally
        {
            if (File.Exists(immutableTemporary)) File.Delete(immutableTemporary);
        }
    }

    private static async Task WriteTufMetadataAuditRecordAsync(string auditRoot,
        TufMetadataPublicationAuditRecord record, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(auditRoot);
        var path = TufMetadataAuditRecordPath(auditRoot, record);
        await WriteJsonDurablyAsync(path, record, cancellationToken);
    }

    private static string TufMetadataAuditRecordPath(string auditRoot,
        TufMetadataPublicationAuditRecord record) => Path.Combine(auditRoot,
        $"{record.CreatedAtUtc:yyyyMMddTHHmmssfffffffZ}-{record.PublicationId}-tuf-{record.Event}.json");

    private static async Task WriteJsonDurablyAsync<T>(string path, T value,
        CancellationToken cancellationToken)
    {
        var auditRoot = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(auditRoot);
        EnsureNoReparsePoints(path);
        var temporaryPath = Path.Combine(auditRoot, $".{Guid.NewGuid():N}.tmp");
        try
        {
            EnsureNoReparsePoints(temporaryPath);
            EnsureNoReparsePoints(path);
            EnsureNoReparsePoints(temporaryPath);
            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(output, value, TrustRoot.JsonOptions, cancellationToken);
                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task RecoverPendingTufMetadataAuditRecordsAsync(string metadataDirectory,
        string auditDirectory, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(auditDirectory)) return;
        foreach (var pendingPath in Directory.EnumerateFiles(auditDirectory, ".*.tuf-activated.pending"))
        {
            EnsureNoReparsePoints(pendingPath);
            TufMetadataPublicationAuditRecord record;
            try
            {
                record = JsonSerializer.Deserialize<TufMetadataPublicationAuditRecord>(
                    await File.ReadAllBytesAsync(pendingPath, cancellationToken), TrustRoot.JsonOptions)
                    ?? throw new InvalidDataException("Pending TUF metadata audit record is empty.");
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("Pending TUF metadata audit record is invalid.", error);
            }
            if (record.Schema != 1 || record.Event != "activated" || record.TimestampSha256.Length != 64 ||
                record.SnapshotSha256.Length != 64 || record.TargetsSha256.Length != 64)
                throw new InvalidDataException("Pending TUF metadata audit record has invalid fields.");

            var timestampPath = Path.Combine(metadataDirectory, "timestamp.json");
            var activated = false;
            if (File.Exists(timestampPath))
            {
                EnsureNoReparsePoints(timestampPath);
                var timestampDigest = Convert.ToHexString(SHA256.HashData(
                    await File.ReadAllBytesAsync(timestampPath, cancellationToken))).ToLowerInvariant();
                activated = string.Equals(timestampDigest, record.TimestampSha256, StringComparison.Ordinal);
            }
            if (activated)
            {
                var auditRecordPath = TufMetadataAuditRecordPath(auditDirectory, record);
                if (File.Exists(auditRecordPath))
                {
                    EnsureNoReparsePoints(auditRecordPath);
                    var expected = JsonSerializer.SerializeToUtf8Bytes(record, TrustRoot.JsonOptions);
                    var existing = await File.ReadAllBytesAsync(auditRecordPath, cancellationToken);
                    if (!expected.AsSpan().SequenceEqual(existing))
                        throw new InvalidDataException("Activated TUF metadata audit record conflicts with its pending record.");
                }
                else
                {
                    await WriteTufMetadataAuditRecordAsync(auditDirectory, record, cancellationToken);
                }
            }
            File.Delete(pendingPath);
        }
    }

    private sealed record TufMetadataPublicationAuditRecord(int Schema, string PublicationId, string Event,
        DateTime CreatedAtUtc, long RootVersion, TufMetadataVersions Versions, string TimestampSha256,
        string SnapshotSha256, string TargetsSha256);

    public static Task PublishAsync(
        SignedManifest envelope,
        TrustRoot trustRoot,
        UpdaterOptions verificationOptions,
        string artifactSourceRoot,
        string artifactRoot,
        string manifestRoot,
        string auditRoot,
        DateTime nowUtc,
        CancellationToken cancellationToken = default) =>
        PublishAsync(envelope, trustRoot, verificationOptions, artifactSourceRoot, artifactRoot,
            manifestRoot, auditRoot, nowUtc, null, cancellationToken);

    internal static async Task PublishAsync(
        SignedManifest envelope,
        TrustRoot trustRoot,
        UpdaterOptions verificationOptions,
        string artifactSourceRoot,
        string artifactRoot,
        string manifestRoot,
        string auditRoot,
        DateTime nowUtc,
        Action<PublicationBoundary>? onBoundary,
        CancellationToken cancellationToken)
    {
        if (verificationOptions.Channel is not ("stable" or "beta" or "nightly" or "internal") ||
            verificationOptions.Platform is not ("linux" or "win") ||
            verificationOptions.Architecture is not ("x64" or "arm64"))
            throw new InvalidDataException("Channel, Plattform oder Architektur ist ungültig.");
        var manifest = ManifestVerifier.Validate(envelope, trustRoot, verificationOptions, nowUtc);
        var sourceRoot = Path.GetFullPath(artifactSourceRoot);
        var destinationRoot = Path.GetFullPath(artifactRoot);
        var metadataRoot = Path.GetFullPath(manifestRoot);
        var auditDirectory = Path.GetFullPath(auditRoot);
        EnsureNoReparsePoints(sourceRoot);
        EnsureNoReparsePoints(destinationRoot);
        EnsureNoReparsePoints(metadataRoot);
        EnsureNoReparsePoints(auditDirectory);
        EnsureRootsAreSeparate(destinationRoot, metadataRoot, auditDirectory);
        Directory.CreateDirectory(destinationRoot);

        foreach (var package in manifest.Packages)
        {
            var digest = package.Sha256.ToLowerInvariant();
            if (!string.Equals(package.Url, $"artifacts/{digest[..2]}/{digest}", StringComparison.Ordinal))
                throw new InvalidDataException($"Paket {package.Id} verweist nicht auf seinen hashadressierten Downloadpfad.");
            await PublishArtifactAsync(package, sourceRoot, destinationRoot, cancellationToken);
        }

        var activePath = Path.Combine(metadataRoot, manifest.Channel,
            $"{manifest.Platform}-{manifest.Architecture}.json");
        EnsureNoReparsePoints(activePath);
        Directory.CreateDirectory(Path.GetDirectoryName(activePath)!);
        EnsureNoReparsePoints(activePath);
        var publishLockPath = activePath + ".publish.lock";
        EnsureNoReparsePoints(publishLockPath);
        using var publishLock = new FileStream(publishLockPath, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        EnsureNoReparsePoints(publishLockPath);
        await RecoverPendingAuditRecordsAsync(auditDirectory, activePath, cancellationToken);
        UpdateManifest? activeManifest = null;
        if (File.Exists(activePath))
        {
            var activeEnvelope = JsonSerializer.Deserialize<SignedManifest>(
                await File.ReadAllBytesAsync(activePath, cancellationToken), TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("Aktives Manifest ist leer.");
            byte[] activePayload;
            try { activePayload = Convert.FromBase64String(activeEnvelope.Signed); }
            catch (FormatException error) { throw new InvalidDataException("Aktives Manifest ist beschädigt.", error); }
            activeManifest = JsonSerializer.Deserialize<UpdateManifest>(activePayload, TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("Aktives Manifest ist leer.");
            if (activeManifest.Version >= manifest.Version)
                throw new InvalidDataException("Manifest-Version muss gegenüber der aktiven Version steigen.");
        }

        var publicationId = Guid.NewGuid().ToString("N");
        var manifestDigest = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(envelope.Signed)))
            .ToLowerInvariant();
        var trustRootDigest = Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(trustRoot, TrustRoot.JsonOptions))).ToLowerInvariant();
        var packageAudit = manifest.Packages
            .Select(p => new PublishedPackageAudit(p.Id, p.Size, p.Sha256)).ToArray();
        var auditRecord = new PublicationAuditRecord(
            1, publicationId, "prepared", DateTime.UtcNow, manifest.Channel, manifest.Platform,
            manifest.Architecture, manifest.Version, manifestDigest, trustRootDigest,
            envelope.Signatures.Select(signature => $"{signature.Algorithm}:{signature.KeyId}")
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            activeManifest?.Version, packageAudit);
        await WriteAuditRecordAsync(auditDirectory, auditRecord, cancellationToken);

        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(envelope, TrustRoot.JsonOptions);
        var tempPath = activePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var activatedAudit = auditRecord with { Event = "activated", CreatedAtUtc = DateTime.UtcNow };
        var pendingAuditPath = PendingAuditRecordPath(auditDirectory, activatedAudit.PublicationId);
        try
        {
            EnsureNoReparsePoints(tempPath);
            await WriteDurableBytesAsync(tempPath, manifestBytes, cancellationToken);
            await WritePendingAuditRecordAsync(auditDirectory, activatedAudit, cancellationToken);
            onBoundary?.Invoke(PublicationBoundary.ActivationAuditPrepared);
            EnsureNoReparsePoints(activePath);
            File.Move(tempPath, activePath, overwrite: true);
            onBoundary?.Invoke(PublicationBoundary.ManifestActivated);
            EnsureNoReparsePoints(pendingAuditPath);
            EnsureNoReparsePoints(AuditRecordPath(auditDirectory, activatedAudit));
            File.Move(pendingAuditPath, AuditRecordPath(auditDirectory, activatedAudit));
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    private static async Task WriteAuditRecordAsync(string auditRoot, PublicationAuditRecord record,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(auditRoot);
        var path = AuditRecordPath(auditRoot, record);
        var temporaryPath = Path.Combine(auditRoot, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            EnsureNoReparsePoints(path);
            EnsureNoReparsePoints(temporaryPath);
            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(output, record, TrustRoot.JsonOptions, cancellationToken);
                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task WriteRootAuditRecordAsync(string auditRoot, RootPublicationAuditRecord record,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(auditRoot);
        var path = RootAuditRecordPath(auditRoot, record);
        var temporaryPath = Path.Combine(auditRoot, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            EnsureNoReparsePoints(path);
            EnsureNoReparsePoints(temporaryPath);
            await WriteDurableBytesAsync(temporaryPath,
                JsonSerializer.SerializeToUtf8Bytes(record, TrustRoot.JsonOptions), cancellationToken);
            File.Move(temporaryPath, path);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task WritePendingRootAuditRecordAsync(string auditRoot, string pendingPath,
        RootPublicationAuditRecord record, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(auditRoot);
        var temporaryPath = Path.Combine(auditRoot, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            EnsureNoReparsePoints(pendingPath);
            EnsureNoReparsePoints(temporaryPath);
            await WriteDurableBytesAsync(temporaryPath,
                JsonSerializer.SerializeToUtf8Bytes(record, TrustRoot.JsonOptions), cancellationToken);
            File.Move(temporaryPath, pendingPath);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task RecoverPendingRootAuditRecordsAsync(string rootDirectory, string auditRoot,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(auditRoot)) return;
        foreach (var pendingPath in Directory.EnumerateFiles(auditRoot, ".*.root-activated.pending"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureNoReparsePoints(pendingPath);
            RootPublicationAuditRecord record;
            await using (var input = new FileStream(pendingPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                record = await JsonSerializer.DeserializeAsync<RootPublicationAuditRecord>(input,
                    TrustRoot.JsonOptions, cancellationToken)
                    ?? throw new InvalidDataException("Pending TUF root audit record is empty.");
            }
            if (record.SchemaVersion != 1 || record.Event != "activated" || record.RootVersion < 1 ||
                record.RootSha256.Length != 64 || !record.RootSha256.All(Uri.IsHexDigit))
                throw new InvalidDataException("Pending TUF root audit record is invalid.");
            var rootPath = Path.Combine(rootDirectory, $"{record.RootVersion}.json");
            EnsureNoReparsePoints(rootPath);
            if (File.Exists(rootPath))
            {
                await using var rootFile = new FileStream(rootPath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
                var digest = Convert.ToHexString(await SHA256.HashDataAsync(rootFile, cancellationToken)).ToLowerInvariant();
                if (string.Equals(digest, record.RootSha256, StringComparison.Ordinal))
                {
                    var finalPath = RootAuditRecordPath(auditRoot, record);
                    EnsureNoReparsePoints(finalPath);
                    File.Move(pendingPath, finalPath);
                    continue;
                }
            }
            File.Delete(pendingPath);
        }
    }

    private static async Task<bool> HasActivatedRootAuditRecordAsync(string auditRoot, long rootVersion,
        string rootDigest, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(auditRoot)) return false;
        foreach (var path in Directory.EnumerateFiles(auditRoot, "*-root-activated.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureNoReparsePoints(path);
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            RootPublicationAuditRecord record;
            try
            {
                record = await JsonSerializer.DeserializeAsync<RootPublicationAuditRecord>(input,
                    TrustRoot.JsonOptions, cancellationToken)
                    ?? throw new InvalidDataException("TUF root audit record is empty.");
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("TUF root audit record is invalid.", error);
            }
            if (record.SchemaVersion != 1 || record.Event != "activated" ||
                record.RootVersion < 1 || record.RootSha256.Length != 64 || !record.RootSha256.All(Uri.IsHexDigit))
                throw new InvalidDataException("TUF root audit record is invalid.");
            if (record.RootVersion == rootVersion &&
                string.Equals(record.RootSha256, rootDigest, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static IReadOnlyList<string> ReadRootSignatureKeyIds(byte[] envelopeBytes)
    {
        using var document = JsonDocument.Parse(envelopeBytes);
        return document.RootElement.GetProperty("signatures").EnumerateArray()
            .Select(signature => signature.GetProperty("keyid").GetString()!)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
    }

    private static async Task WritePendingAuditRecordAsync(string auditRoot, PublicationAuditRecord record,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(auditRoot);
        var pendingPath = PendingAuditRecordPath(auditRoot, record.PublicationId);
        var temporaryPath = Path.Combine(auditRoot, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            EnsureNoReparsePoints(pendingPath);
            EnsureNoReparsePoints(temporaryPath);
            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(output, record, TrustRoot.JsonOptions, cancellationToken);
                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, pendingPath);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task RecoverPendingAuditRecordsAsync(string auditRoot, string activeManifestPath,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(auditRoot)) return;
        var active = await ReadActiveManifestIdentityAsync(activeManifestPath, cancellationToken);
        foreach (var pendingPath in Directory.EnumerateFiles(auditRoot, ".*.activated.pending"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureNoReparsePoints(pendingPath);
            PublicationAuditRecord record;
            await using (var input = new FileStream(pendingPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                record = await JsonSerializer.DeserializeAsync<PublicationAuditRecord>(input,
                    TrustRoot.JsonOptions, cancellationToken)
                    ?? throw new InvalidDataException("Pending publication audit record is empty.");
            }
            if (record.SchemaVersion != 1 || record.Event != "activated" ||
                !Guid.TryParseExact(record.PublicationId, "N", out _) ||
                record.ManifestSha256 is not { Length: 64 } || !record.ManifestSha256.All(Uri.IsHexDigit) ||
                record.ManifestVersion < 1 || record.PreviousManifestVersion is < 1 ||
                (record.PreviousManifestVersion is long previousVersion && previousVersion >= record.ManifestVersion))
                throw new InvalidDataException("Pending publication audit record is invalid.");

            var finalPath = AuditRecordPath(auditRoot, record);
            if (active.ManifestSha256 is not null &&
                string.Equals(active.ManifestSha256, record.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            {
                if (!File.Exists(finalPath)) File.Move(pendingPath, finalPath);
                else File.Delete(pendingPath);
            }
            else if (active.ManifestVersion == record.PreviousManifestVersion)
            {
                File.Delete(pendingPath);
            }
        }
    }

    private static async Task<(string? ManifestSha256, long? ManifestVersion)> ReadActiveManifestIdentityAsync(
        string activeManifestPath, CancellationToken cancellationToken)
    {
        if (!File.Exists(activeManifestPath)) return (null, null);
        var envelope = JsonSerializer.Deserialize<SignedManifest>(
            await File.ReadAllBytesAsync(activeManifestPath, cancellationToken), TrustRoot.JsonOptions)
            ?? throw new InvalidDataException("Aktives Manifest ist leer.");
        byte[] payload;
        try { payload = Convert.FromBase64String(envelope.Signed); }
        catch (FormatException error) { throw new InvalidDataException("Aktives Manifest ist beschädigt.", error); }
        var manifest = JsonSerializer.Deserialize<UpdateManifest>(payload, TrustRoot.JsonOptions)
            ?? throw new InvalidDataException("Aktives Manifest ist leer.");
        return (Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(), manifest.Version);
    }

    private static async Task WriteDurableBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            128 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
        await output.WriteAsync(bytes, cancellationToken);
        await output.FlushAsync(cancellationToken);
        output.Flush(flushToDisk: true);
    }

    private static string AuditRecordPath(string auditRoot, PublicationAuditRecord record) =>
        Path.Combine(auditRoot,
            $"{record.CreatedAtUtc:yyyyMMddTHHmmssfffffffZ}-{record.PublicationId}-{record.Event}.json");

    private static string RootAuditRecordPath(string auditRoot, RootPublicationAuditRecord record) =>
        Path.Combine(auditRoot,
            $"{record.CreatedAtUtc:yyyyMMddTHHmmssfffffffZ}-{record.PublicationId}-root-{record.Event}.json");

    private static string PendingAuditRecordPath(string auditRoot, string publicationId) =>
        Path.Combine(auditRoot, $".{publicationId}.activated.pending");

    private static string PendingRootAuditRecordPath(string auditRoot, string publicationId) =>
        Path.Combine(auditRoot, $".{publicationId}.root-activated.pending");

    private static void EnsureRootsAreSeparate(params string[] configuredRoots)
    {
        var roots = configuredRoots
            .Select(Path.GetFullPath)
            .Select(Path.TrimEndingDirectorySeparator)
            .ToArray();
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        for (var left = 0; left < roots.Length; left++)
        {
            for (var right = left + 1; right < roots.Length; right++)
            {
                if (string.Equals(roots[left], roots[right], comparison) ||
                    IsInside(roots[left], roots[right], comparison) || IsInside(roots[right], roots[left], comparison))
                    throw new InvalidDataException("Artifact, manifest and audit roots must be separate and non-overlapping.");
            }
        }
    }

    private static void EnsureNoReparsePoints(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var pathRoot = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException("Publisher path has no filesystem root.");
        var relativePath = Path.GetRelativePath(pathRoot, fullPath);
        var segments = relativePath.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        var currentPath = pathRoot;
        foreach (var segment in segments)
        {
            if (segment is "." or "..")
                throw new InvalidDataException("Publisher path contains traversal segments.");
            currentPath = Path.Combine(currentPath, segment);
            FileAttributes attributes;
            try { attributes = File.GetAttributes(currentPath); }
            catch (FileNotFoundException) { break; }
            catch (DirectoryNotFoundException) { break; }

            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Publisher paths must not traverse symbolic links or reparse points.");
            if (currentPath != fullPath && (attributes & FileAttributes.Directory) == 0)
                throw new InvalidDataException("A publisher path parent is not a directory.");
        }
    }

    private static bool IsInside(string candidate, string parent, StringComparison comparison)
    {
        var parentPrefix = Path.EndsInDirectorySeparator(parent) ? parent : parent + Path.DirectorySeparatorChar;
        return candidate.StartsWith(parentPrefix, comparison);
    }

    private static async Task PublishArtifactAsync(
        UpdatePackage package, string sourceRoot, string destinationRoot, CancellationToken cancellationToken)
    {
        var digest = package.Sha256.ToLowerInvariant();
        var sourcePath = Path.Combine(sourceRoot, "sha256", digest[..2], digest);
        var targetDirectory = Path.Combine(destinationRoot, "sha256", digest[..2]);
        var targetPath = Path.Combine(targetDirectory, digest);
        EnsureNoReparsePoints(sourcePath);
        EnsureNoReparsePoints(targetPath);
        if (File.Exists(targetPath))
        {
            await VerifyFileAsync(targetPath, package.Size, digest, cancellationToken);
            return;
        }

        Directory.CreateDirectory(targetDirectory);
        EnsureNoReparsePoints(targetPath);
        var tempPath = Path.Combine(targetDirectory, digest + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[128 * 1024];
                long total = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken)) != 0)
                {
                    total = checked(total + read);
                    if (total > package.Size) throw new InvalidDataException($"Artefakt {package.Id} ist zu groß.");
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                if (total != package.Size || !Convert.ToHexString(hash.GetHashAndReset()).Equals(digest, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"Größe oder SHA-256 von Artefakt {package.Id} stimmt nicht.");
                await output.FlushAsync(cancellationToken);
            }

            try { File.Move(tempPath, targetPath); }
            catch (IOException) when (File.Exists(targetPath))
            {
                await VerifyFileAsync(targetPath, package.Size, digest, cancellationToken);
            }
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    private static async Task VerifyFileAsync(string path, long expectedSize, string expectedHash, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length != expectedSize) throw new InvalidDataException("Hashadressiertes Artefakt kann nicht überschrieben werden.");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        if (!Convert.ToHexString(hash).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Hashadressiertes Artefakt kann nicht überschrieben werden.");
    }

    private sealed record PublicationAuditRecord(int SchemaVersion, string PublicationId, string Event,
        DateTime CreatedAtUtc, string Channel, string Platform, string Architecture, long ManifestVersion,
        string ManifestSha256, string TrustRootSha256, IReadOnlyList<string> SignatureKeyIds,
        long? PreviousManifestVersion, IReadOnlyList<PublishedPackageAudit> Packages);

    private sealed record RootPublicationAuditRecord(int SchemaVersion, string PublicationId, string Event,
        DateTime CreatedAtUtc, long RootVersion, string RootSha256, long PreviousRootVersion,
        string? PreviousRootSha256, string TrustRootSha256, IReadOnlyList<string> SignatureKeyIds);

    private sealed record PublishedPackageAudit(string PackageId, long Size, string Sha256);
}
