using System.Text.Json;
using LancerNexus.Download;
using LancerNexus.Updater;

var arguments = Parse(args);
if (arguments is null)
{
    Console.Error.WriteLine("Usage: Publisher --manifest FILE --trust-root FILE --source-root DIR --artifact-root DIR --manifest-root DIR --audit-root DIR\n       Publisher --root-metadata FILE --trust-root FILE --manifest-root DIR --audit-root DIR\n       Publisher --tuf-timestamp FILE --tuf-snapshot FILE --tuf-targets FILE [--tuf-delegated-dir DIR] --trust-root FILE --artifact-root DIR --manifest-root DIR --audit-root DIR");
    return 2;
}

try
{
    if (arguments.TryGetValue("tuf-timestamp", out var timestampPath))
    {
        var metadataTrustRoot = TrustRoot.Load(arguments["trust-root"]);
        if (arguments.TryGetValue("root-chain-state", out var metadataRootChainStatePath))
            metadataTrustRoot = await TufRootRotationVerifier.UpdateChainAsync(metadataTrustRoot,
                metadataRootChainStatePath, (_, _) => Task.FromResult<byte[]?>(null), DateTime.UtcNow);
        var snapshotBytes = await File.ReadAllBytesAsync(arguments["tuf-snapshot"]);
        var delegatedMetadata = arguments.TryGetValue("tuf-delegated-dir", out var delegatedDirectory)
            ? await LoadDelegatedMetadataAsync(snapshotBytes, delegatedDirectory, metadataTrustRoot.ConsistentSnapshot)
            : new Dictionary<string, byte[]>(StringComparer.Ordinal);
        await ReleasePublisher.PublishTufMetadataAsync(await File.ReadAllBytesAsync(timestampPath),
            snapshotBytes, await File.ReadAllBytesAsync(arguments["tuf-targets"]), delegatedMetadata, metadataTrustRoot,
            arguments["artifact-root"], arguments["manifest-root"], arguments["audit-root"], DateTime.UtcNow);
        Console.WriteLine($"Published verified TUF timestamp, snapshot, targets and {delegatedMetadata.Count} delegated roles.");
        return 0;
    }

    if (arguments.TryGetValue("root-metadata", out var rootMetadataPath))
    {
        var rootTrustRoot = TrustRoot.Load(arguments["trust-root"]);
        if (arguments.TryGetValue("root-chain-state", out var rootChainStatePath))
            rootTrustRoot = await TufRootRotationVerifier.UpdateChainAsync(rootTrustRoot, rootChainStatePath,
                (_, _) => Task.FromResult<byte[]?>(null), DateTime.UtcNow);
        await ReleasePublisher.PublishRootMetadataAsync(await File.ReadAllBytesAsync(rootMetadataPath), rootTrustRoot,
            arguments["manifest-root"], arguments["audit-root"], DateTime.UtcNow);
        Console.WriteLine("Published verified TUF root metadata.");
        return 0;
    }

    var envelope = JsonSerializer.Deserialize<SignedManifest>(
        await File.ReadAllBytesAsync(arguments["manifest"]), TrustRoot.JsonOptions)
        ?? throw new InvalidDataException("Signed manifest is empty.");
    var trustRoot = TrustRoot.Load(arguments["trust-root"]);
    var payload = Convert.FromBase64String(envelope.Signed);
    var manifest = JsonSerializer.Deserialize<UpdateManifest>(payload, TrustRoot.JsonOptions)
        ?? throw new InvalidDataException("Signed manifest payload is empty.");
    var options = new UpdaterOptions(new Uri("https://publisher.invalid/v1/channels/" + manifest.Channel + "/manifest"),
        manifest.Channel, manifest.Platform, manifest.Architecture, arguments["trust-root"]);
    await ReleasePublisher.PublishAsync(envelope, trustRoot, options, arguments["source-root"],
        arguments["artifact-root"], arguments["manifest-root"], arguments["audit-root"], DateTime.UtcNow);
    Console.WriteLine($"Published {manifest.Channel}/{manifest.Platform}-{manifest.Architecture} manifest version {manifest.Version}.");
    return 0;
}
catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
                              FormatException or JsonException or ArgumentException or InvalidOperationException)
{
    Console.Error.WriteLine($"Release publication failed: {error.Message}");
    return 1;
}

static Dictionary<string, string>? Parse(string[] values)
{
    var result = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < values.Length; index += 2)
    {
        if (index + 1 >= values.Length || values[index] is not
            ("--manifest" or "--root-metadata" or "--tuf-timestamp" or "--tuf-snapshot" or "--tuf-targets" or
             "--root-chain-state" or "--tuf-delegated-dir" or "--trust-root" or "--source-root" or "--artifact-root" or "--manifest-root" or "--audit-root") ||
            !result.TryAdd(values[index][2..], values[index + 1])) return null;
    }
    var rootPublication = result.ContainsKey("root-metadata");
    var tufPublication = result.ContainsKey("tuf-timestamp") || result.ContainsKey("tuf-snapshot") ||
                         result.ContainsKey("tuf-targets");
    var expected = tufPublication
        ? new[] { "tuf-timestamp", "tuf-snapshot", "tuf-targets", "trust-root", "artifact-root", "manifest-root", "audit-root" }
        : rootPublication
            ? new[] { "root-metadata", "trust-root", "manifest-root", "audit-root" }
            : new[] { "manifest", "trust-root", "source-root", "artifact-root", "manifest-root", "audit-root" };
    var allowsChain = rootPublication || tufPublication;
    var allowedWithChain = expected.ToList();
    if (allowsChain && result.ContainsKey("root-chain-state")) allowedWithChain.Add("root-chain-state");
    if (tufPublication && result.ContainsKey("tuf-delegated-dir")) allowedWithChain.Add("tuf-delegated-dir");
    if (result.ContainsKey("root-metadata") && tufPublication ||
        tufPublication && !new[] { "tuf-timestamp", "tuf-snapshot", "tuf-targets" }.All(result.ContainsKey))
        return null;
    return result.Count == allowedWithChain.Count && allowedWithChain.All(result.ContainsKey) ? result : null;
}

static async Task<Dictionary<string, byte[]>> LoadDelegatedMetadataAsync(byte[] snapshotBytes,
    string metadataDirectory, bool consistentSnapshot)
{
    using var document = JsonDocument.Parse(snapshotBytes);
    var meta = document.RootElement.GetProperty("signed").GetProperty("meta");
    var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
    foreach (var item in meta.EnumerateObject())
    {
        if (item.Name == "targets.json") continue;
        if (!item.Name.EndsWith(".json", StringComparison.Ordinal))
            throw new InvalidDataException("TUF snapshot contains an invalid delegated metadata path.");
        var role = item.Name[..^".json".Length];
        if (role.Length is < 1 or > 256 || role.StartsWith('/') || role.EndsWith('/') || role.Contains('\\') ||
            role.Contains(':') || role.Contains('%') || role.Split('/').Any(segment => segment.Length == 0 ||
                segment is "." or ".." || segment.Any(character => !char.IsAsciiLetterOrDigit(character) &&
                    character is not ('.' or '_' or '-'))))
            throw new InvalidDataException("TUF snapshot contains an unsafe delegated metadata role name.");
        if (!item.Value.TryGetProperty("version", out var versionElement) ||
            !versionElement.TryGetInt64(out var version) || version < 1)
            throw new InvalidDataException("TUF delegated metadata reference has an invalid version.");
        var fileName = consistentSnapshot ? $"{version}.{role}.json" : $"{role}.json";
        var sourcePath = Path.Combine(metadataDirectory, fileName.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException($"Delegated TUF metadata file for role '{role}' was not found.", sourcePath);
        if (!result.TryAdd(role, await File.ReadAllBytesAsync(sourcePath)))
            throw new InvalidDataException("TUF snapshot contains duplicate delegated role references.");
    }
    return result;
}
