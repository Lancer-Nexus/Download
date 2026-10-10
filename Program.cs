using System.Security.Cryptography;
using System.Globalization;
using Microsoft.Net.Http.Headers;
using LancerNexus.Download;

var builder = WebApplication.CreateBuilder(args);
var app = DownloadServer.Build(builder);
await app.RunAsync();

public static class DownloadServer
{
    private const long MaximumManifestBytes = 2 * 1024 * 1024;

    public static WebApplication Build(WebApplicationBuilder builder)
    {
        var options = DownloadServerOptions.FromConfiguration(builder.Configuration);
        builder.Services.AddSingleton(options);

        var app = builder.Build();
        var logger = app.Logger;
        var stableManifestPath = Path.Combine(options.ManifestRoot, "stable", $"{options.Platform}-{options.Architecture}.json");
        logger.LogInformation(
            "Download service starting for {Platform}/{Architecture}; artifact storage {ArtifactStorageStatus}; stable manifest {ManifestStatus}.",
            options.Platform,
            options.Architecture,
            Directory.Exists(options.ArtifactRoot) ? "available" : "missing",
            File.Exists(stableManifestPath) ? "available" : "missing");

        app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
        app.MapGet("/health/ready", (DownloadServerOptions settings) =>
            IsReady(settings)
                ? Results.Ok(new { status = "ready" })
                : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));

        app.MapGet("/v1/channels/{channel}/manifest", ServeManifestAsync);
        app.MapGet("/v1/bootstrapper/{platform}/{architecture}/manifest", ServeBootstrapperManifestAsync);
        app.MapGet("/v1/metadata/root/{version:long}", ServeRootMetadataAsync);
        app.MapGet("/v1/metadata/{**metadataFile}", ServeTufMetadataAsync);
        app.MapGet("/v1/artifacts/{prefix}/{hash}", ServeArtifact);
        return app;
    }

    private static Task<IResult> ServeManifestAsync(
        string channel, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
        ServeManifestFileAsync(settings.ManifestRoot,
            ManifestPath(settings, channel, settings.Platform, settings.Architecture), context, cancellationToken);

    private static Task<IResult> ServeBootstrapperManifestAsync(
        string platform, string architecture, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
        ServeManifestFileAsync(settings.ManifestRoot,
            ManifestPath(settings, "stable", platform, architecture), context, cancellationToken);

    private static Task<IResult> ServeRootMetadataAsync(
        long version, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken)
    {
        if (version < 1) return Task.FromResult<IResult>(Results.BadRequest());
        var path = Path.Combine(settings.ManifestRoot, "root", $"{version}.json");
        return ServeManifestFileAsync(settings.ManifestRoot, path, context, cancellationToken);
    }

    private static Task<IResult> ServeTufMetadataAsync(
        string metadataFile, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken)
    {
        // Delegated role names are constrained TUF paths; root metadata has its own endpoint.
        if (!IsSupportedTufMetadataFile(metadataFile))
            return Task.FromResult<IResult>(Results.NotFound());
        var path = Path.Combine(settings.ManifestRoot, "metadata", metadataFile);
        return ServeManifestFileAsync(settings.ManifestRoot, path, context, cancellationToken);
    }

    private static bool IsSupportedTufMetadataFile(string metadataFile)
    {
        if (metadataFile is "timestamp.json" or "snapshot.json" or "targets.json") return true;
        var rolePath = metadataFile;
        var firstSeparator = rolePath.IndexOf('/');
        var firstSegment = firstSeparator < 0 ? rolePath : rolePath[..firstSeparator];
        var versionSeparator = firstSegment.IndexOf('.');
        if (versionSeparator > 0 && firstSegment[..versionSeparator].All(char.IsAsciiDigit))
        {
            var versionText = firstSegment[..versionSeparator];
            if (!long.TryParse(versionText, NumberStyles.None, CultureInfo.InvariantCulture, out var version) ||
                version < 1 || version.ToString(CultureInfo.InvariantCulture) != versionText)
                return false;
            rolePath = firstSegment[(versionSeparator + 1)..] +
                       (firstSeparator < 0 ? "" : metadataFile[firstSeparator..]);
        }

        if (!rolePath.EndsWith(".json", StringComparison.Ordinal)) return false;
        var role = rolePath[..^".json".Length];
        if (role is "snapshot" or "targets") return true;
        if (role.Contains('/') && role.Split('/').Any(segment => segment is "" or "." or "..")) return false;
        return role.Length is > 0 and <= 256 &&
               role.Split('/').All(segment => segment.Length > 0 && segment is not ("." or "..") &&
                   segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')) &&
               (role.Contains('/') || role is not ("root" or "timestamp" or "snapshot" or "targets" or "mirrors"));
    }

    private static async Task<IResult> ServeManifestFileAsync(string root, string? path, HttpContext context,
        CancellationToken cancellationToken)
    {
        if (path is null || !IsRegularFileUnderRoot(root, path)) return Results.NotFound();
        var info = new FileInfo(path);
        if (info.Length > MaximumManifestBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        var etag = new EntityTagHeaderValue($"\"{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}\"");
        context.Response.Headers.CacheControl = "no-cache";
        context.Response.Headers.ETag = etag.ToString();
        context.Response.Headers.XContentTypeOptions = "nosniff";
        if (MatchesIfNoneMatch(context.Request, etag)) return Results.StatusCode(StatusCodes.Status304NotModified);
        return Results.Bytes(bytes, "application/json");
    }

    private static IResult ServeArtifact(string prefix, string hash, HttpContext context, DownloadServerOptions settings)
    {
        if (!IsHashPath(prefix, hash)) return Results.BadRequest();
        var path = Path.Combine(settings.ArtifactRoot, "sha256", prefix.ToLowerInvariant(), hash.ToLowerInvariant());
        if (!IsRegularFileUnderRoot(settings.ArtifactRoot, path)) return Results.NotFound();

        var etag = new EntityTagHeaderValue($"\"{hash.ToLowerInvariant()}\"");
        context.Response.Headers.CacheControl = "public,max-age=31536000,immutable";
        context.Response.Headers.ETag = etag.ToString();
        context.Response.Headers.XContentTypeOptions = "nosniff";
        if (MatchesIfNoneMatch(context.Request, etag)) return Results.StatusCode(StatusCodes.Status304NotModified);
        try
        {
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return Results.File(stream, "application/octet-stream", enableRangeProcessing: true);
        }
        catch (FileNotFoundException)
        {
            return Results.NotFound();
        }
        catch (DirectoryNotFoundException)
        {
            return Results.NotFound();
        }
    }

    private static string? ManifestPath(DownloadServerOptions settings, string channel, string platform, string architecture)
    {
        if (!IsSafeSegment(channel) || !IsSafeSegment(platform) || !IsSafeSegment(architecture)) return null;
        return Path.Combine(settings.ManifestRoot, channel, $"{platform}-{architecture}.json");
    }

    private static bool IsHashPath(string prefix, string hash) =>
        prefix.Length == 2 && hash.Length == 64 && prefix.All(Uri.IsHexDigit) && hash.All(Uri.IsHexDigit) &&
        hash.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeSegment(string value) => value.Length is > 0 and <= 32 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static bool IsRegularFileUnderRoot(string root, string path)
    {
        try
        {
            var fullRoot = Path.GetFullPath(root);
            if (!IsSafeDirectoryPath(fullRoot)) return false;

            var rootPrefix = fullRoot.EndsWith(Path.DirectorySeparatorChar)
                ? fullRoot
                : fullRoot + Path.DirectorySeparatorChar;
            var fullPath = Path.GetFullPath(path);
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!fullPath.StartsWith(rootPrefix, comparison)) return false;

            var relativePath = Path.GetRelativePath(fullRoot, fullPath);
            var segments = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var currentPath = fullRoot;
            FileAttributes attributes = 0;
            for (var index = 0; index < segments.Length; index++)
            {
                var segment = segments[index];
                if (segment is "" or "." or "..") return false;
                currentPath = Path.Combine(currentPath, segment);
                attributes = File.GetAttributes(currentPath);
                if ((attributes & FileAttributes.ReparsePoint) != 0) return false;
                if (index < segments.Length - 1 && (attributes & FileAttributes.Directory) == 0)
                    return false;
            }

            return (attributes & FileAttributes.Directory) == 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsReady(DownloadServerOptions settings)
    {
        if (!IsSafeDirectoryPath(settings.ArtifactRoot)) return false;
        var manifestPath = ManifestPath(settings, "stable", settings.Platform, settings.Architecture);
        if (manifestPath is null || !IsRegularFileUnderRoot(settings.ManifestRoot, manifestPath)) return false;
        var length = new FileInfo(manifestPath).Length;
        return length is > 0 and <= MaximumManifestBytes;
    }

    private static bool IsSafeDirectoryPath(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var filesystemRoot = Path.GetPathRoot(fullPath);
            if (filesystemRoot is null) return false;
            var relativePath = Path.GetRelativePath(filesystemRoot, fullPath);
            if (relativePath == ".") return false;
            var currentPath = filesystemRoot;
            foreach (var segment in relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                if (segment is "" or "." or "..") return false;
                currentPath = Path.Combine(currentPath, segment);
                var attributes = File.GetAttributes(currentPath);
                if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                    (attributes & FileAttributes.Directory) == 0)
                    return false;
            }
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool MatchesIfNoneMatch(HttpRequest request, EntityTagHeaderValue etag) =>
        request.GetTypedHeaders().IfNoneMatch?.Any(candidate => candidate.Equals(EntityTagHeaderValue.Any) ||
            candidate.Compare(etag, useStrongComparison: false)) == true;
}

public partial class Program;
