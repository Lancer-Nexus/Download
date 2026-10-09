using System.Security.Cryptography;
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
            Directory.Exists(settings.ArtifactRoot)
                ? Results.Ok(new { status = "ready" })
                : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));

        app.MapGet("/v1/channels/{channel}/manifest", ServeManifestAsync);
        app.MapGet("/v1/bootstrapper/{platform}/{architecture}/manifest", ServeBootstrapperManifestAsync);
        app.MapGet("/v1/artifacts/{prefix}/{hash}", ServeArtifact);
        return app;
    }

    private static Task<IResult> ServeManifestAsync(
        string channel, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
        ServeManifestFileAsync(ManifestPath(settings, channel, settings.Platform, settings.Architecture), context, cancellationToken);

    private static Task<IResult> ServeBootstrapperManifestAsync(
        string platform, string architecture, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
        ServeManifestFileAsync(ManifestPath(settings, "stable", platform, architecture), context, cancellationToken);

    private static async Task<IResult> ServeManifestFileAsync(string? path, HttpContext context, CancellationToken cancellationToken)
    {
        if (path is null || !File.Exists(path)) return Results.NotFound();
        var info = new FileInfo(path);
        if (info.Length > MaximumManifestBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        var etag = new EntityTagHeaderValue($"\"{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}\"");
        context.Response.Headers.CacheControl = "no-cache";
        context.Response.Headers.ETag = etag.ToString();
        context.Response.Headers.XContentTypeOptions = "nosniff";
        if (MatchesIfNoneMatch(context.Request, etag)) return Results.StatusCode(StatusCodes.Status304NotModified);
        return Results.File(path, "application/json", enableRangeProcessing: false);
    }

    private static IResult ServeArtifact(string prefix, string hash, HttpContext context, DownloadServerOptions settings)
    {
        if (!IsHashPath(prefix, hash)) return Results.BadRequest();
        var path = Path.Combine(settings.ArtifactRoot, "sha256", prefix.ToLowerInvariant(), hash.ToLowerInvariant());
        if (!File.Exists(path)) return Results.NotFound();

        var etag = new EntityTagHeaderValue($"\"{hash.ToLowerInvariant()}\"");
        context.Response.Headers.CacheControl = "public,max-age=31536000,immutable";
        context.Response.Headers.ETag = etag.ToString();
        context.Response.Headers.XContentTypeOptions = "nosniff";
        if (MatchesIfNoneMatch(context.Request, etag)) return Results.StatusCode(StatusCodes.Status304NotModified);
        return Results.File(path, "application/octet-stream", enableRangeProcessing: true);
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

    private static bool MatchesIfNoneMatch(HttpRequest request, EntityTagHeaderValue etag) =>
        request.GetTypedHeaders().IfNoneMatch?.Any(candidate => candidate.Equals(EntityTagHeaderValue.Any) ||
            candidate.Compare(etag, useStrongComparison: false)) == true;
}

public partial class Program;
