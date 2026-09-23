using LancerNexus.Download;

var builder = WebApplication.CreateBuilder(args);
var options = DownloadServerOptions.FromConfiguration(builder.Configuration);
builder.Services.AddSingleton(options);

var app = builder.Build();
app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
app.MapGet("/health/ready", (DownloadServerOptions settings) =>
    Directory.Exists(settings.ArtifactRoot)
        ? Results.Ok(new { status = "ready" })
        : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));

app.MapGet("/v1/channels/{channel}/manifest", async (
    string channel, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
{
    var path = ManifestPath(settings, channel, settings.Platform, settings.Architecture);
    if (path is null || !File.Exists(path)) return Results.NotFound();
    context.Response.Headers.CacheControl = "no-cache";
    return Results.File(path, "application/json", enableRangeProcessing: false);
});

app.MapGet("/v1/bootstrapper/{platform}/{architecture}/manifest", async (
    string platform, string architecture, HttpContext context, DownloadServerOptions settings, CancellationToken cancellationToken) =>
{
    var path = ManifestPath(settings, "stable", platform, architecture);
    if (path is null || !File.Exists(path)) return Results.NotFound();
    context.Response.Headers.CacheControl = "no-cache";
    return Results.File(path, "application/json", enableRangeProcessing: false);
});

app.MapGet("/v1/artifacts/{prefix}/{hash}", (string prefix, string hash, DownloadServerOptions settings) =>
{
    if (!IsHashPath(prefix, hash)) return Results.BadRequest();
    var path = Path.Combine(settings.ArtifactRoot, "sha256", prefix, hash);
    return File.Exists(path) ? Results.File(path, "application/octet-stream", enableRangeProcessing: true) : Results.NotFound();
});

app.Run();

static string? ManifestPath(DownloadServerOptions settings, string channel, string platform, string architecture)
{
    if (!IsSafeSegment(channel) || !IsSafeSegment(platform) || !IsSafeSegment(architecture)) return null;
    return Path.Combine(settings.ManifestRoot, channel, $"{platform}-{architecture}.json");
}

static bool IsHashPath(string prefix, string hash) =>
    prefix.Length is 2 and not 0 && hash.Length == 64 && prefix.All(Uri.IsHexDigit) && hash.All(Uri.IsHexDigit);
static bool IsSafeSegment(string value) => value.Length is > 0 and <= 32 && value.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');

public partial class Program;
