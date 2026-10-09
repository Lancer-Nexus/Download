using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace LancerNexus.Download.Tests;

public sealed class DownloadEndpointTests : IAsyncDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "lancer-download-tests", Guid.NewGuid().ToString("N"));
    private WebApplication? app;

    [Fact]
    public async Task ArtifactSupportsHashValidationCachingAndByteRanges()
    {
        var client = await StartAsync();
        var bytes = "immutable test artifact"u8.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var artifact = Path.Combine(root, "artifacts", "sha256", hash[..2], hash);
        Directory.CreateDirectory(Path.GetDirectoryName(artifact)!);
        await File.WriteAllBytesAsync(artifact, bytes);

        using var response = await client.GetAsync($"/v1/artifacts/{hash[..2]}/{hash}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(bytes.Length, response.Content.Headers.ContentLength);
        Assert.Equal($"\"{hash}\"", response.Headers.ETag?.Tag);
        Assert.Contains("immutable", response.Headers.CacheControl?.ToString());
        Assert.Equal(bytes, await response.Content.ReadAsByteArrayAsync());

        using var conditional = new HttpRequestMessage(HttpMethod.Get, $"/v1/artifacts/{hash[..2]}/{hash}");
        conditional.Headers.IfNoneMatch.ParseAdd($"\"{hash}\"");
        using var notModified = await client.SendAsync(conditional);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);

        using var range = new HttpRequestMessage(HttpMethod.Get, $"/v1/artifacts/{hash[..2]}/{hash}");
        range.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 3);
        using var partial = await client.SendAsync(range);
        Assert.Equal(HttpStatusCode.PartialContent, partial.StatusCode);
        Assert.Equal(bytes[..4], await partial.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task ArtifactRejectsUnsafeOrInconsistentHashPaths()
    {
        var client = await StartAsync();
        using var mismatch = await client.GetAsync($"/v1/artifacts/00/{new string('a', 64)}");
        using var traversal = await client.GetAsync($"/v1/artifacts/../{new string('a', 64)}");
        Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
        Assert.True(traversal.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ManifestIsRevalidatedByContentEtagAndHasNoCachePolicy()
    {
        var client = await StartAsync();
        var manifest = Path.Combine(root, "manifests", "stable", "linux-x64.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifest)!);
        await File.WriteAllTextAsync(manifest, "{\"signed\":true}");

        using var response = await client.GetAsync("/v1/channels/stable/manifest");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsByteArrayAsync();
        var expectedTag = $"\"{Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant()}\"";
        Assert.Equal(expectedTag, response.Headers.ETag?.Tag);
        Assert.Equal("no-cache", response.Headers.CacheControl?.ToString());

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/bootstrapper/linux/x64/manifest");
        request.Headers.IfNoneMatch.ParseAdd(expectedTag);
        using var notModified = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);
    }

    private async Task<HttpClient> StartAsync()
    {
        Directory.CreateDirectory(Path.Combine(root, "artifacts"));
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Download:ManifestRoot"] = Path.Combine(root, "manifests"),
            ["Download:ArtifactRoot"] = Path.Combine(root, "artifacts"),
            ["Download:Platform"] = "linux",
            ["Download:Architecture"] = "x64"
        });
        app = DownloadServer.Build(builder);
        await app.StartAsync();
        return app.GetTestClient();
    }

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.DisposeAsync();
        }
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}
