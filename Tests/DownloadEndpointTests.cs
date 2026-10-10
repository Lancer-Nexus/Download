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
    public async Task ReadinessRequiresArtifactStorageAndAServableStableManifest()
    {
        var client = await StartAsync();

        using (var missingManifest = await client.GetAsync("/health/ready"))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, missingManifest.StatusCode);

        var stableManifest = Path.Combine(root, "manifests", "stable", "linux-x64.json");
        Directory.CreateDirectory(Path.GetDirectoryName(stableManifest)!);
        await File.WriteAllTextAsync(stableManifest, "{\"signed\":\"payload\",\"signatures\":[]}");

        using var ready = await client.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
    }

    [Fact]
    public async Task ReadinessRejectsASymlinkedArtifactRoot()
    {
        var externalArtifacts = Path.Combine(root, "external-artifacts");
        Directory.CreateDirectory(externalArtifacts);
        var linkedArtifactRoot = Path.Combine(root, "artifact-root-link");
        Directory.CreateSymbolicLink(linkedArtifactRoot, externalArtifacts);
        var client = await StartAsync(artifactRootOverride: linkedArtifactRoot);
        var stableManifest = Path.Combine(root, "manifests", "stable", "linux-x64.json");
        Directory.CreateDirectory(Path.GetDirectoryName(stableManifest)!);
        await File.WriteAllTextAsync(stableManifest, "{\"signed\":\"payload\",\"signatures\":[]}");

        using var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

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
    public async Task ArtifactDoesNotFollowSymbolicLinkOutsideArtifactRoot()
    {
        var client = await StartAsync();
        var bytes = "outside-root secret"u8.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var externalDirectory = Path.Combine(root, "external-artifacts");
        Directory.CreateDirectory(externalDirectory);
        await File.WriteAllBytesAsync(Path.Combine(externalDirectory, hash), bytes);
        var hashDirectory = Path.Combine(root, "artifacts", "sha256");
        Directory.CreateDirectory(hashDirectory);
        Directory.CreateSymbolicLink(Path.Combine(hashDirectory, hash[..2]), externalDirectory);

        using var response = await client.GetAsync($"/v1/artifacts/{hash[..2]}/{hash}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ArtifactDoesNotFollowSymbolicLinksInConfiguredRootPath(bool symlinkIsRoot)
    {
        var content = "outside configured-root secret"u8.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var externalStorage = Path.Combine(root, "external-storage");
        var linkedComponent = Path.Combine(root, "storage-link");
        var configuredArtifactRoot = symlinkIsRoot
            ? linkedComponent
            : Path.Combine(linkedComponent, "artifacts");
        var externalArtifactRoot = symlinkIsRoot
            ? externalStorage
            : Path.Combine(externalStorage, "artifacts");
        var artifact = Path.Combine(externalArtifactRoot, "sha256", hash[..2], hash);
        Directory.CreateDirectory(Path.GetDirectoryName(artifact)!);
        await File.WriteAllBytesAsync(artifact, content);
        Directory.CreateSymbolicLink(linkedComponent, externalStorage);
        var client = await StartAsync(artifactRootOverride: configuredArtifactRoot);

        using var response = await client.GetAsync($"/v1/artifacts/{hash[..2]}/{hash}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
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
        Assert.Equal(body.Length, response.Content.Headers.ContentLength);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/bootstrapper/linux/x64/manifest");
        request.Headers.IfNoneMatch.ParseAdd(expectedTag);
        using var notModified = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);
    }

    [Fact]
    public async Task VersionedRootMetadataIsServedWithContentEtag()
    {
        var client = await StartAsync();
        var content = "{\"signed\":{\"_type\":\"root\",\"version\":2},\"signatures\":[]}"u8.ToArray();
        var rootMetadata = Path.Combine(root, "manifests", "root", "2.json");
        Directory.CreateDirectory(Path.GetDirectoryName(rootMetadata)!);
        await File.WriteAllBytesAsync(rootMetadata, content);

        using var response = await client.GetAsync("/v1/metadata/root/2");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(content, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal($"\"{Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant()}\"",
            response.Headers.ETag?.Tag);
        Assert.Equal("no-cache", response.Headers.CacheControl?.ToString());
    }

    [Theory]
    [InlineData("timestamp.json")]
    [InlineData("snapshot.json")]
    [InlineData("targets.json")]
    [InlineData("3.snapshot.json")]
    [InlineData("4.targets.json")]
    [InlineData("content.json")]
    [InlineData("delegates/content.json")]
    [InlineData("7.delegates/content.json")]
    public async Task TopLevelTufMetadataIsServedWithRevalidation(string metadataFile)
    {
        var client = await StartAsync();
        var content = System.Text.Encoding.UTF8.GetBytes("{\"signed\":{\"_type\":\"timestamp\"}}");
        var path = Path.Combine(root, "manifests", "metadata", metadataFile);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, content);

        using var response = await client.GetAsync($"/v1/metadata/{metadataFile}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(content, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("no-cache", response.Headers.CacheControl?.ToString());
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/v1/metadata/{metadataFile}");
        request.Headers.IfNoneMatch.ParseAdd(response.Headers.ETag!.Tag);
        using var notModified = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);
    }

    [Theory]
    [InlineData("root/1.json")]
    [InlineData("../../outside.json")]
    [InlineData("other.json")]
    [InlineData("0.snapshot.json")]
    [InlineData("03.targets.json")]
    [InlineData("delegates/../outside.json")]
    [InlineData("delegates//outside.json")]
    public async Task TopLevelTufMetadataRejectsPathsAndUnknownRoles(string metadataFile)
    {
        var client = await StartAsync();

        using var response = await client.GetAsync($"/v1/metadata/{metadataFile}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task TopLevelTufMetadataDoesNotFollowSymlinkOutsideManifestRoot()
    {
        var client = await StartAsync();
        var externalMetadata = Path.Combine(root, "outside-timestamp.json");
        await File.WriteAllTextAsync(externalMetadata, "{\"private\":true}");
        var metadataDirectory = Path.Combine(root, "manifests", "metadata");
        Directory.CreateDirectory(metadataDirectory);
        File.CreateSymbolicLink(Path.Combine(metadataDirectory, "timestamp.json"), externalMetadata);

        using var response = await client.GetAsync("/v1/metadata/timestamp.json");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task VersionedRootMetadataRejectsInvalidVersionsAndSymlinkedFiles()
    {
        var client = await StartAsync();
        using (var invalidVersion = await client.GetAsync("/v1/metadata/root/0"))
            Assert.Equal(HttpStatusCode.BadRequest, invalidVersion.StatusCode);

        var externalMetadata = Path.Combine(root, "outside-root.json");
        await File.WriteAllTextAsync(externalMetadata, "{\"signed\":{\"version\":2}}");
        var rootDirectory = Path.Combine(root, "manifests", "root");
        Directory.CreateDirectory(rootDirectory);
        File.CreateSymbolicLink(Path.Combine(rootDirectory, "2.json"), externalMetadata);

        using var response = await client.GetAsync("/v1/metadata/root/2");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ManifestDoesNotFollowSymbolicLinkOutsideManifestRoot()
    {
        var client = await StartAsync();
        var externalManifest = Path.Combine(root, "outside-manifest.json");
        await File.WriteAllTextAsync(externalManifest, "{\"private\":true}");
        var stableDirectory = Path.Combine(root, "manifests", "stable");
        Directory.CreateDirectory(stableDirectory);
        File.CreateSymbolicLink(Path.Combine(stableDirectory, "linux-x64.json"), externalManifest);

        using var response = await client.GetAsync("/v1/channels/stable/manifest");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private async Task<HttpClient> StartAsync(string? artifactRootOverride = null, string? manifestRootOverride = null)
    {
        Directory.CreateDirectory(Path.Combine(root, "artifacts"));
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Download:ManifestRoot"] = manifestRootOverride ?? Path.Combine(root, "manifests"),
            ["Download:ArtifactRoot"] = artifactRootOverride ?? Path.Combine(root, "artifacts"),
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
