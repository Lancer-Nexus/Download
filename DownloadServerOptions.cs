namespace LancerNexus.Download;

public sealed record DownloadServerOptions(string ManifestRoot, string ArtifactRoot, string Platform, string Architecture)
{
    public static DownloadServerOptions FromConfiguration(IConfiguration configuration) => new(
        Path.GetFullPath(configuration["Download:ManifestRoot"] ?? "manifests"),
        Path.GetFullPath(configuration["Download:ArtifactRoot"] ?? "artifacts"),
        configuration["Download:Platform"] ?? "linux",
        configuration["Download:Architecture"] ?? "x64");
}
