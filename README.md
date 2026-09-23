**Lancer Nexus ** **Download** ** ** **Server**  
The Download Server publishes signed manifests and immutable client/game-data artifacts for Windows and Linux.  
**Responsibilities**  
- Serve channel- and platform-specific manifests  
- Publish immutable artifacts addressed by hash  
- Support stable, beta, nightly and internal channels  
- Expose health and readiness endpoints  
- Integrate with the GitHub Actions release pipeline  
- Keep signing operations separate from public artifact serving  
The Download Server does not authenticate game sessions and does not replace the Gateway.

## Skeleton runtime

The .NET 10 minimal host currently exposes `/health/live`, `/health/ready`, channel manifests under `/v1/channels/{channel}/manifest`, bootstrapper manifests and hash-addressed artifacts under `/v1/artifacts/{prefix}/{sha256}`. Configure `Download:ManifestRoot` and `Download:ArtifactRoot`; the service never accepts arbitrary filesystem paths or manifest URLs. Signature generation/publication is intentionally outside this public serving process.
