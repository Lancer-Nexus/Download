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

## Runtime

The .NET 10 host exposes `/health/live`, `/health/ready`, signed channel manifests at `/v1/channels/{channel}/manifest`, bootstrapper manifests, and immutable artifacts at `/v1/artifacts/{first-two-sha256-characters}/{sha256}`. Artifacts support byte ranges, SHA-256 ETags, conditional `304` responses, one-year immutable caching, and content-length reporting. Manifests use a content-derived ETag and `no-cache` so clients revalidate them. Invalid hash prefixes and unsafe channel/platform/architecture segments are rejected.

Configure `Download:ManifestRoot` and `Download:ArtifactRoot`. Store manifests as `<root>/<channel>/<platform>-<architecture>.json` and artifacts as `<root>/sha256/<prefix>/<sha256>`. The service never accepts arbitrary filesystem paths or manifest URLs. Signature generation and publication stay outside this public serving process.

Run endpoint and signed DownloadServer-to-Updater client artifact integration tests with `dotnet test Tests/Download.Tests.csproj -c Release`. The CI workflow checks out the Updater test seam at a pinned commit so these tests exercise both services without adding a runtime dependency between them.

## Current verification status

As of 2026-10-09, the signed-manifest and immutable-artifact endpoints are covered by 4 passing tests, including an integration flow that serves a signed manifest and a synthetic `tar.zst` client artifact to the Updater, verifies the Ed25519 signature and artifact hash, then stages the client and checks its executable, payload file and generated `client-version.json`. GitHub Actions [CI run 37937675593](https://github.com/Lancer-Nexus/Download/actions/runs/37937675593) passed for commit `ac75ed8d06c6244ccbdcf3231e13b0a0da58375e`. This validates the service-to-Updater test path; publishing production manifests and release artifacts remains to be configured and exercised.
