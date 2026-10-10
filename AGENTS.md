**AGENTS.md – Lancer Nexus ** **Download** ** ** **Server**  
**Mission**  
Deliver authentic, immutable and platform-compatible update metadata and artifacts.  
**Rules**  
- Never generate release signatures with a private key stored on the public server.  
- Keep release signing separate; `Publisher/` accepts pre-signed metadata and only the public trust root.
- Verify every package path, size, digest, manifest target and signature before manifest activation.
- Publish all immutable artifacts first; activate channel metadata atomically under a per-target publication lock.
- Write immutable prepared/activated audit records outside publicly served manifest and artifact roots; retain them through deployment-level append-only controls.
- Publish artifacts before activating a manifest that references them.  
- Never overwrite an artifact at an existing hash or version path.  
- Validate channel, platform, architecture and manifest schema.  
- Keep downloads separate from Gateway sessions and game-cluster state.  
- Enforce safe cache headers and correct content length/ETag behavior.  
- Support auditability for manifest publication and key rotation.  
- Do not return arbitrary filesystem paths or unvalidated URLs.  
- Download the Client for public pages  
