**AGENTS.md – Lancer Nexus ** **Download** ** ** **Server**  
**Mission**  
Deliver authentic, immutable and platform-compatible update metadata and artifacts.  
**Rules**  
- Never generate release signatures with a private key stored on the public server.  
- Publish artifacts before activating a manifest that references them.  
- Never overwrite an artifact at an existing hash or version path.  
- Validate channel, platform, architecture and manifest schema.  
- Keep downloads separate from Gateway sessions and game-cluster state.  
- Enforce safe cache headers and correct content length/ETag behavior.  
- Support auditability for manifest publication and key rotation.  
- Do not return arbitrary filesystem paths or unvalidated URLs.  
- Download the Client for public pages  
