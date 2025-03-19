# Federation

## Supported federation protocols and standards

- [ActivityPub](https://www.w3.org/TR/activitypub/) (Server-to-Server and limited Client-to-Server)
- [WebFinger](https://webfinger.net/)
- [HTTP Signatures](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures)

## Supported FEPs

- [FEP-67ff: Federation Documentation](https://codeberg.org/fediverse/fep/src/branch/main/fep/67ff/fep-67ff.md) - This document itself implements FEP-67ff

## ActivityPub

Jaseur implements a subset of the ActivityPub protocol, with primary focus on server-to-server (federation) interactions and limited client-to-server support. It supports the following core ActivityPub functionality:

### Supported Activities

- **Follow**: Processing incoming follow requests and managing follower collections
- **Create**: Processing and delivering new content (primarily Notes)
- **Delete**: Processing delete operations for activities and objects

### Protocol Support

#### Server-to-Server (S2S)
- **Inbox Delivery**: Accepts incoming activities via POST requests to actor inboxes
- **HTTP Signature Authentication**: Verifies the authenticity of incoming federation requests

#### Client-to-Server (C2S)
- **Outbox Publishing**: Accepts Create activities posted to actor outboxes from authenticated clients
- **Bearer Token Authentication**: Supports API token authentication for local clients

### Collections

- **Inbox**: Stores and manages incoming activities
- **Outbox**: Stores and manages outgoing activities
- **Followers**: Maintains a list of actors following the local actor
- **Following**: Maintains a list of actors the local actor follows

## Implementation Details

### Resource Storage

Activities and objects are stored using a flexible storage system:

- Default implementation uses file-based storage with SHA-256 content addressing
- Storage is abstracted behind the `ResourceStore` interface, allowing for alternative backends
- Resources are stored as JSON objects with consistent ActivityPub formatting

### URI Independence

Jaseur uses a content-addressed storage system that doesn't rely on specific URI path structures:

- URIs are mapped to storage locations using hash functions
- This architecture allows for future multi-tenant (multi-domain) support
- WebFinger enables discovery of actor resources regardless of URI structure

### Security

- **HTTP Signatures**: All federated requests are authenticated using HTTP Signatures
- **Private Key Management**: Secure storage of private keys in a separate directory
- **IP Filtering**: Optional restriction of server access to specific IP addresses
- **Bearer Token Authentication**: API token authentication for local clients

## Limitations

- No support for [NodeInfo](https://nodeinfo.diaspora.software/) protocol
- Limited implementation of FEPs (Only supports FEP-67ff for federation documentation)
- Limited support for complex ActivityPub extension mechanisms
- Experimental implementation not intended for production use

## LLM Integration

Jaseur includes experimental integration with Large Language Models (LLMs) via Ollama:

- Automated responses to incoming activities
- Content generation capabilities
- Configurable through the standard configuration system