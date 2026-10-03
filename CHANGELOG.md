# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-03

First public release. Early and unaudited: read SECURITY.md before relying on it.

### Added

- **Service.** A WSGI application under gunicorn with SQLite storage: request creation signed by the caller and checked before the body is read, encrypted content and large encrypted attachments, enrolment of passkeys with the PRF extension, a chain of key statements per recipient with epochs, answers confirmed by a device or by a device session and stored only sealed, a queue and an inbox for a live session.
- **Web client.** Decrypts and renders in the browser: text, HTML with its own styling, images, PDF, video, audio and files; buttons, form fields and a comment; caller-designed full pages. It checks what the service presents against the facts the caller sealed, and replays the recipient's key statement chain from the device's own anchor before signing a key change. Every client file is listed in a release manifest and loaded with Subresource Integrity.
- **Caller library and CLI** (`caller/hitl.py`): key pinning by chain replay and fingerprint, request creation under an id the caller mints, verification of every part of a signed answer by the caller's own record and clock, exactly-once consumption, `hold` when the service is unreachable.
- **MCP bridge** (`caller/mcp/`): `ask_human`, `list_recipients` and `check_human` for agents, with every outcome (answered, expired, rejected) handed to the deployment as a delivery file.
- **Review of an answered request.** A caller may allow it per request (`--review`, `allow_review`, `policy.review`): the recipient can open the link again and see the request with their signed answer, read-only.
- **Dictation.** A Dictate button beside free-text fields where the browser offers speech recognition. The page sends nothing; the browser's speech service hears the audio.
- **Configurable request life.** `HITL_MAX_TTL` on the service and `HITL_MCP_MAX_TTL_MINUTES` on the bridge; both default to 7 days.
- **Tools.** `release.py` builds and checks the client manifest and lets an operator sign it with a key of their own, `verify_deployment.py` compares what a deployment serves with a checkout, `prepublish.py` checks that a release carries nothing private.
- **Tests.** An end-to-end test with a virtual authenticator, including a service that lies to the page; a lying service against the caller library and hostile clients against the service, without a browser; and shared vectors (canonical JSON, signed objects, assertions, key statement chains) checked against the server, the caller and the web client.
