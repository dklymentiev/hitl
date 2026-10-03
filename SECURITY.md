# Security

## Reporting a vulnerability

Report privately through "Report a vulnerability" on the Security tab of this repository (GitHub private vulnerability reporting). Please do not open a public issue for a security problem.

Say what you found, how to reproduce it, and which commit you tested.

## Supported versions

The latest release. There are no maintenance branches.

## What hitl is meant to guarantee

Stated for a caller that uses the caller library in this repository and has pinned the recipient's keys by comparing the fingerprint outside the service.

- **An answer is the recipient's.** It is signed by a WebAuthn credential the caller pinned, with user verification, or by a session key that such a credential delegated to and that the caller's own policy allows.
- **An answer is for this request.** The caller mints the request id and keeps its own record under it. The signed record names that id, the hash of the caller's signed creation body (caller, recipient, reference, policy, lifetime, both ciphertexts) and the hashes of the content in clear, and the answer inside is sealed to a key made for this one request. An answer to one request does not verify for another, and nothing the service returns can rename or redirect a request.
- **An answer is in time.** It must be signed inside the request's lifetime and reach the caller by the caller's own deadline, by the caller's own clock. An approval held back is not an approval.
- **The service cannot read an answer to a caller's request.** The record holds it only padded and sealed to the caller's answer key. Padding is to blocks of 4096 bytes: answers shorter than that all look alike.
- **An answer fits the caller's schema.** The caller checks it against its own copy; anything outside is refused.
- **An answer is used once.** The caller library refuses a second consume.
- **The service cannot swap keys.** A caller pins the result of replaying the recipient's key statement chain, after comparing its fingerprint with the recipient outside the service; later keys are accepted only through statements that name the one before and are signed by a credential already in the set. A device, before it signs a change, replays the same chain from an anchor that only its own authenticator can open, and signs nothing it cannot account for.
- **A caller's content is shown only with that caller's question.** Who asks, the reference, the policy, the lifetime and the key the answer is sealed to are read from the sealed manifest and compared with what the service presents, and the manifest and the attachments name each other by values only the recipient can see. The service cannot put another question, another answer key or another policy in front of a caller's content.
- **No answer, no action.** When the service is unreachable or an answer does not verify, the caller library reports `hold` or `rejected` and never invents an approval.

## What it does not guarantee

- **Confidentiality from a malicious service.** The recipient decrypts and signs inside a web page that the service serves. A service that serves modified code can read the content or change the answer before it is signed. The release manifest and Subresource Integrity let anyone compare what a deployment serves with the source (`tools/verify_deployment.py`), but a browser checks only what the served page tells it to check. See "Honest scope of end-to-end in v1" in [docs/spec.md](docs/spec.md).
- **Secrecy of metadata.** The service sees who asks whom, when, the caller's reference, the policy, the sizes, and whether and when a request was opened and answered. Part of it is served to anyone who has a link or guesses a recipient id; see "What the service sees" in the specification.
- **That the caller named on the page really asked.** Recipients pin no caller keys. A lying service can show a request made entirely by itself under a registered caller's name, and read the answer to it; no real caller will accept that answer, but the person has answered a question nobody asked, and told the service what they would say.
- **Delivery.** The service chooses what to deliver and when: it can show an answered request again, withhold an answer until the caller's deadline has passed, or hide a recipient's newest key statement from a caller.
- **Single-device non-repudiation with synchronised passkeys.** A passkey that syncs through a platform account proves that account, not one device.
- **Protection of an unlocked device.** While a device session lives, anyone holding the device can read pending requests and answer those whose caller accepts sessions.
- **Availability.** There are no rate limits, and nothing is ever deleted from storage.

## What has not been done

- No independent security review of the protocol or of this implementation.
- The protocol is this project's own design on top of WebAuthn, libsodium sealed boxes and Ed25519. Treat it as such.
- Tested authenticators are listed under "Platform support" in the specification. iOS, macOS, hardware keys and Firefox are not tested yet.

## Operating it safely

- Serve it only over TLS, on an origin used for nothing else. Passkeys are bound to that host.
- Run `tools/verify_deployment.py <origin> --repo <checkout>` against your deployment after every update: it compares every served file and every page shell, byte for byte, with that checkout. If you sign the manifest with a key of your own, keep the secret key off the servers.
- With single sign-on enrolment, only the proxy must be able to reach the service with `X-Hitl-Proxy-Secret`: the identity header is trusted on the strength of that secret alone.
- The caller state directory holds the caller's secret key and, for each request, the plaintext that was sent and the key that opens its answer. Protect it like a credential store.
- Pin a recipient only with a fingerprint they read to you from their own device, over a channel that is not this service. There is no option to skip the comparison, and a caller that pinned without it has pinned whatever the service said.
- The SQLite file and the `blobs/` directory hold ciphertext, wrapped keys and the event log. Back them up; losing them loses every pending request.
