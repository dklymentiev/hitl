# hitl v1 specification

Status: this document is the protocol as decided, and the code implements it. What is described here as intended and has never been built is listed under "Not implemented yet".

## Goal

Build v1 of hitl: a service that lets a machine caller obtain a verifiable "this person approved THIS specific action" before doing something that should not happen without a human decision.

The caller sends an encrypted request and gets a short opaque link. It delivers the link to the person over whatever channel it already uses. The person opens the link, authenticates on their device, sees what the request declares, answers, and the answer comes back to the caller signed by the person's device. The caller verifies it and acts on it exactly once.

The service is agnostic: nothing in its API, wire format, config schema or docs refers to any particular caller, product or platform.

## Actors and trust boundaries

- **Caller**: a machine that needs one human decision on one action.
- **Recipient**: a specific person who controls the keys the payload is encrypted to and whose device signs the answer.
- **Service**: serves the decision page, transports ciphertext and signed answers. It does not decide.

Each boundary is enforced, not assumed:

- Caller to service: TLS, and every request creation is signed by the caller's key. No anonymous or guest callers.
- Service to recipient: TLS; the page is served from a domain the recipient recognises.
- Recipient to device: WebAuthn authenticator with user verification.
- Caller to recipient end to end: payload encrypted to the recipient's encryption key; answer signed by the recipient's signing credential. Both keys are pinned by the caller, never trusted from the service (see Recipient keys). See also the honesty note below.

## Honest scope of end-to-end in v1

In v1 the recipient decrypts and signs inside a web page served by the service itself. A malicious service could serve code that leaks plaintext or swaps the answer before signing. So "the service never sees plaintext" is a v1 goal, trusted but verifiable, not a guarantee by construction. Mitigations required in v1:

- Subresource Integrity on every client script, plus a manifest of asset hashes.
- No build step for the client: the files in the repository are the files served, so anyone can compare served assets against source (`tools/verify_deployment.py`).
- The enrolment page states this model plainly.

The trust anchor is the source: a verifier compares a deployment with a checkout it obtained elsewhere. The project ships no signing key. An operator may sign the manifest with a key of their own and publish the public half, which gives their users an anchor that does not need a checkout.

What these mitigations do not do: a browser checks only what the served page tells it to check, and a service can serve one thing to a verifier and another to a recipient. Verification catches a deployment that was modified for everyone; it cannot prove what one person was served.

A PWA or native client with a pinned code hash is the v2 path to the stronger guarantee.

Limits that hold even with genuine client code and that no mitigation here removes:

- **The caller chip is the service's statement.** Recipients pin no caller keys, and anyone can encrypt to a recipient. A lying service can show a request of its own making under any registered caller's name, sealed by itself with an answer key of its own, and so read what the recipient answers to it. No real caller will accept that answer, since it matches no request of theirs, but the recipient has answered a question that caller never asked. The chip means "this service says the request is from this caller", no more. What the service cannot do is mix its own with a caller's: a manifest and a payload name each other (see "Creation body"), so a caller's content is shown only with that caller's question, answer key and policy.
- **The service chooses what to deliver and when.** It can show a request again after it was answered, since a device keeps no memory of its answers; of two genuine answers it can pass on either; it can delay an answer until the caller's deadline.
- **A registered caller can address any recipient**, and with a full-page design can draw anything inside its own region, a false chip included. The service bar and the confirm bar are outside that region.
- **An unlocked session key has no forward secrecy.** Whoever obtains it while it lives can read every request sealed to that recipient.

This caveat covers the served client code only. It does not cover what the service says through its API. A service that serves the genuine client can still lie in its answers: about a recipient's keys, about a request's id, about times. Neither the client nor the caller library may take such a value on the service's word (R10); the sections below say, for each value, what it is checked against.

## Cryptographic model

WebAuthn authenticators sign; they do not decrypt application payloads. v1 therefore uses two key pairs per recipient, and one per request on the caller's side:

- **Encryption key pair** (X25519). Callers encrypt to its public half (libsodium sealed box). The private half is stored wrapped by a key derived through the WebAuthn PRF extension, so unwrapping needs a live authenticator gesture and the key is only ever unwrapped on the client.
- **Signing**: the WebAuthn credential itself. The answer signature is a WebAuthn assertion whose challenge is SHA-256 of the canonical response record (below).
- **Answer key pair** (X25519), made by the caller for each request. Its public half travels in the signed creation body; the recipient's page encrypts the answer to it. The private half never leaves the caller's state.

Consequences to state up front:

- PRF output is per credential. A recipient with a single lost credential loses the encryption key, and everything encrypted to it stays sealed. Recovery is designed into enrolment.
- Synchronised passkeys (platform keychains) make a signature non-repudiable to the recipient's passkey ecosystem, not to one device. Recipients who need single-device non-repudiation enrol a non-synchronised credential such as a hardware key.
- A decision takes two authenticator gestures: one to unwrap the encryption key when the page opens, one to sign the chosen answer. The signing challenge depends on the answer, so the two cannot be merged.

## Requirements

- **R1 Config-driven rendering.** The caller supplies a config manifest: content blocks (text, HTML, images, PDF, downloadable files) and an answer schema (buttons, form fields, an optional comment). See "Content and answers".
- **R2 Answers bounded by the schema.** The CALLER validates the answer against its own copy of the schema and refuses anything else. The service only validates in the page for convenience, because the manifest is encrypted and the service cannot read the schema. The signature covers the hash of the manifest, and the schema is part of the manifest.
- **R3 Confidentiality of content and answers.** Config manifest and payload are encrypted to the recipient's pinned encryption key, and the answer is encrypted to the caller's answer key; the service stores and moves ciphertext only (within the honest scope above). What the service does see is listed under "What the service sees".
- **R4 Authentication on device.** WebAuthn: passkey, platform biometrics, hardware key, with user verification required. The authenticator is the recipient's choice at enrolment, among those that support PRF.
- **R5 Signed answers.** WebAuthn assertion over the response record hash, verifiable by any caller against the credential keys it has pinned.
- **R6a Service-side idempotency.** Submitting the same signed response for the same request twice has one effect.
- **R6b Caller-side single use.** A caller consumes a signed answer exactly once and refuses a replay. The service ships a caller library that does this.
- **R7 Agnostic.** No coupling to any caller in API, format, schema or docs.
- **R8 Caller authentication and identity display.** Every caller is registered and signs every request. The decision page shows, before the content and styled apart from it: a "verified caller" chip (display name and domain), and a banner saying this is a decision with consequences, not a message.
- **R9 Recipient key pinning.** A caller trusts a recipient's encryption key and credential keys only if it pinned them at onboarding or received them in a key statement signed by an already pinned credential. The caller library refuses any other key change.
- **R10 Nothing on the service's word.** The client and the caller library treat every value the service returns as a claim to check: a key set against signed statements and the device's own anchor, an encryption public key against the private key it unwraps, and everything about a request (who asks, the reference, the policy, the deadline, the key the answer is sealed to) against the copy inside the sealed manifest. A value that cannot be checked is not used for a security decision.
- **R11 A device signs only what the page computed.** Every challenge a credential signs is the hash of an object the page built itself, never a value supplied by the service. Every signed object carries a `type`, and every verifier requires exactly the fields of that type, no more and no fewer, so a signature over one kind of object can never pass as another.

## Creation body

The caller mints the request id, so nothing about a request's identity or lifetime is the service's to choose. It signs (Ed25519) the canonical encoding of:

```
type                 "hitl.request"
version              2
request_id           uuid, minted by the caller
caller_id            the caller
recipient_id         the recipient
config_ct_hash       SHA-256 of the encrypted config manifest
payload_ct_hash      SHA-256 of the encrypted payload
answer_pubkey        the X25519 public key the answer must be sealed to, made for this request
ttl                  seconds
caller_ref           the caller's opaque reference (empty string if none)
created_at           RFC 3339, the caller's clock
policy               see "Assurance policy and device sessions"; always present
blobs                the ids of the blobs this request claims (empty list if none)
```

The request expires at `created_at + ttl`. The caller keeps the body; its SHA-256 is the **creation hash**.

`POST /api/v1/requests` carries the body and its signature in headers (`X-Hitl-Body`, the canonical encoding in base64url, at most 8 KiB, and `X-Hitl-Signature`), as blob upload does. Before it reads the HTTP body, which holds only the two ciphertexts (`{config_ct, payload_ct}`, base64url), the service checks the caller, the signature, `created_at` against its own clock (300 s either way) and that `request_id` was never used. An unsigned party therefore cannot make the service read or parse a large body, and a copied body cannot create a second request. The service returns the short link and nothing the caller has to trust.

The manifest carries the same request facts again, sealed (see "Content and answers"): `request_id`, `caller_id`, `caller_ref`, `policy`, `answer_pubkey`, `created_at`, `ttl`. The page acts on the sealed copy. It hashes the two ciphertexts it received, compares them and every one of those fields with the creation body the service presents, and refuses the request on any difference.

Those facts are all public, and a sealed box does not say who sealed it, so on their own they do not show that a manifest is the caller's. The manifest therefore also holds `payload_hash`, the SHA-256 of the payload in clear, and the payload holds `manifest_salt`, the manifest's salt; the page refuses a manifest and a payload that do not name each other. Both values are known only to someone who can open the ciphertexts (the payload hash becomes public in the signed record once the request is answered, which is why the payload names the manifest too). So a service that changes the answer key, the policy, the reference or the deadline of a caller's request is caught by the page, not later by the caller: it would need a manifest of its own, and the caller's payload will not go with it. A request made by the service from nothing is a different matter, see "Honest scope".

## Signed response record

The device signs SHA-256 of the canonical encoding of:

```
type                 "hitl.response"
version              2
request_id           from the creation body
creation_hash        SHA-256 of the canonical creation body
config_hash          SHA-256 of the config manifest in clear
payload_hash         SHA-256 of the payload in clear
answer_ct            the answer, conforming to the schema, padded and sealed to answer_pubkey
answer_self_ct       the same answer sealed to the recipient's own encryption key; present exactly when policy.review is true
signed_at            RFC 3339
```

Through `creation_hash` the signature covers the caller, the recipient, the reference, the policy, the deadline and both ciphertexts. `config_hash` and `payload_hash` are over plaintext, so a caller that kept what it sent can show later, to anyone, what was approved. Manifest and payload each begin with 32 random bytes of `salt`, so these hashes confirm nobody's guess about the content.

The answer is never in the record in clear, and neither is a hash of it: an answer is often one of two buttons, and a hash of that is as good as the answer. For the same reason its length must not show. Before sealing, the canonical answer is padded (ISO/IEC 7816-4, as libsodium's `sodium_pad`) to a multiple of 4096 bytes, so every answer under 4096 bytes looks the same; a longer one shows how many blocks it takes. The service, and anyone who fetches the request by its link, sees that it was answered and when.

A page that has built and signed a record keeps it, in the tab, until the service acknowledges it or refuses it, and sends the same bytes again when the recipient retries or reloads; while the service cannot be reached or fails, the record stays. The service treats the same record received twice as one answer (R6a) and refuses a different record for an answered request.

Encoding: every signed object is a JSON object serialised with the JSON Canonicalization Scheme (JCS, RFC 8785). Binary values (hashes, signatures, keys, ciphertext) are unpadded base64url strings. Timestamps are RFC 3339 in UTC with a `Z` suffix, whole seconds, not before 1970, in the one spelling an instant has (no second 60, no hour 24). ECDSA signatures are strict DER. An encoding one implementation accepts and another refuses would let a service show different parties different truths, so all three refuse the same things. Every implementation must produce byte-identical output for the same object; fixed vectors are in `tests/vectors/` (`jcs.json` for the encoding; `protocol.json` for the exact fields of each signed object, timestamps, padding, assertion checks and key statement chains), checked against the server, the caller library and the web client.

Signed objects and their types: `hitl.request` and `hitl.blob` (caller key), `hitl.response`, `hitl.key-statement` and `hitl.session` (device credential), `hitl.inbox` and session answers (session key).

## Verifying an answer

The caller library accepts a signed answer only if all of these hold:

1. The assertion signature verifies against a credential public key the caller has pinned for this recipient.
2. The assertion challenge equals SHA-256 of the canonical record.
3. `clientDataJSON.type` is `webauthn.get`, `clientDataJSON.origin` is the deployment's origin, and `crossOrigin` is not true.
4. The rpIdHash in authenticatorData equals SHA-256 of the deployment's rpId.
5. The authenticatorData flags have UP (user present) and UV (user verified) set.
6. The record has exactly the fields of `hitl.response` version 2. `request_id` is one the caller created; `creation_hash`, `config_hash` and `payload_hash` equal what the caller computed from its own body, manifest and payload.
7. `signed_at` is not earlier than `created_at - 300 s` and not later than `created_at + ttl`, and the caller's own clock, at the moment it first sees the answer, is not past `created_at + ttl + 300 s`. An answer that reaches the caller after its deadline is refused even if it was signed in time: an approval held back is not an approval.
8. `answer_self_ct` is present exactly when the caller's policy has `review`.
9. `answer_ct` opens with the answer key the caller made for this request; the padding is valid; the answer inside conforms to the caller's copy of the schema.
10. The record has not been consumed before (R6b).

Any failure is a rejection with a reason; the caller never falls back to acting without a valid answer.

The caller keys its local state by the request id it minted and creates each record exclusively, so nothing the service returns can name, overwrite or redirect a request. It cannot check that `answer_self_ct` holds the same answer as `answer_ct`; that copy exists for the recipient's own later reading and is evidence of nothing.

## Caller reference

A caller may attach `caller_ref` to a request: an opaque string of at most 200 printable ASCII characters, for example the id of the work item the decision belongs to. The service does not interpret it. It is part of the signed creation body, and so of the creation hash in the signed response record; the page shows it to the recipient from the sealed manifest. A service cannot move an answer from one reference to another. It is stored and shown to the service in clear: callers must not put secrets in it. Routing an answer by its reference (which task to update, whom to wake) is the caller's business.

## Assurance policy and device sessions

The caller decides per request how strictly the answer must be confirmed, with the `policy` in the signed creation body. It is always present and has one form, so nobody applies a default on the caller's behalf:

```
assurance         fresh | session
review            true | false; whether the recipient may later open the request and see their own answer
max_session_age   seconds, 60 to 86400; optional, and only with session
```

- `fresh`: the answer is a WebAuthn assertion over the record, a new device gesture for this answer.
- `session`: an unlocked device session may confirm the answer. When the recipient unlocks, the same device gesture that unwraps the encryption key signs a delegation `{version: 1, type: "hitl.session", recipient_id, session_pubkey, issued_at, expires_at}` (at most 24 h). The session key is a non-extractable Ed25519 key created in the recipient's browser and kept with the unlocked key until it expires or the recipient locks it. Answers are then signed by the session key over the JCS record, with no further gesture.

A session-confirmed answer carries `{delegation, delegation_assertion, signature}`. The caller verifies the delegation assertion against a pinned credential (all the usual assertion checks), that the answer was signed inside the session, that its own policy is `session`, that the session had started at most `max_session_age` before the answer, and the session key's signature over the record. The service applies the same checks and refuses a session answer to a `fresh` request.

Time. `signed_at` is written by the device, and a device clock can be set. The service therefore refuses any answer, session or fresh, whose `signed_at` is more than 300 s from its own clock, and a session answer when its own clock is past the delegation's `expires_at`. The page deletes an expired session key whenever it loads. This bounds answering; it does not bound reading: while a session key is still stored, someone holding the device with its clock set back can open requests whose links they have. A recipient who needs that closed locks the session or keeps sessions off.

The recipient chooses how long a session lasts on each device (off, 1 h, 12 h or 24 h) and can lock it at any time. A caller's `max_session_age` can only shorten what it accepts. While a session lives, requests also open without a gesture; this lets someone at the unlocked device read pending requests, and answer those whose caller accepts sessions.

## Queue and inbox

A recipient with a live device session can list their pending requests: the page signs `{type: "hitl.inbox", recipient_id, ts}` with the session key and sends it with the device-signed delegation to `POST /api/v1/inbox`. The service checks the delegation and the signature and returns metadata only (request id, short link, caller name and domain, expiry, policy), soonest expiry first; titles are decrypted in the page. Without a valid session proof the list is refused.

After an answer the page offers the next pending request, with the number left; a request can be skipped and comes back at the end. `/inbox` shows all pending requests; requests whose policy allows sessions and whose answer is a single button press can be selected and answered together with a choice they share, each answer signed by the session key and verifiable on its own. Requests that need a fresh confirmation or a form are answered one by one.

## Callers

A caller record: `caller_id`, `display_name`, `display_domain`, `verified_since`, `caller_pubkey` (Ed25519). v1 registers callers manually by the operator of the deployment. The service verifies the caller signature before minting a request.

## Recipient keys

- **Enrolment links.** An enrolment token is a bearer credential: single use, valid for the time the operator sets (at most 7 days) or 15 minutes on the single sign-on path, and stored by the service only as a hash, so a copy of the database yields no usable link.
- **Enrolment identity check.** Before any credential is registered, the deployment establishes who the recipient is. The check is pluggable: an identity provider the deployment already runs (for example an SSO that sits in front of the enrolment page and passes a verified user id), or an operator-run check where no such provider exists. The service records which method vouched for each enrolment. Self-service enrolment without either is v2.
- **PRF is required.** The client requests the PRF extension at credential creation and refuses the credential if the authenticator reports PRF as not enabled. The enrolment page tells the recipient which authenticators work (see Platform support).
- **Algorithms.** ES256 with a P-256 key, or RS256 with an RSA key of at least 2048 bits; the declared algorithm must match the key. Signature counters are not checked: synchronised passkeys do not maintain one.
- **Credentials.** The recipient registers at least one WebAuthn credential, two recommended (for example a platform authenticator plus a hardware key, or a phone plus a laptop). The client generates the encryption key pair and stores one PRF-wrapped copy of the private key per credential.
- **The device's anchor.** The blob a credential's PRF key wraps holds two things: the encryption private key, and the anchor, which is the sequence number and SHA-256 of the key statement that enrolled this credential. The blob is authenticated, so the service cannot change either. A device thereby remembers, without any storage of its own, a key set it once saw and signed or was signed into.
- **What a device checks before it signs a key statement.** It derives the encryption public key from the private key it unwrapped and refuses if the service names a different one. For a first enrolment the statement lists the new credential and nothing else, whatever the service returned. For a later one the confirming device fetches the statement chain from its anchor, checks that the anchor statement has the remembered hash and that every later statement is signed by a credential of the set before it, and refuses unless the result is exactly the key set the service presented. It then shows the recipient the devices that will be listed, by label, before asking for the gesture. A credential the service added on its own has no such chain and is never signed into a statement.
- **The fingerprint** is the first 128 bits of SHA-256 of the canonical encoding of the latest key statement, written as 32 hexadecimal digits in groups of four. Because each statement names the hash of the one before, it commits to the whole history. A page computes it from the statement the device has just signed, or, on any later visit, from the chain it has verified from its anchor; never from a reply of the service. Forging a different chain with the same fingerprint is a second-preimage search of 2^128.
- **Pinning at onboarding.** When a caller starts working with a recipient, it fetches the whole statement chain of the current epoch from sequence 1, checks every link (the first statement signed by the one credential it lists, each later one by a credential of the set before it), requires the service's current key set to equal the result, and confirms the fingerprint of that result with the recipient over a channel other than the service (the enrolment page shows it, and so does any page the recipient has unlocked). The caller library pins only when given that fingerprint (`pin --fingerprint`) or a confirmation at its prompt; it has no option to skip the comparison. A service that builds a chain of its own produces a different fingerprint. From then on the caller uses only pinned keys. The comparison is the whole of the trust: a caller configured to skip it has pinned whatever the service said.
- **Key statements.** Rotation and new credentials are published as a key statement: the new key set, a sequence number and a timestamp, signed by a credential that is already pinned. Callers fetch statements from the service, verify the signature against their pinned keys, and update their pins. A statement not signed by a pinned credential is refused, and so is every request to that recipient until the caller's operator has looked: the caller library reports the refusal instead of sending.
- **Key statement format.** A JSON object, signed as a WebAuthn assertion whose challenge is SHA-256 of its JCS encoding:

  ```
  type           "hitl.key-statement"
  version        2
  recipient_id   the recipient
  epoch          1 at first enrolment, +1 at every reset by the operator
  seq            1 for the first statement of an epoch, then +1 for every change
  prev           SHA-256 of the previous statement of this epoch (empty string when seq is 1)
  enc_pubkey     the current encryption public key
  credentials    the complete current credential list, sorted by id: {id, spki, alg, label}
  issued_at      RFC 3339
  ```

  A statement's assertion is verified like an answer's: type, challenge, origin, `crossOrigin`, rpId, UP and UV. Device labels are inside the statement, so the list a device shows before signing is the list it signs.

  The first statement is signed by the credential it enrols (it is trusted through the fingerprint check at pinning). Every later statement must be signed by a credential listed in the previous one. The service refuses a credential change without a valid statement and publishes the chain at `GET /api/v1/recipients/{id}/statements?after=<seq>`. A caller replays the chain from the sequence number it pinned, then requires the service's current key set to equal the result; a credential that drops out stays verifiable for answers signed before the statement that retired it. A credential enrolled by a version without the anchor cannot confirm a new device: the recipient is reset and enrols again.
- **Epochs.** A reset by the operator starts a new epoch with sequence 1 and no link to the old chain. A caller pins an epoch together with the keys and never follows a change of epoch on its own: after a reset it must pin again, with a fresh fingerprint comparison. A service that announces a new epoch gains nothing but a refusal.
- **Withholding.** A service can hide the newest statements from a caller, which keeps an older key set in use there. Today that only delays a new device. Once single credentials can be retired it would keep a retired one valid, so retirement must come with a way for callers to learn the head of the chain from the recipient.
- **Rotation.** Signing rotates by adding credentials, each change being a key statement. A credential that drops out of a later statement stays in the caller's pin history so past answers remain verifiable. Rotating the encryption key pair and retiring a single credential are not implemented yet.
- **Recovery.** With a surviving credential: confirm with it and enrol a new one, as a key statement. With none: the operator resets the recipient, who passes the identity check and enrols again; callers must re-pin out of band; requests encrypted to the lost key stay unreadable. A reset also cancels every enrolment link issued before it.

## Platform support

Tested 2026-09-25:

| Authenticator | PRF |
|---|---|
| Chrome 151 on Windows, platform passkey | works |
| Android phone over hybrid (QR), passkey in Google Password Manager | works |
| Android phone over hybrid (QR), passkey in Samsung Pass | not supported (`enabled=false` at creation) |

Not tested yet: iOS and macOS (iCloud Keychain), a FIDO2 hardware key, Firefox.

## Data flow

Caller creates a request:

1. Use the pinned encryption key of the recipient; if the service offers a newer key statement, verify it against pinned credentials first.
2. Build the config manifest and payload; encrypt both to the recipient.
3. Mint the request id and the answer key pair; put the request facts in the manifest; sign the creation body (see "Creation body").
4. `POST /api/v1/requests`. The service verifies the caller signature, stores the ciphertext, returns `{short_link}`.
5. The caller delivers the link itself. The service never sends it.

Recipient decides:

1. Open the link; authenticate; PRF unwraps the encryption key in the browser.
2. Fetch and decrypt the manifest and payload in the browser; check the creation body the service presents against the ciphertexts and against the request facts in the manifest.
3. Render the caller chip, the caller's reference and the banner, then the declared content.
4. Pick an answer; pad it and seal it to the answer key named in the manifest; build the response record; sign its hash with a WebAuthn assertion.
5. `POST /api/v1/requests/{id}/response` with record, signature, credential id.

Caller receives (polling `GET /api/v1/requests/{id}`) and verifies as in "Verifying an answer"; then acts and marks the answer consumed. The caller keeps the signed record together with the plaintext it sent, so the approval can be re-verified later; how it stores them is the caller's business.

## Degraded mode

If the service is unreachable, a caller must HOLD, not PROCEED: never invent an approval, never silently drop the action, no automatic retry without its operator's instruction (an outage may mean compromise). The caller library makes this the default, and callers should surface service health to their operators.

## Events

The service keeps an event log in its database. There is no API to read it yet.

```
hitl.request.created          request_id, caller_id, recipient_id, ciphertext hashes, ttl
hitl.request.opened           request_id, hash of the user agent that first opened it
hitl.request.signed           request_id, signature hash
hitl.recipient.enrol_started  recipient_id, which identity check vouched
hitl.recipient.keys           recipient_id, added credential, epoch, statement sequence, statement hash
hitl.recipient.reset          recipient_id, number of credentials retired
```

On the caller side the library reports each outcome as the status of its command: `pending`, `answered`, `expired`, `rejected` with a reason, or `hold`.

## Content and answers

The config manifest (version 3) is `{version: 3, salt, payload_hash, request, title, blocks, answers}`. `request` holds the facts the page must not take from the service: `{request_id, caller_id, caller_ref, policy, answer_pubkey, created_at, ttl}`. The payload is `{salt, manifest_salt, files: {ref: {mime, name, data}}}` with `data` in base64url. `salt` is 32 random bytes in each; `payload_hash` and `manifest_salt` tie the two together (see "Creation body"). Both are encrypted to the recipient. Earlier manifest versions carry no request facts and are refused.

Content blocks, rendered in order in the recipient's browser after decryption:

- `text`: plain text.
- `html`: an HTML document or fragment, inline (`html`) or from a file (`ref`), with its own CSS (`<style>` and `style` attributes), so designed content keeps its look. It renders in a sandboxed iframe that runs no scripts, submits no forms, opens no popups and cannot navigate the page; the frame grows to its content's height. Remote images, fonts and requests stay blocked by the page CSP, so images and fonts must be `data:` URIs or attachments. The verified caller chip, the caller's reference, the banner and the answer controls are drawn by the service and cannot be styled by the caller.
- `image`: PNG, JPEG, GIF or WebP from `ref`, with optional `alt` and `caption`. Other image types (SVG included) are offered as downloads.
- `pdf`: rendered page by page with pdf.js inside the page (works on phones, which do not show PDFs inline), plus a download link. pdf.js is a client file listed in the manifest; the worker is fetched with its SRI value.
- `video`, `audio`: the browser's own player (MP4, WebM, Ogg, QuickTime; MP3, AAC, WAV, Ogg, WebM), plus a download link. Other media types are offered as downloads.
- `file`: a download, served as application/octet-stream so the browser never renders it in the service's origin.

Large attachments (above about 2 MB, and all video and audio) travel as blobs. The caller encrypts the file in 64 KiB chunks with libsodium secretstream under a fresh random key and uploads the ciphertext with `PUT /api/v1/blobs`, signing a header `{type: "hitl.blob", version: 2, caller_id, sha256, size, created_at}` (sha256 of the ciphertext). The payload entry carries the blob id, ciphertext hash and size, the key and the stream header, so only the recipient can decrypt it, and the ciphertext hash is covered by the payload hash in the signed record. The creation body lists the blob ids; a blob becomes downloadable (`GET /api/v1/blobs/{id}`) only once a signed request claims it, and only by one request. The page refuses a blob whose ciphertext hash does not match the payload. Deployment limit `HITL_MAX_BLOB_BYTES` (default 250 MB).

Page design. By default the page is plain black and white. A caller can set `"layout": "full"` in the manifest to make its HTML block the whole page (a dashboard, a gallery, a designed document), between a slim service bar at the top (verified caller, banner) and the service's confirm bar at the bottom. The design answers through ordinary controls, still without scripts:

- `data-hitl-field="<field>"` on inputs (radio, checkbox, select, text, number, date, textarea) binds them to schema fields; a radio group styled as a picture grid becomes an image selector.
- `data-hitl-choice="<value>"` on any element (or on a radio input) makes it an answer option; the selected element gets the class `hitl-selected` for styling.
- `src="hitl:<ref>"` and `poster="hitl:<ref>"` show encrypted attachments (images, video, audio) inside the design.

The confirm bar shows exactly what will be signed (the chosen option and every field value, with option labels) and stays disabled until the answer fits the schema. Fields and choices the design does not provide are offered by the service below the design. Designs cannot style the service bar or the confirm bar.

Office documents are best converted to PDF by the caller before sending; in-browser rendering of DOCX, XLSX and PPTX is future work.

Answer schema (`answers`), at least one of `choices` and `fields`:

- `choices`: buttons `{value, label}` with unique values. Without choices the page shows a single Submit button and the answer has no `choice`.
- `fields`: form fields `{name, label, type, required?}`; types `text` and `textarea` (`max_length`), `number` (whole numbers of magnitude at most 2^53 - 1, `min`, `max`), `date` (YYYY-MM-DD), `select` and `multiselect` (`options: [{value, label}]`), `checkbox` (boolean; a required checkbox must be ticked).
- `comment`: optional free text `{max_length}`.

Every number in a schema is a whole number of magnitude at most 2^53 - 1; the caller library refuses a schema with a fraction or a larger number when the request is created, since no answer to it could verify.

The answer is `{choice?, fields?, comment?}`, in one form: `choice` when the schema has choices; `fields`, as an object, whenever the schema has fields and the choice is not `cancel`, even when none was filled in; `comment` only when one was written. A `cancel` choice carries no fields. Option values are strings, a text answer is at most `max_length` characters (2000 when the field gives none), and a comment needs a `max_length` of 1 to 2000. The caller refuses any answer that does not fit its own schema exactly: an unknown key or field, a missing required field, a value of the wrong type, out of range, or not among the options.

Size: the deployment sets `HITL_MAX_PAYLOAD_BYTES` (default 15 MB of encrypted inline payload) and `HITL_MAX_BLOB_BYTES` for blobs.

## What the service sees

The service is not trusted with content, but it is not blind. It stores and can read:

- who asks whom and when, each request's `caller_ref`, policy, sizes, and whether and when it was opened and answered;
- recipients' ids and display names, device labels, credential public keys, and which identity check vouched for each enrolment;
- the event log.

It cannot read the manifest, the payload, blob contents or the answer.

Some of this is served to anyone, without authentication, because a caller or a page needs it before any key is unlocked:

| Route | What anyone can fetch |
|---|---|
| `GET /api/v1/recipients/{id}/keys`, `/statements` | display name, credential ids and public keys, statement times |
| `GET /api/v1/recipients/{id}/unlock` | the same, with PRF salts and wrapped keys (of no use without the authenticator) |
| `GET /api/v1/requests/{id or short link}` | the creation body (caller, recipient, reference, policy, deadline), ciphertext, and the signed record once answered, in which the answer is sealed |
| `GET /api/v1/blobs/{id}` | blob ciphertext |
| `GET /api/v1/enroll/{token}` | recipient and wrapped keys; the token is the credential |

Recipient ids are guessable, so the first two rows are in effect public. A link, once shared, shows its holder that a request exists, between whom, and whether it was answered. Callers must not put anything secret in `caller_ref` or in ids.

## Limits and response headers

- Bodies are bounded per route before they are parsed: 64 KiB for the inbox and for enrolment, 256 KiB for an answer. Request creation and blob upload read their body only after the caller's signature in the headers has been verified.
- Every response carries `X-Content-Type-Options: nosniff`. Pages carry `frame-ancestors 'none'` in their content security policy: the decision page is never shown inside another site.
- Blobs are served as `application/octet-stream` with `Content-Security-Policy: default-src 'none'; sandbox`, so stored bytes can never run in the service's origin.
- The page that shows an answered request for review verifies the record's signature against the recipient's keys before it shows anything.

## Not in v1

Multi-recipient (any one of N signs); answers that the caller marks as public, readable with their proof by anyone who has the link; in-browser rendering of office documents; file upload in answers; auto-approval, delegation or "yes if no reply"; organisations, billing, quotas; a PWA or native client; enrolment without an identity check.

## Open questions

1. TTL: default 24 h, min 15 min, max 7 days unless the deployment raises it (`HITL_MAX_TTL`), set per request.
2. Retention: one year at the service, early deletion on the recipient's request; the caller keeps its own signed copy. Today the service deletes nothing.
3. Rate limits per caller and per recipient. Today there are none.
4. Webhook plus polling fallback for delivering the signed answer?

## Not implemented yet

Described here as intended, never built:

- Reading the event log: no API, stream or webhook. A caller learns of an answer by polling.
- Withdrawing or replacing a pending request.
- Retiring a single credential, and rotating the encryption key pair. Recovery today is adding a device, or a reset by the operator. When retirement is built, an answer by a retired credential must not be accepted on its own `signed_at` alone.
- An acknowledgement step when a recipient enrols only one credential.
- Retention: expired requests, answered requests and blobs are never deleted.
- Rate limits.
- A signed history of their own answers for recipients.

## Changes since the first draft

- Added R9 and the key pinning / key statement model; the pubkey endpoint is no longer trusted on its own.
- Named the canonical encoding (JCS, RFC 8785) and binary and time formats.
- Added "Verifying an answer" with the UV, origin and rpId checks.
- PRF is required at enrolment; added Platform support with the 2026-09-25 test results.
- Enrolment identity check is pluggable (existing identity provider or operator).
- Stated the two-gesture consequence of the crypto model.
- Added `caller_ref`, an opaque caller reference echoed in the signed record (2026-09-26).
- Encryption key type fixed to X25519 (libsodium sealed box) for v1.
- Key statement format and chain replay specified (2026-09-28).
- Content blocks (text, HTML, image, PDF, file) and form answers replace the v1 rendering list (2026-09-28).
- Video and audio blocks; large attachments as chunk-encrypted blobs (2026-09-28).
- HTML blocks keep their CSS; frames auto-size (2026-09-28).
- Caller assurance policy (fresh or session with a maximum age) and device sessions (2026-09-28).
- Queue and inbox for a live session (2026-09-28).
- Black and white default page; caller-designed full pages with bound controls and hitl: media (2026-09-28).
- Security review of 2026-10-03: nothing on the service's word (R10); creation body and response record version 2 with the answer sealed to the caller; the device's anchor and chain check; pinning from sequence 1; caller-side bounds on ids and times; own-clock checks at the service; body limits and response headers; "What the service sees".
- Second review of 2026-10-03: the caller mints the request id and the service mints nothing (no service nonce or times in the record); request facts sealed inside the manifest and checked by the page; salted plaintext hashes; padded answer; `type` on every signed object and exact field sets (R11); key statement version 2 with epoch, `prev` and labels; fingerprint defined; enrolment tokens hashed; limits of the caller chip and of delivery stated.
- Third review of 2026-10-03, of the code: manifest and payload name each other (`payload_hash`, `manifest_salt`), since public facts in an unauthenticated sealed box did not tie a caller's content to its answer key; one form of an answer on every path of the page; one spelling of a timestamp and strict DER in all three implementations; what the padding does and does not hide; the unsent record as built.
- 2026-10-03: the code brought up to this document (protocol version 2 in the service, the caller library and the web client, one cut). The policy is always present in one canonical form; blob headers carry a `type`.
