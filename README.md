# hitl

A human-in-the-loop service. A program that needs a person to take part (approve an action, choose between options, review a document, fill in a short form) sends a request; the person gets a short link, reviews what the request shows on their own device, and answers. The program gets back a structured answer, signed by the person's device.

hitl knows nothing about the programs that call it. Any number of independent callers can use one deployment.

hitl does not deliver anything. The caller gets a link and sends it to the person over whatever channel it already uses.

## How it works

1. The caller writes a request: content blocks (text, HTML, images, PDF, video, audio, files) and the allowed answers (buttons, form fields, a comment). It can also design the whole page.
2. The caller mints the request id and a key pair for the answer, encrypts the request to the recipient's key and submits it with its own signature. The service stores ciphertext and returns a short link, which the caller delivers.
3. The recipient opens the link and unlocks with a passkey; the request is decrypted in the browser, and the page checks what the service presented against what the caller sealed.
4. The recipient answers. The answer is encrypted to the caller's answer key and the record around it is signed by the device (or by a device session, when the caller allows it). The caller verifies it against keys it pinned itself, by its own record of the request and its own clock.

## Properties

- **Bounded answers.** Only answers inside the declared schema count; the caller checks every field, since the service never sees plaintext.
- **Confidential content and answers.** The service stores and relays ciphertext only: the request, large files, and the answer, which is padded and sealed to a key the caller made for that one request.
- **Signed answers.** Each answer is bound, through the hash of the caller's signed creation body, to the request id, the caller, the recipient, the reference, the policy, the lifetime and both ciphertexts, and through plaintext hashes to the content the caller sent. It is verifiable by the caller against pinned device keys.
- **Nothing on the service's word.** The caller mints the request id and the times; the page takes the request facts from the sealed manifest; an answer that reaches the caller after its own deadline is not an approval. What the service says about keys, ids and times is checked, never used as given.
- **Keys the service cannot swap.** A recipient's keys form a signed chain of key statements. Callers pin by replaying the chain and comparing its fingerprint with the recipient outside the service; a device checks the same chain, from an anchor only its authenticator can open, before it signs any change.
- **Caller-chosen strictness.** Per request: a fresh device confirmation, or an unlocked device session no older than the caller allows.
- **Verifiable client.** The client is not built: the files in the repository are the files served. Every one is listed with its hash in a release manifest and loaded with Subresource Integrity, and anyone can compare a deployment with a checkout of the source.
- **Agnostic.** No coupling to any particular caller, product or platform.

## Status

Early release. The protocol and this implementation have not had an independent security review; read "Honest scope of end-to-end in v1" in [docs/spec.md](docs/spec.md) before relying on it. What it guarantees and what it does not is in [SECURITY.md](SECURITY.md); what the specification describes but the code does not do yet is under "Not implemented yet" in the specification. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Layout

```
server/hitl/       WSGI application: routing, API handlers, HTML shells, shared helpers
server/public/     web client, vendored libsodium and pdf.js
server/bin/        admin.py: callers, enrolment links, recipient reset
server/schema.sql  SQLite schema
caller/hitl.py     caller library and CLI
caller/mcp/        MCP bridge for agents (ask_human)
tools/             release manifest, deployment verification, pre-publish check
deploy/            Dockerfile, gunicorn settings, example compose file
tests/e2e.mjs      end-to-end test with a virtual authenticator, including a service that lies to the page
tests/hostile.py   a lying service against the caller library, hostile clients against the service
tests/vectors*     shared test vectors (canonical JSON, signed objects, assertions, key chains) and their runners
docs/spec.md       specification
```

## Running

The server is a plain WSGI application for Python 3.11+ with PyNaCl and cryptography, run by gunicorn behind a TLS-terminating proxy. `requirements.txt` is a lock file: exact versions, each with its hashes, which pip checks on install; the ranges it was made from are in `requirements.in`. It serves the web client itself. Set `HITL_ORIGIN` to the exact origin users open; passkeys are bound to its host. `HITL_DB` is the SQLite file (default `/var/hitl-data/hitl.sqlite`); blobs go to `blobs/` next to it. gunicorn listens on `HITL_BIND` (default `127.0.0.1`; the Dockerfile sets `0.0.0.0`) and `PORT` (default 8080). See `deploy/Dockerfile` and `deploy/docker-compose.example.yml`.

To try it on one machine (Linux or macOS; gunicorn does not run on Windows):

```
pip install -r requirements.txt
mkdir data
export HITL_ORIGIN=http://localhost:8080 HITL_DB=$PWD/data/hitl.sqlite
(cd server && gunicorn -c ../deploy/gunicorn.conf.py hitl.app:application) &

export HITL_URL=http://localhost:8080 HITL_STATE=$PWD/data/caller
python caller/hitl.py keygen my-caller                       # prints the caller's public key
python server/bin/admin.py add-caller my-caller "My caller" example.com <pubkey>
python server/bin/admin.py enrol-link alice "Alice"          # open the printed link in a browser, create a passkey
python caller/hitl.py pin alice                              # confirm the fingerprint against the one Alice's device shows
python caller/hitl.py ask alice --title "Send the report?" --text "To the whole team."
python caller/hitl.py consume <request_id>                   # after answering through the link
```

Browsers allow passkeys on `http://localhost`; anywhere else the origin must be HTTPS.

Optional settings: `HITL_MAX_PAYLOAD_BYTES` (inline payload, default 15 MB), `HITL_MAX_BLOB_BYTES` (blobs, default 250 MB), `HITL_MAX_TTL` (longest request life in seconds, default 7 days), `HITL_WORKERS` and `HITL_THREADS` (gunicorn, default 2 and 8), and for SSO enrolment `HITL_SSO_ID_HEADER`, `HITL_SSO_PROXY_SECRET`, `HITL_SSO_NAME`, `HITL_SSO_ALLOW`.

Operator tasks:

```
python server/bin/admin.py add-caller <caller_id> <display_name> <display_domain> <pubkey>
python server/bin/admin.py set-caller-theme <caller_id> colors.json [logo.png]
python server/bin/admin.py enrol-link <recipient_id> <display_name>
python server/bin/admin.py reset-recipient <recipient_id>      # recovery when no device survives
python server/bin/admin.py list
```

An operator may set a separate outer-shell theme for each registered caller. `colors.json` accepts six-digit hex values for `background`, `surface`, `ink`, `muted`, `border`, `accent`, and `on_accent`; every key is optional. The optional logo must be PNG, JPEG or WebP, at most 64 KiB. For example:

```json
{"background":"#fafaf8","surface":"#ffffff","ink":"#101114","muted":"#76767a","border":"#e7e6e1","accent":"#101114","on_accent":"#ffffff"}
```

The service validates color contrast and applies the theme to its header, page background, controls and confirmation bar. The logo appears beside the registered caller's name. This theme is operator-controlled metadata; a request cannot style the outer shell. Caller HTML remains inside its sandboxed frame. Use an empty JSON object without a logo file to restore the defaults.

## Caller CLI

Needs only PyNaCl and cryptography. Each command prints one JSON object. Exit codes: 0 answered or ok, 10 pending, 3 rejected or expired, 75 hold.

```
HITL_URL=https://decide.example.com python caller/hitl.py keygen my-caller     # give pubkey to the operator
python caller/hitl.py pin alice --fingerprint "1a2b 3c4d ..."                   # the fingerprint alice read to you from her device
python caller/hitl.py refresh alice                                             # follow signed key statements
python caller/hitl.py ask alice --title "Send the report?" --text "..." --choices "A:Send,B:Edit,cancel:Cancel" --comment 500
python caller/hitl.py ask alice --manifest request.json --attach photo=label.png --attach spec=spec.pdf \
    --ref task:42 --assurance session --max-session-age 12h --review
python caller/hitl.py check <request_id>                                        # pending, or the verified answer
python caller/hitl.py consume <request_id>                                      # verified answer, exactly once
```

`pin` replays the recipient's key statement chain from its first statement and pins only if the fingerprint of the result is the one the recipient's device shows (on the enrolment page, and on any page they have unlocked). Give that value with `--fingerprint`, or, at a terminal, leave it out and confirm at the prompt. There is no option that skips the comparison: it is the whole of the trust in the keys. `--replace` pins again from scratch after a recipient was reset; a reset starts a new epoch, which a caller never follows on its own.

`request.json` holds `title`, `blocks`, `answers` and optionally `"layout": "full"`; see "Content and answers" in the spec. The caller delivers the link to the recipient itself. On `hold` it must not proceed. A `hold` from `ask` that carries a `request_id` means the request may exist at the service although no link came back: `check` that id rather than asking again.

`--review` puts `"review": true` in the signed request policy: the page then seals a second copy of the answer to the recipient's own key, and after answering the recipient can open the link again, unlock it, and see the request with their answer, read-only. Without it an answered link only says it was answered. The flag is visible to the service (the policy is not encrypted) but signed by the caller and repeated inside the sealed manifest, so the service cannot turn it on.

Free-text fields use typed input. The decision page does not request microphone access or offer browser speech recognition.
The page always offers Cancel beside Confirm. Cancel signs an explicit `cancel` answer and leaves form fields out, even when the caller did not list cancel in its choices. The registered sender name is visible above the content, with its operator-configured logo when present. Caller ID, registered domain, reference, expiry and confirmation policy are available from the small information icon in the header (labelled “Technical information” for assistive technology). Answered pages offer Close; browsers that forbid script-closing a manually opened tab show a reminder to close it. The service's outer-shell theme does not alter caller-designed content.

## MCP bridge

`caller/mcp/` exposes `ask_human`, `list_recipients` and `check_human` to agents. The agent passes a reference such as `task:42` and delivers the link; the bridge verifies and consumes the answer and hands it, with its proof, to the deployment through a delivery file. See [caller/mcp/README.md](caller/mcp/README.md).

## Verifying a deployment

The decision page decrypts and signs in the browser, so the code it runs matters. The client has no build step: every file it loads is in this repository as served, listed with its SHA-256 and SRI value in `server/public/assets/release/manifest.json`, and the page shells load only those files, each with its `integrity` attribute.

```
python tools/verify_deployment.py https://decide.example.com --repo . --npm
```

compares a deployment with this checkout: every served file against the manifest and against the checkout, each page shell byte for byte against what the checkout renders, the content security policy, and the vendored libsodium and pdf.js against the published npm packages. The checkout is the trust anchor, so take it from somewhere the deployment does not control. What this cannot show is in "Honest scope of end-to-end in v1" in the specification.

After changing any client file run `python tools/release.py build`; `python tools/release.py check` fails while the manifest is stale.

The repository holds no signing key. An operator who wants their users to check a deployment without a checkout can sign the manifest with a key of their own: `python tools/release.py keygen`, keep the secret off the server, `python tools/release.py sign <secret-key-file>`, and publish the public key where the deployment cannot change it. Their users then run `verify_deployment.py <origin> --pubkey <key>`.

## Tests

`tests/e2e.mjs` drives headless Chrome with a virtual authenticator: enrolment, pinning, requests of every block type, forms, designed pages, blobs, sessions and policy, queue and inbox, review, key statements, and a service that lies to the page about a request and about the recipient's keys (the test rewrites API replies on their way to the browser). Usage is in the file header; `DB_PY`, `BLOB_TAMPER` and `INJECT` point the tampering checks at the service's storage.

For a local run without TLS, start the server on `http://localhost:<port>` with `HITL_ORIGIN` set to the same URL (browsers allow passkeys on localhost).

Checks that need no running service:

```
python tests/hostile.py            # a lying service against the caller library; hostile clients against the service
python tests/vectors.py            # shared vectors against the server and the caller
node tests/vectors.mjs             # the same vectors against the web client
python tools/release.py check      # the manifest matches the client files
python tools/prepublish.py --self-test
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
