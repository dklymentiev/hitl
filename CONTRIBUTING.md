# Contributing

## Setting up

Python 3.11 or newer, and Node.js 20 or newer for the client vectors and the end-to-end test.

```
pip install -r requirements.txt
```

The server runs under gunicorn, so on Linux or macOS; the caller, the tools and the vector tests run anywhere. "Running" in the [README](README.md) has a one-machine setup.

## Checks before sending a change

```
python tests/hostile.py                  # a lying service against the caller; hostile clients against the service
python tests/vectors.py                  # shared vectors: server and caller
node tests/vectors.mjs                   # shared vectors: web client
python tools/release.py check            # the manifest matches the client files
python tools/prepublish.py --self-test   # the pre-publish scanner still catches every planted kind
python tools/prepublish.py               # nothing private in what would ship (scans the last commit)
```

The end-to-end test needs a running service and Chrome; its header in `tests/e2e.mjs` says how to run it. Run it for any change to the server, the caller or the client.

## Rules of the code

- **The service stays agnostic.** Nothing in the API, the wire format, the configuration or the documentation may refer to a particular caller, product or platform.
- **Three implementations of one protocol.** Canonical JSON, the exact fields of each signed object, the assertion check and the key statement chain live in `server/hitl/lib.py`, `caller/hitl.py` and `server/public/assets/app.js`. A change to one is a change to all three, with a vector in `tests/vectors/` (`jcs.json` by hand, `protocol.json` through `tests/make_vectors.py`).
- **A check is shown failing first.** A new check comes with a test that is red without it: switch the check off, see the test fail, switch it back on. Nothing a service returns is used for a security decision without such a check (R10 in the specification).
- **The caller decides, the service transports.** Every check that an answer is valid belongs in the caller library. The service repeats some checks for convenience; none may exist only there.
- **Never proceed on doubt.** An unreachable service is `hold`, a failed check is `rejected`. No fallback, no retry that the operator did not ask for.
- **No defaults that point at a real host.** Hostnames in defaults and examples are empty or under `example.com`.
- **Comments say why**, not what.

## Dependencies

`requirements.in` and `caller/mcp/requirements.in` hold the ranges; the `requirements.txt` beside each is the lock, with a hash for every file pip may download. Change a range in the `.in` file and regenerate the lock with the `pip-compile` command written at its top (pip-tools, on Python 3.12). Do not edit a lock by hand.

## Changing the web client

Every file under `server/public/assets/` is hashed into the release manifest. After any change there `python tools/release.py check` fails until you run `python tools/release.py build`; commit the rebuilt manifest with the change. The repository holds no signing key: do not add one, and do not commit a `manifest.sig`.

The vendored libsodium and pdf.js must stay byte-identical to the npm packages named in `tools/verify_deployment.py`.

## Changing the protocol

Anything that changes what is signed or how it is verified starts as a change to [docs/spec.md](docs/spec.md), in the same pull request as the code.

## Commits and pull requests

One change per commit, with a message that says what changed and why. Add a line to `CHANGELOG.md` under "Unreleased" for anything a user or operator would notice.

## Security problems

Not in a public issue: see [SECURITY.md](SECURITY.md).
