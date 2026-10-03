# Notes for coding agents

hitl lets a program obtain a person's signed answer to one specific request. Read [README.md](README.md) for what it does and [docs/spec.md](docs/spec.md) for the protocol before changing anything that is signed or verified.

## Layout

```
server/hitl/app.py     WSGI entry: routes, static files, HTML shells, CSP
server/hitl/api.py     JSON API handlers
server/hitl/lib.py     configuration, SQLite, canonical JSON, WebAuthn assertion check
server/hitl/http.py    request and response types
server/schema.sql      storage; applied on every connection, every statement idempotent
server/bin/admin.py    operator commands
server/public/assets/  web client (app.js, app.css), vendored libraries, release manifest
caller/hitl.py         caller library and CLI, one file, no dependency on the server code
caller/mcp/server.py   MCP bridge; shells out to caller/hitl.py
tools/                 release.py, verify_deployment.py, prepublish.py
tests/                 e2e.mjs, hostile.py, vectors.py, vectors.mjs, make_vectors.py, vectors/*.json
```

## Things that are easy to break

- `caller/hitl.py` and `server/hitl/` do not import each other, and both define `jcs`, `b64u` and the assertion check. They must stay in step, and so must the web client's copy in `app.js`: `tests/vectors.py` and `tests/vectors.mjs` hold all three to the same vectors for the encoding, the exact fields of every signed object, timestamps, padding, assertion checks and key statement chains. A new check in one implementation is a new vector for all (`tests/make_vectors.py`).
- The server package and the caller file are both called `hitl`. Do not put both directories on `sys.path`.
- Any byte changed under `server/public/assets/` makes `tools/release.py check` fail until the manifest is rebuilt: run `python tools/release.py build` and commit the manifest with the change. The repository holds no signing key and must not gain one.
- Strings such as `hitl.session`, `hitl.key-statement`, `hitl.inbox` and the field names of the response record are part of what devices sign. Renaming one breaks every deployed client and every stored proof.
- The caller must never act without a verified answer. Do not add a fallback to `hold` or `rejected`.
- The service must not learn anything about a caller's product. Do not add caller-specific fields, names or branches.

## Checks

```
python tests/hostile.py
python tests/vectors.py
node tests/vectors.mjs
python tools/release.py check
python tools/prepublish.py --self-test
python tools/prepublish.py
```

`tools/prepublish.py` scans the last commit, not the working directory. `tests/e2e.mjs` needs a running service and Chrome; run it when you can and say plainly when you could not.

## Style

Plain Python and plain JavaScript, no framework, no build step. Small functions, docstrings that state the rule a function enforces, comments that give the reason. Every command-line tool prints one JSON object and uses its exit code.
