#!/usr/bin/env python3
"""Release manifest for the web client: the SHA-256 and SRI value of every file the decision and
enrolment pages load.

  python tools/release.py build                   rewrite server/public/assets/release/manifest.json from the files
  python tools/release.py check [--pubkey K]      the manifest matches the files; with --pubkey, its signature verifies
  python tools/release.py keygen                  a key pair, for whoever wants to sign what they deploy
  python tools/release.py sign <secret-key-file>  build, then write manifest.sig; prints the public key to publish

The repository ships the manifest unsigned and holds no key. What a deployment serves is checked
against a checkout of the source (tools/verify_deployment.py --repo), and the source is the trust
anchor. Signing is for an operator who wants a second anchor of their own: they keep the secret key
off the server, publish the public key somewhere the deployment cannot change, and their users
pass it as --pubkey. The signature (Ed25519) covers the JCS encoding of the manifest.
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys

import nacl.bindings as sodium
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
# The caller is a file called hitl.py and the server a package called hitl: load the caller by path.
_spec = importlib.util.spec_from_file_location("hitl_caller", os.path.join(ROOT, "caller", "hitl.py"))
_caller = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_caller)
b64u, jcs_bytes = _caller.b64u, _caller.jcs_bytes

ASSETS = os.path.join(ROOT, "server", "public", "assets")
OUT = os.path.join(ASSETS, "release")
MANIFEST = os.path.join(OUT, "manifest.json")
SIGNATURE = os.path.join(OUT, "manifest.sig")
# Client files, in load order. Anything the shells load must be listed here.
FILES = ["app.css", "vendor/libsodium.js", "vendor/libsodium-wrappers.js", "app.js",
         "vendor/pdfjs/pdf.min.mjs", "vendor/pdfjs/pdf.worker.min.mjs"]


def unb64u(s: str) -> bytes:
    s = s.strip()
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return b""


def read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def build() -> dict:
    files = {}
    for f in FILES:
        try:
            with open(os.path.join(ASSETS, f), "rb") as fh:
                body = fh.read()
        except OSError:
            sys.stderr.write(f"missing asset {f}\n")
            sys.exit(65)
        files[f] = {"sha256": hashlib.sha256(body).hexdigest(),
                    "sri": "sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode()}
    return {"version": 1, "files": files}


def write_manifest(m: dict) -> None:
    os.makedirs(OUT, 0o755, exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(m, indent=4) + "\n")


def fail(msg: str):
    print(json.dumps({"status": "failed", "reason": msg}))
    sys.exit(1)


def main(argv: list[str]) -> None:
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "build":
        m = build()
        stale = os.path.isfile(SIGNATURE) and jcs_bytes(m) != jcs_bytes(json.loads(read(MANIFEST) or "{}"))
        write_manifest(m)
        if stale:
            # A signature over the old manifest would only mislead whoever finds it next to the new one.
            os.unlink(SIGNATURE)
        print(json.dumps({"status": "built", "files": len(m["files"]), "signature_removed": stale}))
    elif cmd == "keygen":
        pk, sk = sodium.crypto_sign_keypair()
        print(json.dumps({"public_key": b64u(pk), "secret_key": b64u(sk)}))
    elif cmd == "sign":
        secret = unb64u(read(argv[2]) if len(argv) > 2 else "")
        if len(secret) != 64:
            fail("usage: sign <file holding the base64url secret key>")
        m = build()
        write_manifest(m)
        with open(SIGNATURE, "w", encoding="utf-8", newline="\n") as f:
            f.write(b64u(sodium.crypto_sign(jcs_bytes(m), secret)[:64]) + "\n")
        print(json.dumps({"status": "signed", "files": len(m["files"]), "public_key": b64u(secret[32:])}))
    elif cmd == "check":
        pubkey = argv[argv.index("--pubkey") + 1] if "--pubkey" in argv and argv.index("--pubkey") + 1 < len(argv) else None
        try:
            m = json.loads(read(MANIFEST))
        except ValueError:
            m = None
        if not isinstance(m, dict):
            fail("manifest missing or unreadable; run build")
        if jcs_bytes(m) != jcs_bytes(build()):
            fail("manifest is stale: a client file changed since it was built; run build")
        signed = os.path.isfile(SIGNATURE)
        if pubkey is None:
            # Without a key nothing is claimed about the signature, and the output says so.
            print(json.dumps({"status": "ok", "files": len(m["files"]),
                              "signature": "present, not checked: pass --pubkey" if signed else "none"}))
            return
        sig, pub = unb64u(read(SIGNATURE)), unb64u(pubkey)
        if len(sig) != 64 or len(pub) != 32:
            fail("--pubkey given but manifest.sig or the key is missing or malformed")
        try:
            VerifyKey(pub).verify(jcs_bytes(m), sig)
        except BadSignatureError:
            fail("signature does not verify against that key")
        print(json.dumps({"status": "ok", "files": len(m["files"]), "signature": "verified"}))
    else:
        sys.stderr.write("usage: release.py build | check [--pubkey K] | keygen | sign <secret-key-file>\n")
        sys.exit(64)


if __name__ == "__main__":
    main(sys.argv)
