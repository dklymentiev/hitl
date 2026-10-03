#!/usr/bin/env python3
"""Checks that a hitl deployment serves exactly the client code it should.

  python tools/verify_deployment.py <origin> --repo <checkout> [--npm]
  python tools/verify_deployment.py <origin> --pubkey <base64url> [--repo <checkout>] [--npm]

Something the deployment cannot change has to say what "should" means. That is a checkout of the
source (--repo), or the public key of an operator who signs what they deploy (--pubkey), or both.
With neither there is nothing to compare against and the tool refuses to run.

1. --pubkey: the release manifest served at /assets/release/ verifies against that key.
2. Every file served under /assets matches its manifest hash.
3. Every shell (decision, both enrolment pages, inbox) loads only manifest files, each with the manifest
   SRI value, has no script of its own and no inline handler, and comes with the content security policy.
   With --repo, each shell must equal, byte for byte, the one that checkout renders.
4. --repo: the manifest equals the hashes of the files in that checkout (the client is not built,
   so the checkout is the reproducible source).
5. --npm: the vendored libsodium and pdf.js files equal the published npm packages.
Prints one JSON object; exit 0 only if every check passed.
"""

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

# The caller is a file called hitl.py and the server a package called hitl (rendered below for
# --repo): load the caller by path, under a name of its own.
_spec = importlib.util.spec_from_file_location(
    "hitl_caller", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "caller", "hitl.py"))
_caller = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_caller)
jcs_bytes = _caller.jcs_bytes

VENDORED = [
    ("libsodium", "0.8.4", "vendor/libsodium.js", "package/dist/modules/libsodium.js"),
    ("libsodium-wrappers", "0.8.4", "vendor/libsodium-wrappers.js", "package/dist/modules/libsodium-wrappers.js"),
    ("pdfjs-dist", "6.3.289", "vendor/pdfjs/pdf.min.mjs", "package/build/pdf.min.mjs"),
    ("pdfjs-dist", "6.3.289", "vendor/pdfjs/pdf.worker.min.mjs", "package/build/pdf.worker.min.mjs"),
]


def fetch(url: str) -> tuple[bytes | None, dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hitl-verify/1"})
        with urllib.request.urlopen(req, timeout=20) as res:
            return res.read(), {k.lower(): v for k, v in res.headers.items()}
    except OSError:
        return None, {}


def get(url: str) -> bytes | None:
    return fetch(url)[0]


# What the pages' content security policy must say for the shell checks to mean anything: scripts
# only from the origin (so only the files checked here), nothing inline, no framing.
CSP_NEEDS = ("default-src 'self'", "script-src 'self' 'wasm-unsafe-eval'", "base-uri 'none'", "frame-ancestors 'none'")
SHELLS = {"/r/AAAAAAAAAAAAAAAA": ("decide", "AAAAAAAAAAAAAAAA"), "/enroll/AAAAAAAAAAAAAAAA": ("enrol", "AAAAAAAAAAAAAAAA"),
          "/enroll": ("enrol-sso", "sso"), "/inbox": ("inbox", "inbox")}


def shell_problem(html: str, headers: dict, files: dict) -> str:
    """Why a served shell could run something other than the signed files, or "" when it cannot."""
    low = html.lower()
    tags = re.findall(r"<(script|link)\b([^>]*)>", html, flags=re.I)
    if not tags:
        return "no script or stylesheet found"
    for kind, attrs in tags:
        m = re.search(r'(?:src|href)="(/assets/[^"?]+)(?:\?[^"]*)?"', attrs, flags=re.I)
        i = re.search(r'integrity="([^"]+)"', attrs, flags=re.I)
        path = m.group(1)[len("/assets/"):] if m else None
        if path not in files or (i.group(1) if i else "") != files[path].get("sri"):
            return f"a {kind.lower()} tag that is not a signed file with its integrity value: {attrs.strip()[:80]}"
    # The closing tag directly after the opening one: a script with a body would be inline code.
    if len(re.findall(r"<script\b[^>]*></script>", html, flags=re.I)) != low.count("<script"):
        return "a script tag with content of its own"
    if re.search(r"<[^>]+\son[a-z]+\s*=", html, flags=re.I) or "javascript:" in low:
        return "an inline event handler or javascript: URL"
    for attr, path_key in (("data-pdfjs", "vendor/pdfjs/pdf.min.mjs"), ("data-pdfjs-worker", "vendor/pdfjs/pdf.worker.min.mjs")):
        m = re.search(attr + r'="([^"?]*)(?:\?[^"]*)?"', html)
        if m and m.group(1) != "/assets/" + path_key:
            return f"{attr} points at {m.group(1)}"
    m = re.search(r'data-pdfjs-worker-sri="([^"]*)"', html)
    if m and m.group(1) != files.get("vendor/pdfjs/pdf.worker.min.mjs", {}).get("sri"):
        return "data-pdfjs-worker-sri is not the signed value"
    csp = headers.get("content-security-policy", "")
    missing = [d for d in CSP_NEEDS if d not in csp]
    if missing:
        return "content security policy lacks: " + "; ".join(missing)
    if "'unsafe-inline'" in csp.split("style-src")[0] or "'unsafe-eval'" in csp:
        return "content security policy allows inline or evaluated script"
    return ""


def unb64u(s: str) -> bytes:
    s = s.strip()
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return b""


def opt(args: list[str], name: str) -> str | None:
    if "--" + name not in args:
        return None
    i = args.index("--" + name)
    v = args[i + 1] if i + 1 < len(args) else ""
    del args[i:i + 2]
    return v


def main(argv: list[str]) -> int:
    args = argv[1:]
    origin = (args.pop(0) if args else "").rstrip("/")
    pubkey = opt(args, "pubkey")
    repo = opt(args, "repo")
    npm = "--npm" in args
    if not re.match(r"^https?://", origin) or (pubkey is None and repo is None):
        # A manifest checked only against the files served beside it proves nothing: both come from
        # the deployment under test.
        sys.stderr.write("usage: verify_deployment.py <origin> --repo DIR [--npm]\n"
                         "       verify_deployment.py <origin> --pubkey K [--repo DIR] [--npm]\n"
                         "give a checkout of the source, an operator's public key, or both\n")
        return 64

    checks = []

    def ok(name: str, passed: bool, detail: str = "") -> bool:
        checks.append({"check": name, "ok": passed, **({"detail": detail} if detail else {})})
        return passed

    raw = get(f"{origin}/assets/release/manifest.json")
    try:
        manifest = json.loads(raw) if raw is not None else None
    except ValueError:
        manifest = None
    if not ok("manifest served", isinstance(manifest, dict) and isinstance(manifest.get("files"), dict)):
        print(json.dumps({"status": "failed", "checks": checks}, indent=4))
        return 1
    if pubkey is not None:
        sig = unb64u((get(f"{origin}/assets/release/manifest.sig") or b"").decode(errors="replace"))
        pub = unb64u(pubkey)
        try:
            sig_ok = len(pub) == 32 and len(sig) == 64 and VerifyKey(pub).verify(jcs_bytes(manifest), sig) is not None
        except (BadSignatureError, ValueError, TypeError):
            sig_ok = False
        ok("manifest signature", sig_ok)

    files = manifest["files"]
    for path, h in files.items():
        body = get(f"{origin}/assets/{path}")
        ok(f"served {path}", body is not None and hashlib.sha256(body).hexdigest() == h.get("sha256"))

    # Every page that runs the client: decision, enrolment by link, enrolment by single sign-on, inbox.
    served = {}
    for shell in SHELLS:
        raw_html, headers = fetch(origin + shell)
        served[shell] = raw_html
        problem = shell_problem((raw_html or b"").decode(errors="replace"), headers, files)
        ok(f"shell {shell} loads only signed files", problem == "", problem)

    if repo is not None:
        # The shells are rendered by code, so the strongest check is to render them again from the
        # checkout and compare: anything added, in any spelling, is a difference.
        sys.path.insert(0, os.path.join(repo, "server"))
        try:
            from hitl import app as repo_app
        except Exception as e:  # the checkout is the verifier's own; if it does not load, say so
            repo_app = None
            ok("repo renders the shells", False, str(e))
        if repo_app is not None:
            for shell, (name, key) in SHELLS.items():
                ok(f"shell {shell} equals the checkout's", served[shell] == repo_app.page_app(name, key).body)

    if repo is not None:
        for path, h in files.items():
            try:
                with open(os.path.join(repo, "server", "public", "assets", path), "rb") as f:
                    body = f.read()
            except OSError:
                body = None
            ok(f"repo {path}", body is not None and hashlib.sha256(body).hexdigest() == h.get("sha256"))

    if npm:
        for pkg, ver, path, inner in VENDORED:
            tgz = get(f"https://registry.npmjs.org/{pkg}/-/{pkg}-{ver}.tgz")
            match = False
            if tgz is not None:
                try:
                    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
                        member = tar.extractfile(inner)
                        match = member is not None and hashlib.sha256(member.read()).hexdigest() == files.get(path, {}).get("sha256")
                except (tarfile.TarError, KeyError):
                    match = False
            ok(f"npm {pkg} {ver} {os.path.basename(path)}", match)

    passed = all(c["ok"] for c in checks)
    print(json.dumps({"status": "ok" if passed else "failed", "origin": origin, "checks": checks}, indent=4))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
