#!/usr/bin/env python3
"""Pre-publish check: nothing private in what a release would ship.

  python tools/prepublish.py [<tree-ish>]   scan what `git archive` of it carries (default HEAD)
  python tools/prepublish.py --self-test    plant one violation of every kind; fail if any is missed

Scans the archive itself, so export-ignore rules are applied by git and uncommitted work is not
covered: commit first. Every file that decodes as UTF-8 is read, whatever its type. Each text is
searched twice: as written, and after undoing \\uXXXX, URL, HTML-entity and base64 encoding.

Kinds: private hosts, addresses, home folders, e-mail addresses, tracker references, secrets,
unfilled placeholders, and private names. The private names are the maintainer's own (people,
organisations, hosts, products): one per line in .prepublish-private at the repository root, which
is never committed, because naming them here would publish them. They match ignoring case, in
binary files too.

Vendored third-party files (server/public/assets/vendor/) are searched for private names and
secrets only: their bytes are checked against the published packages by verify_deployment.py --npm.
This file is searched for private names only: it holds the planted samples of the self-test.

Prints one JSON object; exit 0 only when the count of findings is zero.
"""

import base64
import html
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.parse

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRIVATE_FILE = os.path.join(ROOT, ".prepublish-private")
VENDOR = "server/public/assets/vendor/"
SELF = "tools/prepublish.py"

# Addresses that mean nothing outside documentation, a container or the local machine.
OK_IP = re.compile(r"^(0\.0\.0\.0|127\.\d+\.\d+\.\d+|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+|255\.255\.255\.\d+)$")
OK_MAIL = re.compile(r"@(example\.(com|org|net)|[a-z0-9.-]+\.example|users\.noreply\.github\.com)$", re.I)

GENERIC = {
    "private_host": re.compile(r"\b[a-z0-9][a-z0-9.-]*\.(?:internal|lan|vpn|corp|intranet|home\.arpa)\b", re.I),
    "ip_address": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "home_folder": re.compile(r"(?:[A-Za-z]:\\+Users\\+[^\\\s<>\"']+|/home/[a-z_][a-z0-9_-]+|/Users/[A-Za-z][\w.-]+)"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"),
    "tracker_ref": re.compile(r"(?:\b(?:issue|task|ticket|bug|backlog item|MR|PR|ADR)s?[ -]?[#!]?\d+\b|(?<![\w&#:/])[#!]\d{4,6}\b)", re.I),
    "placeholder": re.compile(r"(?:TODO-REPLACE|\{\{\s*\w+\s*\}\}|<[A-Z]+_NAME>)"),
}
SECRET = {
    "secret": re.compile(
        r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|\bAKIA[0-9A-Z]{16}\b"
        r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"
        r"|\bglpat-[A-Za-z0-9_-]{20,}\b"
        r"|\bxox[abprs]-[A-Za-z0-9-]{10,}\b"
        r"|\bsk-[A-Za-z0-9_-]{32,}\b"
        r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        r"|(?:password|passwd|secret|api[_-]?key|token)[\"']?\s*[:=]\s*[\"'][^\"'\s]{16,}[\"'])", re.I),
}


def private_names() -> list[str]:
    try:
        with open(PRIVATE_FILE, encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")]
    except OSError:
        return []


def decodings(text: str) -> str:
    """The text with each encoding that hides a word undone, joined into one corpus."""
    out = []
    try:
        out.append(re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text))
    except ValueError:
        pass
    out.append(urllib.parse.unquote(text))
    out.append(html.unescape(text))
    for chunk in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", text):
        try:
            raw = base64.b64decode(chunk.replace("-", "+").replace("_", "/") + "=" * (-len(chunk) % 4), validate=True)
            out.append(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return "\n".join(x for x in out if x != text)


def scan(path: str, body: bytes, names: list[str]) -> list[dict]:
    """Findings in one file: {kind, file, line, text}."""
    found = []

    def hit(kind: str, line: int, text: str) -> None:
        found.append({"kind": kind, "file": path, "line": line, "text": text[:120]})

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    low = body.lower()
    if text is None:
        for n in names:
            for _ in range(low.count(n.lower().encode())):
                hit("private_name", 0, n + " (in a binary file)")
        return found

    patterns = {} if path == SELF else dict(SECRET) if path.startswith(VENDOR) else {**GENERIC, **SECRET}
    passes = [(text, "")]
    hidden = decodings(text)
    if hidden:
        passes.append((hidden, " (decoded)"))
    plain = set()  # what the first pass saw; the decoded pass reports only what an encoding was hiding
    for corpus, note in passes:
        for no, line in enumerate(corpus.split("\n"), 1):
            matches = [(kind, m.group(0)) for kind, rx in patterns.items() for m in rx.finditer(line)]
            matches += [("private_name", m.group(0)) for n in names for m in re.finditer(re.escape(n), line, re.I)]
            for kind, s in matches:
                if kind == "ip_address" and (OK_IP.match(s) or any(int(p) > 255 for p in s.split("."))):
                    continue
                if kind == "email" and OK_MAIL.search(s):
                    continue
                if not note:
                    plain.add((kind, s.lower()))
                elif (kind, s.lower()) in plain:
                    continue
                hit(kind, 0 if note else no, s + note)
    return found


def archive(treeish: str) -> list[tuple[str, bytes]]:
    p = subprocess.run(["git", "-c", "core.autocrlf=false", "archive", "--format=tar", treeish],
                       cwd=ROOT, capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode(errors="replace"))
        sys.exit(65)
    out = []
    with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tar:
        for m in tar.getmembers():
            if m.isfile():
                out.append((m.name, tar.extractfile(m).read()))
    return out


# One violation of every kind, and one hidden by every encoding. The private name is made up.
PLANTED_NAME = "Zorblatt"
PLANTED = {
    "private_host": b"HITL_URL default https://decide.acme.lan\n",
    "ip_address": b"upstream 10.20.30.40:8080;\n",
    "home_folder": b"state = '/home/jdoe/.hitl'\n",
    "home_folder (windows)": b"path = C:\\Users\\jdoe\\state\n",
    "email": b"contact: jane.doe@acme-corp.com\n",
    "tracker_ref": b"Fixed the replay check (#4821).\n",
    "tracker_ref (worded)": b"Source: issue #1, with amendments.\n",
    "placeholder": b"Hello <CAREGIVER_NAME>, welcome.\n",
    "secret": b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "secret (assignment)": b"api_key = 'c29tZXRoaW5nLXZlcnktc2VjcmV0'\n",
    "private_name": b"# ported from the zorblatt deployment\n",
    "private_name (capitalised)": b"// ZORBLATT keeps its own copy\n",
    "private_name (\\u escaped)": b'{"owner": "\\u005aorblatt"}\n',
    "private_name (base64)": base64.b64encode(b"belongs to Zorblatt Ltd, see notes") + b"\n",
    "private_name (url-encoded)": b"https://example.com/?q=%5Aorblatt\n",
    "private_name (html entity)": b"<title>&#90;orblatt console</title>\n",
    "private_name (binary)": b"\xff\xfe\x00\x01zorblatt\x00\xff",
    "private_name (vendored)": b"/* zorblatt */ var a=1;\n",
}
CLEAN = (b"HITL_ORIGIN: https://decide.example.com\nbind 0.0.0.0:8080, proxy at 127.0.0.1, docs use 192.0.2.7\n"
         b"color: #111; border: 1px solid #555; mail alice@example.com; pdfjs-dist 6.3.289\n")


def self_test() -> int:
    missed = []
    for label, body in PLANTED.items():
        kind = label.split(" (")[0]
        path = VENDOR + "x.js" if "vendored" in label else "planted.txt"
        if not any(f["kind"] == kind for f in scan(path, body, [PLANTED_NAME.lower()])):
            missed.append(label)
    false_hits = scan("clean.txt", CLEAN, [PLANTED_NAME.lower()])
    ok = not missed and not false_hits
    print(json.dumps({"status": "ok" if ok else "failed", "planted": len(PLANTED), "missed": missed,
                      "false_hits": false_hits}, indent=4))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) > 1 or (args and args[0].startswith("-")):
        sys.stderr.write("usage: prepublish.py [<tree-ish>] | --self-test\n")
        return 64
    names = private_names()
    files = archive(args[0] if args else "HEAD")
    findings = []
    for path, body in files:
        findings += scan(path, body, names)
    print(json.dumps({"status": "ok" if not findings else "failed", "files": len(files),
                      "private_names": len(names), "findings": len(findings), "list": findings}, indent=4))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
