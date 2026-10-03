#!/usr/bin/env python3
"""Shared test vectors against the two Python implementations (service and caller library).

  python tests/vectors.py

tests/vectors/jcs.json: canonical JSON. tests/vectors/protocol.json: signed objects and their exact
fields, timestamps, padding, WebAuthn assertions, key statement chains (see tests/make_vectors.py).
The web client is checked against the same files by tests/vectors.mjs. Prints one JSON object;
exit 0 only if every vector is judged as the file says, by both implementations.
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "server"))

with open(os.path.join(ROOT, "tests", "vectors", "protocol.json"), encoding="utf-8") as f:
    P = json.load(f)
# The caller library checks assertions against the origin of the service it is configured for.
os.environ["HITL_URL"] = P["origin"]

from hitl import lib as server  # noqa: E402

# The caller is a file called hitl.py and the server a package called hitl: load the caller by path.
_spec = importlib.util.spec_from_file_location("hitl_caller", os.path.join(ROOT, "caller", "hitl.py"))
caller = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(caller)

failed = []
count = 0


def expect(group: str, name: str, side: str, got: object, want: object) -> None:
    global count
    count += 1
    if got != want or type(got) is not type(want):
        failed.append({"group": group, "vector": name, "implementation": side, "got": got, "want": want})


def raw(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def caller_unpad(padded: bytes) -> str | None:
    try:
        return caller.b64u(caller.unpad(padded))
    except caller.Rejected:
        return None


def caller_chain(v: dict) -> dict | None:
    """A caller has no anchor: it replays a chain from its first statement, as at pinning."""
    pin = {"recipient_id": P["recipient_id"], "epoch": v["anchor"]["epoch"], "seq": 0, "head": "",
           "enc_pubkey": None, "credentials": [], "history": []}
    try:
        for item in v["items"]:
            caller.apply_statement(pin, item)
    except caller.Rejected:
        return None
    if pin["seq"] == 0:
        return None
    return {"epoch": pin["epoch"], "seq": pin["seq"], "head": pin["head"], "credentials": pin["credentials"],
            "enc_pubkey": pin["enc_pubkey"], "fingerprint": pin["fingerprint"]}


def main() -> int:
    with open(os.path.join(ROOT, "tests", "vectors", "jcs.json"), encoding="utf-8") as f:
        for v in json.load(f)["vectors"]:
            for side, fn in (("server", server.jcs), ("caller", caller.jcs)):
                expect("jcs", v["name"], side, fn(v["value"]), v["canonical"])

    for v in P["hashes"]:
        for side, impl in (("server", server), ("caller", caller)):
            expect("hashes", v["name"], side, impl.jcs(v["object"]), v["canonical"])
            expect("hashes", v["name"], side, impl.b64u(hashlib.sha256(impl.jcs_bytes(v["object"])).digest()), v["sha256"])
    for v in P["shapes"]:
        for side, impl in (("server", server), ("caller", caller)):
            if v["type"] in impl.SHAPES:
                expect("shapes", v["name"], side, impl.shaped(v["object"], v["type"], tuple(v["extra"])), v["ok"])
    for v in P["timestamps"]:
        for side, impl in (("server", server), ("caller", caller)):
            expect("timestamps", repr(v["value"]), side, impl.parse_ts(v["value"]), v["seconds"])
    for v in P["padding"]:
        expect("padding", v["name"], "caller", caller_unpad(raw(v["padded"])), v["plain"])
    for v in P["bad_padding"]:
        expect("bad_padding", v["name"], "caller", caller_unpad(raw(v["padded"])), None)
    challenge = raw(P["challenge"])
    for v in P["assertions"]:
        c = v["credential"]
        expect("assertions", v["name"], "server",
               server.assertion_problem(v["assertion"], challenge, raw(c["spki"]), c["alg"], P["origin"], P["rp_id"]), v["problem"])
        expect("assertions", v["name"], "caller", caller.assertion_problem(v["assertion"], challenge, c), v["problem"])
    for v in P["chains"]:
        first = v["items"][0]["statement"] if v["items"] else None
        if v["anchor"]["seq"] != 1 or (first is not None and caller.statement_hash(first) != v["anchor"]["hash"]):
            continue  # a device's own memory of its anchor: the web client's check, see vectors.mjs
        expect("chains", v["name"], "caller", caller_chain(v), v["result"])

    for v in P["answers"]:
        expect("answers", v["name"], "caller", caller.schema_problem(v["schema"]), None)
        expect("answers", v["name"], "caller", caller.answer_problem(v["answer"], v["schema"]), None)

    print(json.dumps({"status": "ok" if not failed else "failed", "checks": count, "failed": failed}, indent=4))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
