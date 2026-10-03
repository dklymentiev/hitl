#!/usr/bin/env python3
"""A lying service against the caller library, and hostile clients against the service.

  python tests/hostile.py

No browser and no network: the service runs in this process (its WSGI application is called
directly), the caller library is the shipped caller/hitl.py with only its transport replaced, and
the recipient's devices are simulated here with real keys and real WebAuthn-shaped assertions.
Between the caller and the service sits a hook that rewrites what the service answers: that is the
lying service of the specification's R10. The page's side of the same rule is in tests/e2e.mjs.

Every check prints PASS or FAIL; exit 0 only if all passed.
"""

import contextlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp(prefix="hitl-hostile-")
ORIGIN = "https://hitl.test"
os.environ.update(HITL_DB=os.path.join(TMP, "hitl.sqlite"), HITL_ORIGIN=ORIGIN, HITL_URL=ORIGIN,
                  HITL_STATE=os.path.join(TMP, "caller"))
sys.path.insert(0, os.path.join(ROOT, "server"))

import nacl.bindings as sodium  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from hitl import lib  # noqa: E402
from hitl.app import application  # noqa: E402


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The caller is a file called hitl.py and the server a package called hitl: load the caller by path.
caller = load("hitl_caller", "caller/hitl.py")
admin_cli = load("hitl_admin", "server/bin/admin.py")
verifier = load("hitl_verify", "tools/verify_deployment.py")
b64u, unb64u, sha256, jcs_bytes = caller.b64u, caller.unb64u, caller.sha256, caller.jcs_bytes

failures = 0


def check(name: str, ok: bool, detail: object = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  ' + str(detail)[:300] if detail != '' and not ok else ''}")
    if not ok:
        failures += 1


# ---------------------------------------------------------------- the service, in process

class Body(io.BytesIO):
    """A request body that remembers whether the service read it."""
    touched = False

    def read(self, *a):
        self.touched = True
        return super().read(*a)


def wsgi(method: str, path: str, data: bytes = b"", headers: dict | None = None, length: str | None = None) -> tuple[int, bytes, dict, Body]:
    path, _, query = path.partition("?")
    body = Body(data)
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query, "wsgi.input": body,
               "CONTENT_LENGTH": str(len(data)) if length is None else length, "CONTENT_TYPE": "application/json"}
    for k, v in (headers or {}).items():
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    got = {}

    def start(status, response_headers):
        got["status"] = int(status.split()[0])
        got["headers"] = dict(response_headers)

    out = b"".join(application(environ, start))
    return got["status"], out, got["headers"], body


def call(method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    """A request as a browser or any other client would make it, with nothing in between."""
    status, raw, _, _ = wsgi(method, path, json.dumps(body).encode() if body is not None else b"", headers)
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {}


LIE = None  # (method, path, status, reply) -> (status, reply): the lying service, as the caller sees it


def transport(req, timeout):
    data = req.data.read() if hasattr(req.data, "read") else (req.data or b"")
    path = req.full_url[len(ORIGIN):]
    status, raw, _, _ = wsgi(req.get_method(), path, data, dict(req.header_items()))
    if LIE is not None:
        try:
            reply = json.loads(raw)
        except ValueError:
            reply = {}
        status, reply = LIE(req.get_method(), path, status, reply)
        raw = json.dumps(reply).encode()
    return status, raw


caller._send = transport


@contextlib.contextmanager
def lying(fn):
    global LIE
    LIE = fn
    try:
        yield
    finally:
        LIE = None


def run(*args: str) -> dict:
    """One command of the caller library, as its command line runs it."""
    out = io.StringIO()
    stdin, sys.stdin = sys.stdin, io.StringIO("y\n")  # not a terminal, and a "y" for any prompt that would read one
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            caller.main(["hitl.py", *args])
    finally:
        sys.stdin = stdin
    return json.loads(out.getvalue().strip().splitlines()[-1])


def admin(*args: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        admin_cli.main(list(args))
    return out.getvalue().strip()


class Clock:
    """The time module as the caller library sees it, moved by an offset."""

    def __init__(self, offset: int):
        self.offset = offset

    def time(self):
        return time.time() + self.offset

    def gmtime(self, t=None):
        return time.gmtime(self.time() if t is None else t)

    def __getattr__(self, name):
        return getattr(time, name)


@contextlib.contextmanager
def caller_clock(offset: int):
    caller.time = Clock(offset)
    try:
        yield
    finally:
        caller.time = time


# ---------------------------------------------------------------- simulated devices

RP_ID = "hitl.test"


def now(offset: int = 0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


class Device:
    def __init__(self, label: str, rsa_bits: int = 0):
        self.key = rsa.generate_private_key(65537, rsa_bits) if rsa_bits else ec.generate_private_key(ec.SECP256R1())
        self.alg = -257 if rsa_bits else -7
        self.id = b64u(os.urandom(16))
        self.label = label
        self.spki = b64u(self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo))

    def cred(self) -> dict:
        return {"id": self.id, "spki": self.spki, "alg": self.alg, "label": self.label}

    def assertion(self, challenge: bytes, origin: str = ORIGIN, flags: int = 0x05, kind: str = "webauthn.get") -> dict:
        cdj = json.dumps({"type": kind, "challenge": b64u(challenge), "origin": origin, "crossOrigin": False}).encode()
        ad = sha256(RP_ID.encode()) + bytes([flags]) + b"\x00\x00\x00\x01"
        if self.alg == -7:
            sig = self.key.sign(ad + sha256(cdj), ec.ECDSA(hashes.SHA256()))
        else:
            from cryptography.hazmat.primitives.asymmetric import padding
            sig = self.key.sign(ad + sha256(cdj), padding.PKCS1v15(), hashes.SHA256())
        return {"credential_id": self.id, "client_data_json": b64u(cdj), "authenticator_data": b64u(ad), "signature": b64u(sig)}


class Session:
    """A device session: a key the device delegated to, as the page makes one at unlock."""

    def __init__(self, recipient_id: str, device: Device, issued: int = 0, hours: int = 12):
        self.key = SigningKey.generate()
        self.delegation = {"version": 1, "type": "hitl.session", "recipient_id": recipient_id,
                           "session_pubkey": b64u(bytes(self.key.verify_key)),
                           "issued_at": now(issued), "expires_at": now(issued + hours * 3600)}
        self.assertion = device.assertion(sha256(jcs_bytes(self.delegation)))

    def proof(self, record: dict) -> dict:
        return {"delegation": self.delegation, "assertion": self.assertion,
                "signature": b64u(self.key.sign(jcs_bytes(record)).signature)}


class Recipient:
    """A person with devices, doing what the page does, in Python."""

    def __init__(self, id_: str):
        self.id = id_
        self.fresh()

    def fresh(self) -> None:
        self.pk, self.sk = sodium.crypto_box_keypair()
        self.devices: list[Device] = []
        self.chain: list[dict] = []

    def enrol(self, device: Device, signer: Device | None = None, mutate=None) -> tuple[int, dict]:
        token = admin("enrol-link", self.id, "Test Person").rsplit("/", 1)[1]
        _, info = call("GET", f"/api/v1/enroll/{token}")
        statement = {
            "type": "hitl.key-statement", "version": 2, "recipient_id": self.id, "epoch": info["epoch"],
            "seq": len(self.chain) + 1, "prev": caller.statement_hash(self.chain[-1]) if self.chain else "",
            "enc_pubkey": b64u(self.pk),
            "credentials": sorted([d.cred() for d in self.devices] + [device.cred()], key=lambda c: c["id"]),
            "issued_at": now(),
        }
        if mutate:
            mutate(statement)
        signer = signer or (self.devices[0] if self.devices else device)
        a = signer.assertion(sha256(jcs_bytes(statement)))
        status, res = call("POST", f"/api/v1/enroll/{token}", {
            "credential_id": device.id, "spki": device.spki, "alg": device.alg, "prf_salt": b64u(os.urandom(32)),
            "wrapped_key": b64u(os.urandom(120)), "wrap_nonce": b64u(os.urandom(24)), "enc_pubkey": b64u(self.pk),
            "statement": statement, "statement_assertion": a})
        if status == 200:
            self.devices.append(device)
            self.chain.append(statement)
        return status, res

    def fingerprint(self) -> str:
        return caller.key_fingerprint(self.chain[-1])

    def record(self, request_id: str, answer: dict, seal_to: bytes | None = None, padded: bytes | None = None,
               signed_offset: int = 0) -> dict:
        _, req = call("GET", f"/api/v1/requests/{request_id}")
        manifest = sodium.crypto_box_seal_open(unb64u(req["config_ct"]), self.pk, self.sk)
        payload = sodium.crypto_box_seal_open(unb64u(req["payload_ct"]), self.pk, self.sk)
        facts = json.loads(manifest)["request"]
        if padded is None:
            padded = sodium.sodium_pad(jcs_bytes(answer), 4096)
        record = {
            "type": "hitl.response", "version": 2, "request_id": facts["request_id"],
            "creation_hash": b64u(sha256(jcs_bytes(req["creation_body"]))),
            "config_hash": b64u(sha256(manifest)), "payload_hash": b64u(sha256(payload)),
            "answer_ct": b64u(sodium.crypto_box_seal(padded, seal_to or unb64u(facts["answer_pubkey"]))),
            "signed_at": now(signed_offset),
        }
        if facts["policy"]["review"]:
            record["answer_self_ct"] = b64u(sodium.crypto_box_seal(padded, self.pk))
        return record

    def answer(self, request_id: str, answer: dict, device: Device | None = None, session: Session | None = None,
               **kw) -> tuple[int, dict]:
        record = self.record(request_id, answer, **kw)
        return self.submit(request_id, record, device, session)

    def submit(self, request_id: str, record: dict, device: Device | None = None, session: Session | None = None) -> tuple[int, dict]:
        if session is not None:
            message = {"record": record, "session": session.proof(record)}
        else:
            message = {"record": record, "assertion": (device or self.devices[0]).assertion(sha256(jcs_bytes(record)))}
        return call("POST", f"/api/v1/requests/{request_id}/response", message)


def plant(request_id: str, record: dict, proof: dict) -> None:
    """Puts a response into the service's storage without any of its checks: what a hostile service
    can present to a caller is whatever it likes."""
    lib.q("UPDATE requests SET response_record = ?, response_assertion = ?, signed_at = ? WHERE id = ?",
          (lib.jcs(record), json.dumps(proof), lib.now(), request_id))


def state(rel: str) -> dict:
    with open(os.path.join(os.environ["HITL_STATE"], rel), encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- setup: a caller, a person, a pin

kg = run("keygen", "test-caller")
check("caller keygen", kg["status"] == "ok")
admin("add-caller", "test-caller", "Test Caller", "caller.example", kg["pubkey"])

alice = Recipient("alice")
phone = Device("Phone")
status, res = alice.enrol(phone)
check("first device enrols with a statement it signs itself", status == 200, res)

# ---- pinning (R9, R10): a lying service at onboarding

mallory = Device("Mallory")


def add_key_to_keys(method, path, status, reply):
    if path.endswith("/keys"):
        reply["credentials"] = sorted(reply["credentials"] + [mallory.cred()], key=lambda c: c["id"])
    return status, reply


with lying(add_key_to_keys):
    r = run("pin", "alice", "--fingerprint", alice.fingerprint())
check("pin refuses a key the service lists without a statement", r == {"status": "rejected", "reason": "keys_changed_without_statement"}, r)
check("a refused pin leaves no pin behind", not os.path.exists(os.path.join(os.environ["HITL_STATE"], "pins", "alice.json")))

# A chain entirely of the service's making: its own key, its own first statement, consistently served.
forged_pk, _ = sodium.crypto_box_keypair()
forged_statement = {"type": "hitl.key-statement", "version": 2, "recipient_id": "alice", "epoch": 1, "seq": 1, "prev": "",
                    "enc_pubkey": b64u(forged_pk), "credentials": [mallory.cred()], "issued_at": now()}
forged_item = {"seq": 1, "statement": forged_statement, "assertion": mallory.assertion(sha256(jcs_bytes(forged_statement)))}


def forged_chain(method, path, status, reply):
    if "/statements" in path:
        reply["statements"] = [forged_item]
    if path.endswith("/keys"):
        reply.update(enc_pubkey=b64u(forged_pk), credentials=[mallory.cred()])
    return status, reply


with lying(forged_chain):
    r = run("pin", "alice", "--fingerprint", alice.fingerprint())
check("pin refuses a self-consistent chain of the service's own: the fingerprint differs",
      r == {"status": "rejected", "reason": "fingerprint_mismatch"}, r)
r = run("pin", "alice", "--yes")
check("pin has no way to skip the fingerprint comparison", r["status"] == "error" and "--yes" in r.get("reason"), r)
r = run("pin", "alice", "--fingerprint", "0000 " * 8)
check("pin refuses a wrong fingerprint", r == {"status": "rejected", "reason": "fingerprint_mismatch"}, r)
r = run("pin", "alice", "--fingerprint", alice.fingerprint())
check("pin accepts the chain whose fingerprint the recipient's device shows",
      r["status"] == "pinned" and r["fingerprint"] == alice.fingerprint() and r["seq"] == 1 and r["devices"] == 1, r)

# ---- an honest round trip

ask = run("ask", "alice", "--title", "Order lunch?", "--text", "Sandwiches for six.", "--ttl", "3600", "--ref", "task:1",
          "--choices", "A:Order,B:Skip,cancel:Cancel", "--comment", "200")
check("ask", ask["status"] == "created" and ask["link"].startswith(ORIGIN + "/r/"), ask)
lunch = ask["request_id"]
check("check before the answer is pending", run("check", lunch)["status"] == "pending")
_, shown = call("GET", f"/api/v1/requests/{lunch}")
check("the service is given no answer key, nonce or time to mint: the creation body is the caller's",
      shown["creation_body"] == state(f"requests/{lunch}.json")["body"] and "nonce" not in shown and "issued_at" not in shown)
status, res = alice.answer(lunch, {"choice": "A", "comment": "Fine."})
check("the service accepts a signed, sealed answer", status == 200, res)
_, shown = call("GET", f"/api/v1/requests/{lunch}")
record = shown["response"]["record"]
check("the stored record holds no answer in clear and the sealed answer has a length that says nothing",
      "answer" not in record and "Fine" not in json.dumps(shown) and len(unb64u(record["answer_ct"])) == 48 + 4096, sorted(record))
r = run("check", lunch)
check("check verifies and decrypts the answer", r["status"] == "answered" and r["answer"] == {"choice": "A", "comment": "Fine."}
      and r["answer_label"] == "Order" and r["caller_ref"] == "task:1" and r["assurance"] == "fresh" and r["consumed"] is False, r)
r = run("consume", lunch)
check("consume returns the verified answer once", r["status"] == "answered" and r["proof_token"].startswith("hitl-proof-v2."), r)
r = run("consume", lunch)
check("second consume is a replay", r == {"status": "rejected", "reason": "replay"}, r)
status, res = alice.answer(lunch, {"choice": "B"})
check("the service refuses a second, different answer", status == 409, res)

# ---- the request id is the caller's: nothing the service returns names, overwrites or redirects a request

transfer = run("ask", "alice", "--title", "Transfer 1 000 000?", "--text", "To account 42.", "--ttl", "3600", "--ref", "task:2")["request_id"]


def answer_of_lunch(method, path, status, reply):
    if path == f"/api/v1/requests/{transfer}":
        reply["response"] = shown["response"]
    return status, reply


with lying(answer_of_lunch):
    r = run("consume", transfer)
check("an approval of one request does not count for another", r["status"] == "rejected" and r.get("reason").startswith("record_mismatch:"), r)
check("and the refused request is not marked consumed", not os.path.exists(os.path.join(os.environ["HITL_STATE"], "consumed", transfer + ".json")))


def renamed(method, path, status, reply):
    if method == "POST" and path == "/api/v1/requests":
        reply.update(request_id=lunch, nonce="x", issued_at=now(), expires_at="2099-01-01T00:00:00Z")
    return status, reply


before = state(f"requests/{lunch}.json")
with lying(renamed):
    r = run("ask", "alice", "--text", "Third", "--ttl", "900")
check("a request id, nonce or time in the service's reply changes nothing",
      r["status"] == "created" and r["request_id"] != lunch and state(f"requests/{lunch}.json") == before
      and caller.parse_ts(r["expires_at"]) - time.time() < 1000, r)


def phishing_link(method, path, status, reply):
    if method == "POST" and path == "/api/v1/requests":
        reply["short_link"] = "https://evil.example/r/AAAAAAAAAAAAAAAA"
    return status, reply


n = len(os.listdir(os.path.join(os.environ["HITL_STATE"], "requests")))
with lying(phishing_link):
    r = run("ask", "alice", "--text", "Fourth", "--ttl", "900")
check("a link that leads away from the service is refused, and the request is forgotten",
      r == {"status": "rejected", "reason": "create_returned_a_foreign_link"}
      and len(os.listdir(os.path.join(os.environ["HITL_STATE"], "requests"))) == n, r)
check("a request id that is not this caller's own is unknown to it",
      run("check", "../caller")["status"] == "error" and run("check", "00000000-0000-0000-0000-000000000000")["status"] == "error")

# ---- the record: exact fields, sealed to this request, padded, inside the schema, inside the lifetime


def fresh_request(*extra: str) -> str:
    return run("ask", "alice", "--text", "Decide.", "--ttl", "900", "--choices", "A:Yes,B:No,cancel:Cancel", *extra)["request_id"]


def verdict(request_id: str) -> dict:
    return run("check", request_id)


def forge(change, **record_args) -> dict:
    """A record the device really signed, with one thing wrong, presented by a service that accepts anything."""
    id_ = fresh_request()
    record = alice.record(id_, {"choice": "A"}, **record_args)
    change(record)
    plant(id_, record, phone.assertion(sha256(jcs_bytes(record))))
    return verdict(id_)


r = forge(lambda rec: rec.update(answer={"choice": "A"}))
check("a record with a field too many is refused", r == {"status": "rejected", "reason": "malformed_record"}, r)
r = forge(lambda rec: rec.pop("config_hash"))
check("a record with a field missing is refused", r == {"status": "rejected", "reason": "malformed_record"}, r)
r = forge(lambda rec: rec.update(type="hitl.key-statement"))
check("a signed object of another type is refused as a record", r == {"status": "rejected", "reason": "malformed_record"}, r)
r = forge(lambda rec: rec.update(creation_hash=b64u(os.urandom(32))))
check("a record that names another creation body is refused", r.get("reason") == "record_mismatch:creation_hash", r)
r = forge(lambda rec: rec.update(payload_hash=b64u(os.urandom(32))))
check("a record over another payload is refused", r.get("reason") == "record_mismatch:payload_hash", r)
other_pk, _ = sodium.crypto_box_keypair()
r = forge(lambda rec: None, seal_to=other_pk)
check("an answer sealed to a key the caller did not make for this request is refused", r.get("reason") == "answer_not_sealed_to_this_request", r)
r = forge(lambda rec: None, padded=jcs_bytes({"choice": "A"}).ljust(4096, b"\x00"))
check("an answer without valid padding is refused", r.get("reason") == "answer_padding", r)
r = forge(lambda rec: None, padded=sodium.sodium_pad(b'{"choice": "A"}', 4096))
check("an answer that is not canonical is refused", r.get("reason") == "answer_not_canonical", r)
id_ = fresh_request()
plant(id_, rec := alice.record(id_, {"choice": "Z"}), phone.assertion(sha256(jcs_bytes(rec))))
check("an answer outside the caller's schema is refused", verdict(id_).get("reason") == "schema_mismatch")
r = forge(lambda rec: None, signed_offset=2000)
check("an answer signed after the request's lifetime is refused", r.get("reason") == "signed_outside_the_request_lifetime", r)
r = forge(lambda rec: None, signed_offset=-2000)
check("an answer signed before the request existed is refused", r.get("reason") == "signed_outside_the_request_lifetime", r)
id_ = fresh_request()
rec = alice.record(id_, {"choice": "A"})
plant(id_, rec, mallory.assertion(sha256(jcs_bytes(rec))) | {"credential_id": phone.id})
check("a record signed by another key under a pinned credential's name is refused", verdict(id_).get("reason") == "signature_invalid")
id_ = fresh_request()
rec = alice.record(id_, {"choice": "A"})
plant(id_, rec, phone.assertion(sha256(jcs_bytes(rec)), origin="https://evil.example"))
check("an assertion made for another origin is refused", verdict(id_).get("reason") == "origin_mismatch")
id_ = fresh_request()
rec = alice.record(id_, {"choice": "A"})
plant(id_, rec, phone.assertion(sha256(jcs_bytes(rec)), flags=0x01))
check("an assertion without user verification is refused", verdict(id_).get("reason") == "not_user_verified")

# ---- the deadline is the caller's own clock: an approval held back is not an approval

held = fresh_request()
alice.answer(held, {"choice": "A"})
with caller_clock(900 + 301):
    r = verdict(held)
check("an answer signed in time but first seen after the deadline is not an approval", r["status"] == "expired", r)
seen = fresh_request()
alice.answer(seen, {"choice": "A"})
check("an answer seen in time verifies", verdict(seen)["status"] == "answered")
with caller_clock(900 + 301):
    r = run("consume", seen)
check("and can still be consumed after the deadline, having been seen before it", r["status"] == "answered", r)
down = fresh_request()


def unreachable(req, timeout):
    raise caller.Hold("service_unreachable")


caller._send = unreachable
r1 = verdict(down)
with caller_clock(900 + 301):
    r2 = verdict(down)
caller._send = transport
check("with the service unreachable the caller holds, and reports expired by its own clock once the deadline has passed",
      r1 == {"status": "hold", "reason": "service_unreachable"} and r2["status"] == "expired", (r1, r2))

# ---- review: a second copy sealed to the recipient, present exactly when the policy has review

rv = fresh_request("--review")
status, res = alice.answer(rv, {"choice": "B"})
check("with review the record carries the recipient's own sealed copy", status == 200 and verdict(rv)["answer"] == {"choice": "B"}, res)
id_ = fresh_request("--review")
rec = alice.record(id_, {"choice": "A"})
rec.pop("answer_self_ct")
status, res = alice.submit(id_, rec)
plant(id_, rec, phone.assertion(sha256(jcs_bytes(rec))))
check("without it the service and the caller both refuse", status == 400 and verdict(id_).get("reason") == "malformed_record", res)

# ---- sessions and the caller's policy

session = Session("alice", phone)
ss = fresh_request("--assurance", "session", "--max-session-age", "1h")
status, res = alice.answer(ss, {"choice": "A"}, session=session)
r = verdict(ss)
check("a session confirms an answer where the caller's policy allows sessions", status == 200 and r["status"] == "answered" and r["assurance"] == "session", (res, r))
fr = fresh_request()
status, res = alice.answer(fr, {"choice": "A"}, session=session)
check("the service refuses a session answer to a fresh request", status == 403, res)
rec = alice.record(fr, {"choice": "A"})
proof = session.proof(rec)
plant(fr, rec, {"kind": "session", "credential_id": phone.id, "delegation": proof["delegation"],
                "delegation_assertion": proof["assertion"], "signature": proof["signature"]})
check("and so does the caller, whatever the service stored", verdict(fr).get("reason") == "fresh_confirmation_required")
old = Session("alice", phone, issued=-7200)
id_ = fresh_request("--assurance", "session", "--max-session-age", "1h")
status, res = alice.answer(id_, {"choice": "A"}, session=old)
check("a session older than the caller allows is refused", status == 403, res)
# The session ended 100 s ago; the device claims it signed 150 s ago, while the session was alive,
# and that claim is inside the allowance on signed_at. Only the service's own clock tells.
dead = Session("alice", phone, issued=-3700, hours=1)
id_ = fresh_request("--assurance", "session")
status, res = alice.answer(id_, {"choice": "A"}, session=dead, signed_offset=-150)
check("a session past its end by the service's own clock is refused, whatever the device wrote as signed_at", status == 403, res)
id_ = fresh_request()
status, res = alice.answer(id_, {"choice": "A"}, signed_offset=-600)
check("an answer whose signed_at is far from the service's clock is refused", status == 403, res)

# ---- key statements: the chain, the anchor's other half, epochs

laptop = Device("Laptop")
status, res = alice.enrol(laptop, signer=laptop)
check("the service refuses a new device that signs its own statement", status == 403, res)
status, res = alice.enrol(laptop, mutate=lambda st: st.update(prev=b64u(os.urandom(32))))
check("the service refuses a statement that does not name the one before it", status == 400, res)
status, res = alice.enrol(laptop, mutate=lambda st: st.update(note="x"))
check("the service refuses a statement with a field too many", status == 400, res)
status, res = alice.enrol(laptop)
check("a second device is added by a statement the first one signs", status == 200, res)
r = run("refresh", "alice")
check("the caller follows the signed statement", r["status"] == "pinned" and r["devices"] == 2 and r["seq"] == 2
      and r["fingerprint"] == alice.fingerprint(), r)
id_ = fresh_request()
alice.answer(id_, {"choice": "A"}, device=laptop)
check("and accepts an answer signed by the new device", verdict(id_)["status"] == "answered")

tablet = Device("Tablet")
third = {"type": "hitl.key-statement", "version": 2, "recipient_id": "alice", "epoch": 1, "seq": 3,
         "prev": caller.statement_hash(alice.chain[-1]), "enc_pubkey": b64u(alice.pk),
         "credentials": sorted([phone.cred(), laptop.cred(), tablet.cred()], key=lambda c: c["id"]), "issued_at": now()}


def serve(statement: dict, signer: Device, credentials: list | None = None, enc: bytes | None = None):
    item = {"seq": statement["seq"], "statement": statement, "assertion": signer.assertion(sha256(jcs_bytes(statement)))}

    def lie(method, path, status, reply):
        if "/statements" in path:
            reply["statements"] = [item] if int(path.rsplit("after=", 1)[1]) < statement["seq"] else []
        if path.endswith("/keys"):
            reply.update(credentials=statement["credentials"], seq=statement["seq"], enc_pubkey=statement["enc_pubkey"])
        return status, reply
    return lying(lie)


with serve(third, tablet):
    r = run("refresh", "alice")
check("a statement signed by a credential outside the pinned set is refused", r.get("reason") == "key_statement_unpinned_signer", r)
with serve({**third, "prev": b64u(os.urandom(32))}, phone):
    r = run("refresh", "alice")
check("a statement that does not chain to the pinned one is refused, even signed by a pinned device", r.get("reason") == "key_statement_malformed", r)
with serve({**third, "enc_pubkey": b64u(forged_pk)}, phone):
    r = run("refresh", "alice")
check("a statement that swaps the encryption key is refused", r.get("reason") == "key_statement_changes_encryption_key", r)
with serve({**third, "epoch": 2}, phone):
    r = run("refresh", "alice")
check("a statement of another epoch is refused", r.get("reason") == "key_statement_malformed", r)
wrong_alg = sorted([phone.cred(), laptop.cred(), {**tablet.cred(), "alg": -257}], key=lambda c: c["id"])
with serve({**third, "credentials": wrong_alg}, phone):
    r = run("refresh", "alice")
check("a credential declared under an algorithm that is not its key's is refused", r.get("reason") == "key_statement_credential_key_not_of_its_algorithm", r)
with lying(add_key_to_keys):
    r = run("ask", "alice", "--text", "x", "--ttl", "900")
check("ask refuses while the service lists a key no statement explains", r == {"status": "rejected", "reason": "keys_changed_without_statement"}, r)
check("after all that the pin has not moved", state("pins/alice.json")["seq"] == 2 and len(state("pins/alice.json")["credentials"]) == 2)

weak = Device("Weak", rsa_bits=1024)
status, res = alice.enrol(weak)
check("the service refuses an RSA credential under 2048 bits", status == 400, res)
strong = Device("Strong", rsa_bits=2048)
status, res = alice.enrol(strong)
r = run("refresh", "alice")
id_ = fresh_request()
alice.answer(id_, {"choice": "A"}, device=strong)
check("an RS256 credential of 2048 bits enrols, is followed and verifies", status == 200 and r["devices"] == 3 and verdict(id_)["status"] == "answered", (res, r))

# A reset by the operator: a new epoch, a new chain, and no caller follows it on its own.
stale = admin("enrol-link", "alice", "Test Person").rsplit("/", 1)[1]
admin("reset-recipient", "alice")
check("an enrolment link issued before a reset dies with it", call("GET", f"/api/v1/enroll/{stale}")[0] == 404)
alice.fresh()
status, res = alice.enrol(phone2 := Device("New phone"))
check("after a reset the person enrols again, in a new epoch from sequence 1",
      status == 200 and alice.chain[0]["epoch"] == 2 and alice.chain[0]["seq"] == 1, res)
r = run("refresh", "alice")
check("the caller does not follow a change of epoch", r == {"status": "rejected", "reason": "epoch_changed_pin_again"}, r)
r = run("ask", "alice", "--text", "x", "--ttl", "900")
check("and sends nothing until it pins again", r["status"] == "rejected", r)
r = run("pin", "alice", "--replace", "--fingerprint", alice.fingerprint())
check("pinning again takes the new fingerprint", r["status"] == "pinned" and r["epoch"] == 2 and r["seq"] == 1, r)
phone = phone2

# ---- the service against hostile clients

c = caller.caller()


def creation(change=None, sign_with: bytes | None = None, payload: bytes = b"x") -> tuple[dict, dict]:
    """A creation request built by hand: (headers, HTTP body)."""
    config_ct = sodium.crypto_box_seal(b"{}", alice.pk)
    payload_ct = sodium.crypto_box_seal(payload, alice.pk)
    body = {"type": "hitl.request", "version": 2, "request_id": str(caller.uuid.uuid4()), "caller_id": "test-caller",
            "recipient_id": "alice", "config_ct_hash": b64u(sha256(config_ct)), "payload_ct_hash": b64u(sha256(payload_ct)),
            "answer_pubkey": b64u(os.urandom(32)), "ttl": 900, "caller_ref": "", "created_at": now(),
            "policy": {"assurance": "fresh", "review": False}, "blobs": []}
    if change:
        change(body)
    canonical = jcs_bytes(body)
    sig = caller.sign(canonical, sign_with or unb64u(c["secret_key"]))
    return ({"X-Hitl-Body": b64u(canonical), "X-Hitl-Signature": b64u(sig)},
            {"config_ct": b64u(config_ct), "payload_ct": b64u(payload_ct)})


headers, body = creation()
check("a creation request built by hand is accepted", call("POST", "/api/v1/requests", body, headers)[0] == 201)
status, res = call("POST", "/api/v1/requests", body, headers)
check("the same creation body a second time creates nothing", status == 409, res)
_, stranger = sodium.crypto_sign_keypair()
headers, body = creation(sign_with=stranger)
status, raw, _, stream = wsgi("POST", "/api/v1/requests", os.urandom(5_000_000), headers)
check("an unsigned party cannot make the service read a large body", status == 403 and not stream.touched, (status, stream.touched))
status, raw, _, stream = wsgi("POST", "/api/v1/requests", os.urandom(1000), {})
check("nor one without the signed header", status == 400 and not stream.touched, status)
for name, change in (
        ("a field too many", lambda b: b.update(nonce="x")),
        ("no policy", lambda b: b.pop("policy")),
        ("a policy with an unknown key", lambda b: b["policy"].update(auto_approve=True)),
        ("a policy without review", lambda b: b["policy"].pop("review")),
        ("max_session_age on a fresh request", lambda b: b["policy"].update(max_session_age=600)),
        ("a request id that is not a UUID", lambda b: b.update(request_id="../caller")),
        ("a created_at an hour off", lambda b: b.update(created_at=now(3600))),
        ("a created_at with an offset instead of Z", lambda b: b.update(created_at=now().replace("Z", "+00:00"))),
        ("version 1", lambda b: b.update(version=1)),
        ("the type of another object", lambda b: b.update(type="hitl.blob"))):
    headers, body = creation(change)
    status, res = call("POST", "/api/v1/requests", body, headers)
    check(f"creation with {name} is refused", status == 400, (status, res))
for part in ("config_ct", "payload_ct"):
    headers, body = creation()
    status, res = call("POST", "/api/v1/requests", {**body, part: creation()[1][part]}, headers)
    check(f"a {part} that is not the signed one is refused", status == 400, res)

status, raw, _, _ = wsgi("POST", "/api/v1/inbox", b" " * 70_000, {})
check("the inbox refuses a body over 64 KiB before parsing it", status == 413, status)
status, raw, _, _ = wsgi("POST", f"/api/v1/requests/{lunch}/response", b" " * 300_000, {})
check("an answer over 256 KiB is refused before parsing", status == 413, status)

status, raw, page_headers, _ = wsgi("GET", "/r/AAAAAAAAAAAAAAAA")
check("pages may not be framed by another site", "frame-ancestors 'none'" in page_headers.get("Content-Security-Policy", ""))
replies = [wsgi("GET", "/r/AAAAAAAAAAAAAAAA")[2], wsgi("GET", "/api/v1/recipients/alice/keys")[2],
           wsgi("GET", "/assets/app.js")[2], wsgi("GET", "/api/v1/requests/nope-nope-nope-nope")[2]]
check("every response says nosniff", all(h.get("X-Content-Type-Options") == "nosniff" for h in replies))

big = os.path.join(TMP, "big.bin")
with open(big, "wb") as f:
    f.write(os.urandom(2_100_000))
manifest = os.path.join(TMP, "manifest.json")
with open(manifest, "w") as f:
    json.dump({"title": "A file", "blocks": [{"type": "file", "ref": "f"}], "answers": {"choices": [{"value": "ok", "label": "OK"}]}}, f)
r = run("ask", "alice", "--manifest", manifest, "--attach", f"f={big}", "--ttl", "900")
blob_id = lib.one("SELECT id FROM blobs WHERE request_id = ?", (r.get("request_id"),))
status, raw, blob_headers, _ = wsgi("GET", f"/api/v1/blobs/{blob_id['id']}") if blob_id else (0, b"", {}, None)
check("a blob uploaded with a typed, signed header is claimed by its request", r["status"] == "created" and status == 200, r)
check("a blob can never run in the service's origin",
      blob_headers.get("Content-Security-Policy") == "default-src 'none'; sandbox"
      and blob_headers.get("Content-Type") == "application/octet-stream")

with open(manifest, "w") as f:
    json.dump({"title": "T", "blocks": [], "answers": {"fields": [{"name": "n", "label": "N", "type": "number", "max": 1.5}]}}, f)
r = run("ask", "alice", "--manifest", manifest, "--ttl", "900")
check("a schema with a fraction is refused when the request is created", r["status"] == "error" and "whole number" in r.get("reason"), r)
with open(manifest, "w") as f:
    json.dump({"title": "T", "blocks": [], "answers": {"fields": [{"name": "n", "label": "N", "type": "number", "max": 2**53}]}}, f)
r = run("ask", "alice", "--manifest", manifest, "--ttl", "900")
check("and one with a number past 2^53 - 1", r["status"] == "error" and "whole number" in r.get("reason"), r)

token = admin("enrol-link", "bob", "Bob").rsplit("/", 1)[1]
dump = "\n".join(sqlite3.connect(os.environ["HITL_DB"]).iterdump())
check("a copy of the database yields no usable enrolment link", token not in dump and lib.token_hash(token) in dump)
events = [e["type"] for e in lib.rows("SELECT type FROM events")]
check("an enrolment link issued by the operator is logged like one issued through single sign-on",
      "hitl.recipient.enrol_started" in events)

# ---- manifest and payload name each other (a sealed box does not say who sealed it)

bound = fresh_request()
_, shown = call("GET", f"/api/v1/requests/{bound}")
m_plain = sodium.crypto_box_seal_open(unb64u(shown["config_ct"]), alice.pk, alice.sk)
p_plain = sodium.crypto_box_seal_open(unb64u(shown["payload_ct"]), alice.pk, alice.sk)
check("the manifest names the payload by its hash and the payload names the manifest by its salt",
      json.loads(m_plain)["payload_hash"] == b64u(sha256(p_plain)) and json.loads(p_plain)["manifest_salt"] == json.loads(m_plain)["salt"]
      and len(unb64u(json.loads(m_plain)["salt"])) == 32)

# ---- the service unreachable in the middle of a create


def lost_reply(req, timeout):
    transport(req, timeout)
    raise caller.Hold("service_unreachable")


caller._send = lambda req, timeout: lost_reply(req, timeout) if req.get_method() == "POST" else transport(req, timeout)
r = run("ask", "alice", "--text", "Lost reply", "--ttl", "900", "--choices", "A:Yes,B:No,cancel:Cancel")
caller._send = transport
check("a create whose reply is lost reports hold together with the request id", r.get("status") == "hold" and "request_id" in r, r)
status, res = alice.answer(r.get("request_id", ""), {"choice": "A"})
check("and an answer to that request still verifies under the id the caller kept", status == 200 and verdict(r.get("request_id", ""))["status"] == "answered", res)

# ---- arguments and schemas

r = run("ask", "alice", "--title", "--ttl", "--text", "x", "--ttl", "900")
title = json.loads(unb64u(state(f"requests/{r['request_id']}.json")["manifest"]))["title"] if r.get("request_id") else None
check("a value that looks like an option is still a value", title == "--ttl", r)
check("an unknown option is an error, not a recipient", run("ask", "alice", "--text", "x", "--tttl", "900").get("status") == "error")
check("a piped yes does not confirm a fingerprint: without a terminal pin wants the value itself",
      run("pin", "alice", "--replace").get("status") == "error" and state("pins/alice.json")["epoch"] == 2)
form = os.path.join(TMP, "form.json")
FIELDS = [{"name": "qty", "label": "Quantity", "type": "number", "min": 1, "max": 10, "required": True},
          {"name": "note", "label": "Note", "type": "text", "max_length": 5},
          {"name": "colour", "label": "Colour", "type": "select", "options": [{"value": "red", "label": "Red"}, {"value": "blue", "label": "Blue"}]},
          {"name": "tags", "label": "Tags", "type": "multiselect", "options": [{"value": "a", "label": "A"}, {"value": "b", "label": "B"}]},
          {"name": "day", "label": "Day", "type": "date"}, {"name": "sure", "label": "Sure", "type": "checkbox"}]


def ask_form(answers: dict) -> dict:
    with open(form, "w") as f:
        json.dump({"title": "Form", "blocks": [], "answers": answers}, f)
    return run("ask", "alice", "--manifest", form, "--ttl", "900")


for name, answers in (
        ("option values that are not strings", {"fields": [{"name": "n", "label": "N", "type": "select", "options": [{"value": 1, "label": "One"}]}]}),
        ("duplicate option values", {"fields": [{"name": "n", "label": "N", "type": "select", "options": [{"value": "a", "label": "A"}, {"value": "a", "label": "B"}]}]}),
        ("a comment without a length", {"choices": [{"value": "ok", "label": "OK"}], "comment": {}}),
        ("a text field longer than the limit", {"fields": [{"name": "n", "label": "N", "type": "text", "max_length": 5000}]}),
        ("an unknown key", {"choices": [{"value": "ok", "label": "OK"}], "buttons": []})):
    r = ask_form(answers)
    check(f"a schema with {name} is refused when the request is created", r.get("status") == "error", r)

schema = {"choices": [{"value": "ok", "label": "OK"}, {"value": "cancel", "label": "Cancel"}], "fields": FIELDS, "comment": {"max_length": 5}}
good = {"choice": "ok", "fields": {"qty": 3, "note": "abc", "colour": "red", "tags": ["a", "b"], "day": "2026-10-03", "sure": True}, "comment": "fine"}


def schema_verdict(answer: dict) -> dict:
    id_ = ask_form(schema)["request_id"]
    plant(id_, rec := alice.record(id_, answer), phone.assertion(sha256(jcs_bytes(rec))))
    return verdict(id_)


check("an answer that uses every kind of field verifies", schema_verdict(good).get("answer") == good)
check("cancel carries no fields", schema_verdict({"choice": "cancel"}).get("status") == "answered")
for name, change in (
        ("an unknown key", lambda a: a.update(extra=1)),
        ("a comment longer than allowed", lambda a: a.update(comment="too long")),
        ("a comment that is not text", lambda a: a.update(comment=5)),
        ("no fields where the schema has fields", lambda a: a.pop("fields")),
        ("fields with cancel", lambda a: a.update(choice="cancel")),
        ("an unknown field", lambda a: a["fields"].update(other="x")),
        ("a required field missing", lambda a: a["fields"].pop("qty")),
        ("a number out of range", lambda a: a["fields"].update(qty=11)),
        ("a number given as text", lambda a: a["fields"].update(qty="3")),
        ("true for a number", lambda a: a["fields"].update(qty=True)),
        ("text longer than its field allows", lambda a: a["fields"].update(note="abcdef")),
        ("empty text", lambda a: a["fields"].update(note="")),
        ("an option that was not offered", lambda a: a["fields"].update(colour="green")),
        ("the same option twice", lambda a: a["fields"].update(tags=["a", "a"])),
        ("something that is not a date", lambda a: a["fields"].update(day="tomorrow")),
        ("a checkbox that is not a boolean", lambda a: a["fields"].update(sure="yes")),
        ("no choice where the schema has choices", lambda a: a.pop("choice"))):
    bad = json.loads(json.dumps(good))
    change(bad)
    r = schema_verdict(bad)
    check(f"an answer with {name} is refused", r.get("reason") == "schema_mismatch", r)
id_ = ask_form(schema)["request_id"]
fraction = json.dumps({**good, "fields": {**good["fields"], "qty": 3.5}}, sort_keys=True, separators=(",", ":")).encode()
plant(id_, rec := alice.record(id_, {}, padded=sodium.sodium_pad(fraction, 4096)), phone.assertion(sha256(jcs_bytes(rec))))
r = verdict(id_)
check("an answer with a fraction is refused", r.get("reason") == "answer_not_canonical", r)

try:
    caller.create_json(f"requests/{bound}.json", {})
    exclusive = False
except FileExistsError:
    exclusive = True
check("a request's record cannot be created twice", exclusive and "body" in state(f"requests/{bound}.json"))

# ---- another recipient's keys never count

bob = Recipient("bob")
bob_phone = Device("Bob phone")
bob.enrol(bob_phone)
run("pin", "bob", "--fingerprint", bob.fingerprint())


def plant_session(request_id: str, record: dict, sess: Session, credential_id: str, signature: str | None = None) -> None:
    proof = sess.proof(record)
    plant(request_id, record, {"kind": "session", "credential_id": credential_id, "delegation": proof["delegation"],
                               "delegation_assertion": proof["assertion"], "signature": signature or proof["signature"]})


id_ = fresh_request()
rec = alice.record(id_, {"choice": "A"})
status, res = alice.submit(id_, rec, device=bob_phone)
plant(id_, rec, bob_phone.assertion(sha256(jcs_bytes(rec))))
check("an answer signed by another recipient's device is refused by the service and by the caller",
      status == 403 and verdict(id_).get("reason") == "unpinned_key", res)


def session_case(name: str, sess: Session, credential_id: str, server_status: int, reason: str, policy=("--assurance", "session", "--max-session-age", "1h"),
                 signature: str | None = None, **record_args) -> None:
    id_ = fresh_request(*policy)
    rec = alice.record(id_, {"choice": "A"}, **record_args)
    proof = sess.proof(rec)
    if signature:
        proof["signature"] = signature
    status, res = call("POST", f"/api/v1/requests/{id_}/response", {"record": rec, "session": proof})
    plant_session(id_, rec, sess, credential_id, signature)
    r = verdict(id_)
    check(f"a session {name} is refused by the service and by the caller", status == server_status and r.get("reason") == reason, (status, res, r))


session_case("delegated by another recipient's device", Session("alice", bob_phone), bob_phone.id, 403, "unpinned_key")
session_case("delegated for another recipient", Session("bob", phone), phone.id, 400, "session_delegation_malformed")
session_case("of 48 hours", Session("alice", phone, hours=48), phone.id, 403, "session_not_valid_at_signing")
session_case("that starts in the future", Session("alice", phone, issued=3600), phone.id, 403, "session_not_valid_at_signing")
session_case("older than the caller allows", Session("alice", phone, issued=-7200), phone.id, 403, "session_too_old")
other_session = Session("alice", phone)
session_case("whose key did not sign the record", Session("alice", phone), phone.id, 403, "session_signature_invalid",
             signature=b64u(other_session.key.sign(b"another record").signature))
forged_delegation = Session("alice", mallory)
forged_delegation.assertion["credential_id"] = phone.id
session_case("whose delegation the device did not sign", forged_delegation, phone.id, 403, "session_signature_invalid")
unshaped = Session("alice", phone)
unshaped.delegation["scope"] = "everything"
unshaped.assertion = phone.assertion(sha256(jcs_bytes(unshaped.delegation)))
session_case("whose delegation has a field too many", unshaped, phone.id, 400, "session_delegation_malformed")

live = Session("alice", phone)


def inbox(sess: Session, recipient_id: str = "alice", ts_offset: int = 0, sign_with: Session | None = None, **extra) -> tuple[int, dict]:
    msg = {"type": "hitl.inbox", "recipient_id": recipient_id, "ts": now(ts_offset)}
    return call("POST", "/api/v1/inbox", {**msg, "delegation": sess.delegation, "assertion": sess.assertion,
                                          "signature": b64u((sign_with or sess).key.sign(jcs_bytes(msg)).signature), **extra})


status, res = inbox(live)
check("the inbox lists pending requests for a live session, metadata only",
      status == 200 and len(res["requests"]) > 0 and set(res["requests"][0]) == {"request_id", "short", "created_at", "expires_at", "policy", "caller"}, res)
check("the inbox refuses a session of another recipient", inbox(Session("bob", bob_phone))[0] in (400, 403))
check("the inbox refuses a request the session key did not sign", inbox(live, sign_with=other_session)[0] == 403)
check("the inbox refuses a stale request", inbox(live, ts_offset=-3600)[0] == 403)
check("the inbox refuses an ended session", inbox(Session("alice", phone, issued=-7200, hours=1))[0] == 403)
check("the inbox refuses a request with a field too many", inbox(live, limit=1000)[0] == 400)

# ---- the record, one field at a time, at the service

id_ = fresh_request()
other_id = fresh_request()
for name, change, want in (
        ("the id of another request", lambda r_: r_.update(request_id=other_id), 400),
        ("another creation hash", lambda r_: r_.update(creation_hash=b64u(os.urandom(32))), 400),
        ("an answer that is not padded", lambda r_: r_.update(answer_ct=b64u(sodium.crypto_box_seal(b'{"choice":"A"}', alice.pk))), 400),
        ("a content hash that is not a hash", lambda r_: r_.update(config_hash="short"), 400)):
    rec = alice.record(id_, {"choice": "A"})
    change(rec)
    status, res = alice.submit(id_, rec)
    check(f"the service refuses a record with {name}", status == want, (status, res))
rec = alice.record(id_, {"choice": "A"})
first = phone.assertion(sha256(jcs_bytes(rec)))
second = phone.assertion(sha256(jcs_bytes(rec)))
status, _ = call("POST", f"/api/v1/requests/{id_}/response", {"record": rec, "assertion": first})
again, res = call("POST", f"/api/v1/requests/{id_}/response", {"record": rec, "assertion": first})
other, _ = call("POST", f"/api/v1/requests/{id_}/response", {"record": rec, "assertion": second})
check("the same signed answer again has one effect; the same record under another signature is a second answer",
      status == 200 and again == 200 and res.get("duplicate") is True and other == 409, (status, again, other))
lib.q("UPDATE requests SET expires_at = ? WHERE id = ?", (now(-10), other_id))
status, res = alice.answer(other_id, {"choice": "A"})
check("the service refuses an answer to an expired request", status == 410, res)
status, raw, _, _ = wsgi("POST", f"/api/v1/requests/{id_}/response",
                         json.dumps({"record": rec, "assertion": {**first, "signature": first["signature"] + "\n"}}).encode())
check("base64url with a trailing newline is refused, not an internal error", status in (400, 403, 409), status)
status, raw, _, stream = wsgi("POST", "/api/v1/inbox", b"x" * 200_000, length="-1")
check("a negative Content-Length reads nothing", status == 400 and len(stream.getvalue()) - stream.tell() == 200_000, status)

# ---- creation, the rest of its checks

for name, change, want in (
        ("a ttl below the minimum", lambda b: b.update(ttl=10), 400),
        ("a ttl above the maximum", lambda b: b.update(ttl=10**9), 400),
        ("a reference of 201 characters", lambda b: b.update(caller_ref="x" * 201), 400),
        ("a reference outside printable ASCII", lambda b: b.update(caller_ref="café"), 400),
        ("an answer key that is not 32 bytes", lambda b: b.update(answer_pubkey="AAAA"), 400),
        ("a recipient that is not enrolled", lambda b: b.update(recipient_id="nobody"), 404),
        ("a blob that does not exist", lambda b: b.update(blobs=["A" * 24]), 400)):
    headers, body = creation(change)
    status, res = call("POST", "/api/v1/requests", body, headers)
    check(f"creation with {name} is refused", status == want, (status, res))
headers, body = creation()
spaced = json.dumps(json.loads(unb64u(headers["X-Hitl-Body"])), indent=1).encode()
status, res = call("POST", "/api/v1/requests", body, {"X-Hitl-Body": b64u(spaced), "X-Hitl-Signature": b64u(caller.sign(spaced, unb64u(c["secret_key"])))})
check("a creation body that is not canonical is refused even when signed", status == 400, res)

# ---- blobs

other_pk, other_sk = sodium.crypto_sign_keypair()
admin("add-caller", "other-caller", "Other", "other.example", b64u(other_pk))


def put_blob(data: bytes, secret: bytes = None, caller_id: str = "test-caller", sha: str | None = None, **hdr_extra) -> tuple[int, dict]:
    hdr = {"type": "hitl.blob", "version": 2, "caller_id": caller_id, "sha256": sha or caller.hashlib.sha256(data).hexdigest(),
           "size": len(data), "created_at": now(), **hdr_extra}
    canonical = jcs_bytes(hdr)
    status, raw, _, _ = wsgi("PUT", "/api/v1/blobs", data, {"X-Hitl-Blob": b64u(canonical),
                                                           "X-Hitl-Signature": b64u(caller.sign(canonical, secret or unb64u(c["secret_key"])))})
    return status, json.loads(raw)


status, res = put_blob(b"ciphertext " * 100)
blob = res.get("blob_id", "")
check("a blob is stored under a signed header", status == 201 and len(blob) == 24, res)
check("a blob nobody claimed cannot be downloaded", wsgi("GET", f"/api/v1/blobs/{blob}")[0] == 404)
check("a blob that does not match its signed hash is refused", put_blob(b"data", sha="0" * 64)[0] == 400)
check("a blob header signed by someone else is refused", put_blob(b"data", secret=other_sk)[0] == 403)
check("a blob header with a field too many is refused", put_blob(b"data", note="x")[0] == 400)
headers, body = creation(lambda b: b.update(caller_id="other-caller", blobs=[blob]), sign_with=other_sk)
check("a blob cannot be claimed by another caller's request", call("POST", "/api/v1/requests", body, headers)[0] == 400)
headers, body = creation(lambda b: b.update(blobs=[blob]))
check("its own caller's request claims it", call("POST", "/api/v1/requests", body, headers)[0] == 201
      and wsgi("GET", f"/api/v1/blobs/{blob}")[0] == 200)
headers, body = creation(lambda b: b.update(blobs=[blob]))
check("and no second request can", call("POST", "/api/v1/requests", body, headers)[0] == 400)

# ---- enrolment links and key statements at the service

used = Recipient("dana")
status, _ = used.enrol(Device("Dana phone"))
token = admin("enrol-link", "dana", "Dana").rsplit("/", 1)[1]
lib.q("UPDATE enrol_tokens SET expires_at = ? WHERE token_hash = ?", (now(-10), lib.token_hash(token)))
check("an enrolment link past its time is dead", call("GET", f"/api/v1/enroll/{token}")[0] == 404)
token = admin("enrol-link", "dana", "Dana").rsplit("/", 1)[1]
lib.q("UPDATE enrol_tokens SET used_at = ? WHERE token_hash = ?", (now(), lib.token_hash(token)))
check("an enrolment link works once", call("GET", f"/api/v1/enroll/{token}")[0] == 404 and call("POST", f"/api/v1/enroll/{token}", {})[0] == 404)
other_enc, _ = sodium.crypto_box_keypair()
for name, change in (
        ("another epoch", lambda st: st.update(epoch=st["epoch"] + 1)),
        ("a sequence number that is not the next", lambda st: st.update(seq=st["seq"] + 1)),
        ("another encryption key", lambda st: st.update(enc_pubkey=b64u(other_enc))),
        ("another recipient", lambda st: st.update(recipient_id="bob")),
        ("an enrolled device left out", lambda st: st.update(credentials=[c_ for c_ in st["credentials"] if c_["id"] != used.devices[0].id])),
        ("an enrolled device under another key", lambda st: st["credentials"].__setitem__(
            [c_["id"] for c_ in st["credentials"]].index(used.devices[0].id), {**used.devices[0].cred(), "spki": mallory.spki})),
        ("no label for the new device", lambda st: [c_.update(label="") for c_ in st["credentials"]]),
        ("a label that ends in half a character", lambda st: [c_.update(label="phone \ud83d") for c_ in st["credentials"] if c_["id"] != used.devices[0].id]),
        ("a timestamp in another form", lambda st: st.update(issued_at="2026-10-03 10:00:00"))):
    status, res = used.enrol(Device("Dana tablet"), mutate=change)
    check(f"the service refuses a key statement with {name}", status == 400, (status, res))
status, res = call("GET", "/api/v1/enroll-sso")
check("single sign-on enrolment is off unless configured", status == 404, res)
os.environ.update(HITL_SSO_ID_HEADER="X-User", HITL_SSO_PROXY_SECRET="proxy-secret", HITL_SSO_ALLOW="erin")
check("single sign-on enrolment trusts the identity header only with the proxy's secret",
      call("GET", "/api/v1/enroll-sso", headers={"X-User": "erin"})[0] == 403
      and call("GET", "/api/v1/enroll-sso", headers={"X-User": "erin", "X-Hitl-Proxy-Secret": "guess"})[0] == 403)
check("and only for identities on the allow list", call("GET", "/api/v1/enroll-sso", headers={"X-User": "frank", "X-Hitl-Proxy-Secret": "proxy-secret"})[0] == 403)
status, res = call("GET", "/api/v1/enroll-sso", headers={"X-User": "erin", "X-Hitl-Proxy-Secret": "proxy-secret"})
check("the proxy's word starts an enrolment for that person", status == 200 and res.get("recipient_id") == "erin"
      and call("GET", f"/api/v1/enroll/{res.get('token')}")[1].get("via", "").startswith("sso:"), res)

# ---- pinning, the rest of its checks

two_at_once = {"type": "hitl.key-statement", "version": 2, "recipient_id": "dana", "epoch": 1, "seq": 1, "prev": "",
               "enc_pubkey": b64u(used.pk), "credentials": sorted([used.devices[0].cred(), mallory.cred()], key=lambda c_: c_["id"]),
               "issued_at": now()}
with serve(two_at_once, used.devices[0]):
    r = run("pin", "dana", "--fingerprint", caller.key_fingerprint(two_at_once))
check("a first statement that enrols two credentials at once is refused", r.get("reason") == "key_statement_malformed", r)
with serve({**used.chain[0], "recipient_id": "bob"}, used.devices[0]):
    r = run("pin", "dana", "--fingerprint", used.fingerprint())
check("a statement made for another recipient is refused", r.get("reason") == "key_statement_malformed", r)


def other_enc_key(method, path, status, reply):
    if path.endswith("/keys"):
        reply["enc_pubkey"] = b64u(other_enc)
    return status, reply


with lying(other_enc_key):
    r = run("pin", "dana", "--fingerprint", used.fingerprint())
check("an encryption key the service names beside the chain is refused", r.get("reason") == "keys_changed_without_statement", r)

# A credential that a later statement retires: what it signed before stays valid, what it signs after does not.
carol = Recipient("carol")
carol_phone, carol_laptop = Device("Carol phone"), Device("Carol laptop")
carol.enrol(carol_phone)
carol.enrol(carol_laptop)
run("pin", "carol", "--fingerprint", carol.fingerprint())
before = run("ask", "carol", "--text", "Before", "--ttl", "900")["request_id"]
after = run("ask", "carol", "--text", "After", "--ttl", "900")["request_id"]
carol.answer(before, {"choice": "A"}, device=carol_laptop, signed_offset=-200)
carol.answer(after, {"choice": "A"}, device=carol_laptop)
retiring = {"type": "hitl.key-statement", "version": 2, "recipient_id": "carol", "epoch": 1, "seq": 3,
            "prev": caller.statement_hash(carol.chain[-1]), "enc_pubkey": b64u(carol.pk), "credentials": [carol_phone.cred()],
            "issued_at": now(-100)}
with serve(retiring, carol_phone):
    r0 = run("refresh", "carol")
    r1, r2 = verdict(before), verdict(after)
check("a retired credential still verifies what it signed before, and nothing it signs after",
      r0.get("devices") == 1 and r1.get("status") == "answered" and r2.get("reason") == "unpinned_key", (r0, r1, r2))

# ---- what verify_deployment makes of a shell

manifest_files = json.load(open(os.path.join(ROOT, "server", "public", "assets", "release", "manifest.json")))["files"]
status, raw, shell_headers, _ = wsgi("GET", "/r/AAAAAAAAAAAAAAAA")
shell = raw.decode()
headers_low = {k.lower(): v for k, v in shell_headers.items()}
# The manifest may be older than the client files (it is signed at release); the structure checks do not depend on that.
for path_ in manifest_files:
    manifest_files[path_]["sri"] = "sha384-" + caller.base64.b64encode(
        caller.hashlib.sha384(open(os.path.join(ROOT, "server", "public", "assets", path_), "rb").read()).digest()).decode()
check("the genuine shell passes", verifier.shell_problem(shell, headers_low, manifest_files) == "", verifier.shell_problem(shell, headers_low, manifest_files))
for name, bad, bad_headers in (
        ("a script in capitals", shell.replace("</body>", '<SCRIPT SRC="/evil.js"></SCRIPT></body>'), headers_low),
        ("a script without integrity", shell.replace("</body>", '<script src="/assets/app.js"></script></body>'), headers_low),
        ("an inline script", shell.replace("</body>", "<script>fetch('/x')</script></body>"), headers_low),
        ("an inline handler", shell.replace("<main", '<img src=x onerror="fetch(1)"><main'), headers_low),
        ("another pdf.js module", _re_sub := shell.replace('data-pdfjs="/assets/vendor/pdfjs/pdf.min.mjs', 'data-pdfjs="/evil.mjs'), headers_low),
        ("no content security policy", shell, {k: v for k, v in headers_low.items() if k != "content-security-policy"}),
        ("a policy that allows inline script", shell, {**headers_low, "content-security-policy": headers_low["content-security-policy"].replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")})):
    check(f"a shell with {name} fails", verifier.shell_problem(bad, bad_headers, manifest_files) != "")

with contextlib.redirect_stderr(io.StringIO()):
    no_anchor = verifier.main(["verify_deployment.py", ORIGIN])
check("verify_deployment refuses to run with neither a checkout nor a key to compare against", no_anchor == 64, no_anchor)
check("the repository ships a manifest that matches its client files, and no key or signature",
      {k: v["sri"] for k, v in json.load(open(os.path.join(ROOT, "server", "public", "assets", "release", "manifest.json")))["files"].items()}
      == {k: v["sri"] for k, v in manifest_files.items()}
      and not os.path.exists(os.path.join(ROOT, "server", "public", "assets", "release", "manifest.sig"))
      and not os.path.exists(os.path.join(ROOT, "docs", "release-key.pub")))

old_db = os.path.join(TMP, "old.sqlite")
con = sqlite3.connect(old_db)
con.execute("CREATE TABLE requests (id TEXT PRIMARY KEY, nonce TEXT)")
con.commit()
con.close()
os.environ["HITL_DB"] = old_db
lib._local.conn = None
try:
    lib.db()
    refused = False
except RuntimeError:
    refused = True
check("a database from before protocol version 2 is refused, not read as if it were current", refused)

print("\nall checks passed" if failures == 0 else f"\n{failures} check(s) failed")
sys.exit(0 if failures == 0 else 1)
