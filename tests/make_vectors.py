#!/usr/bin/env python3
"""Writes tests/vectors/protocol.json: signed objects, assertions and key statement chains that
the three implementations (service, caller library, web client) must judge the same way.

  python tests/make_vectors.py

The keys are made here and thrown away, so every run gives a different file with the same
meaning; the checked-in file is one such run. What each vector expects is fixed by how it was
built (which one thing was made wrong), never by asking an implementation. Canonical strings
and hashes are computed with json.dumps over ASCII-only objects with sorted keys, which for
such objects is the JCS encoding, so they do not depend on the code under test either.
"""

import base64
import calendar
import copy
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ORIGIN = "https://vectors.example"
RP_ID = "vectors.example"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canon(o: object) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def digest(o: object) -> bytes:
    return hashlib.sha256(canon(o).encode()).digest()


class Device:
    def __init__(self, name: str, kind: str = "p256"):
        self.key = {"p256": lambda: ec.generate_private_key(ec.SECP256R1()),
                    "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
                    "rsa2048": lambda: rsa.generate_private_key(65537, 2048),
                    "rsa1024": lambda: rsa.generate_private_key(65537, 1024)}[kind]()
        self.alg = -257 if kind.startswith("rsa") else -7
        self.id = name
        self.spki = b64u(self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo))

    def cred(self) -> dict:
        return {"id": self.id, "spki": self.spki, "alg": self.alg, "label": self.id.title()}

    def assertion(self, challenge: bytes, origin: str = ORIGIN, rp_id: str = RP_ID, flags: int = 0x05,
                  kind: str = "webauthn.get", cross: bool = False) -> dict:
        cdj = json.dumps({"type": kind, "challenge": b64u(challenge), "origin": origin, "crossOrigin": cross}).encode()
        ad = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + b"\x00\x00\x00\x01"
        data = ad + hashlib.sha256(cdj).digest()
        if isinstance(self.key, rsa.RSAPrivateKey):
            sig = self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        else:
            sig = self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        return {"credential_id": self.id, "client_data_json": b64u(cdj), "authenticator_data": b64u(ad), "signature": b64u(sig)}


def main() -> None:
    h32 = b64u(bytes(range(32)))

    # ---- objects: exactly the fields of their type
    request = {"type": "hitl.request", "version": 2, "request_id": "3f0e8a52-6c1d-4b7e-9a35-0d2c4e6f8a10",
               "caller_id": "caller", "recipient_id": "person", "config_ct_hash": h32, "payload_ct_hash": h32,
               "answer_pubkey": h32, "ttl": 3600, "caller_ref": "task:42", "created_at": "2026-10-03T10:00:00Z",
               "policy": {"assurance": "session", "max_session_age": 3600, "review": True}, "blobs": []}
    response = {"type": "hitl.response", "version": 2, "request_id": request["request_id"], "creation_hash": b64u(digest(request)),
                "config_hash": h32, "payload_hash": h32, "answer_ct": "AAAA", "signed_at": "2026-10-03T10:05:00Z"}
    session = {"version": 1, "type": "hitl.session", "recipient_id": "person", "session_pubkey": h32,
               "issued_at": "2026-10-03T10:00:00Z", "expires_at": "2026-10-03T22:00:00Z"}
    blob = {"type": "hitl.blob", "version": 2, "caller_id": "caller", "sha256": "00" * 32, "size": 1, "created_at": "2026-10-03T10:00:00Z"}

    one, two, three, outsider = Device("device-1"), Device("device-2", "rsa2048"), Device("device-3"), Device("outsider")
    enc = b64u(bytes(range(32, 64)))

    def statement(seq: int, prev: dict | None, devices: list[Device]) -> dict:
        return {"type": "hitl.key-statement", "version": 2, "recipient_id": "person", "epoch": 1, "seq": seq,
                "prev": b64u(digest(prev)) if prev else "", "enc_pubkey": enc,
                "credentials": sorted((d.cred() for d in devices), key=lambda c: c["id"]), "issued_at": "2026-10-03T09:00:00Z"}

    def item(st: dict, signer: Device) -> dict:
        return {"seq": st["seq"], "statement": st, "assertion": signer.assertion(digest(st))}

    s1 = statement(1, None, [one])
    s2 = statement(2, s1, [one, two])
    s3 = statement(3, s2, [one, two, three])
    chain = [item(s1, one), item(s2, one), item(s3, two)]

    shapes = []
    for name, good, extra in (("request", request, []), ("response", response, []), ("session", session, []),
                              ("blob", blob, []), ("key statement", s1, [])):
        shapes.append({"name": name, "type": good["type"], "extra": extra, "object": good, "ok": True})
        shapes.append({"name": name + " with a field too many", "type": good["type"], "extra": extra, "object": {**good, "note": "x"}, "ok": False})
        missing = dict(good)
        missing.pop(sorted(k for k in good if k not in ("type", "version"))[0])
        shapes.append({"name": name + " with a field missing", "type": good["type"], "extra": extra, "object": missing, "ok": False})
        last = dict(good)
        last.pop(sorted(good)[-1])
        shapes.append({"name": name + " with its last field missing", "type": good["type"], "extra": extra, "object": last, "ok": False})
        shapes.append({"name": name + " with a field too many, sorting last", "type": good["type"], "extra": extra, "object": {**good, "zzz": "x"}, "ok": False})
        shapes.append({"name": name + " with the right fields under another type", "type": good["type"], "extra": extra, "object": {**good, "type": "hitl.other"}, "ok": False})
        shapes.append({"name": name + " of another version", "type": good["type"], "extra": extra, "object": {**good, "version": good["version"] + 1}, "ok": False})
        shapes.append({"name": name + " with its version as a string", "type": good["type"], "extra": extra, "object": {**good, "version": str(good["version"])}, "ok": False})
        shapes.append({"name": name + " with its version as true", "type": good["type"], "extra": extra, "object": {**good, "version": True}, "ok": False})
    shapes.append({"name": "request passed off as a response", "type": "hitl.response", "extra": [], "object": request, "ok": False})
    shapes.append({"name": "response with the recipient's copy, where review asks for it", "type": "hitl.response", "extra": ["answer_self_ct"],
                   "object": {**response, "answer_self_ct": "AAAA"}, "ok": True})
    shapes.append({"name": "response with the recipient's copy, where nothing asks for it", "type": "hitl.response", "extra": [],
                   "object": {**response, "answer_self_ct": "AAAA"}, "ok": False})
    shapes.append({"name": "response without the recipient's copy, where review asks for it", "type": "hitl.response", "extra": ["answer_self_ct"],
                   "object": response, "ok": False})
    shapes.append({"name": "a list", "type": "hitl.response", "extra": [], "object": [response], "ok": False})
    shapes.append({"name": "null", "type": "hitl.response", "extra": [], "object": None, "ok": False})

    hashed = [{"name": n, "object": o, "canonical": canon(o), "sha256": b64u(digest(o))}
              for n, o in (("creation body", request), ("response record", response), ("session delegation", session),
                           ("first key statement", s1), ("third key statement", s3))]

    times = [{"value": v, "seconds": calendar.timegm(time.strptime(v, "%Y-%m-%dT%H:%M:%SZ"))}
             for v in ("2026-10-03T10:00:00Z", "1970-01-01T00:00:00Z", "2099-12-31T23:59:59Z")]
    times += [{"value": v, "seconds": None} for v in (
        "2026-10-03T10:00:00+00:00", "2026-10-03T10:00:00z", "2026-10-03T10:00:00.000Z", "2026-10-03 10:00:00Z",
        "2026-10-03T10:00:00", "2026-13-03T10:00:00Z", " 2026-10-03T10:00:00Z", "", 1790935200, None,
        # each of these names an instant that has another, proper spelling, or none
        "2026-10-03T10:00:60Z", "2026-10-03T24:00:00Z", "2026-02-30T10:00:00Z", "0000-01-01T00:00:00Z", "1969-12-31T23:59:59Z")]

    # ---- padding (ISO/IEC 7816-4 to a multiple of 4096, as sodium_pad)
    def padded(plain: bytes) -> bytes:
        return plain + b"\x80" + b"\x00" * (4096 - len(plain) % 4096 - 1)

    pads = [{"name": n, "plain": b64u(p), "padded": b64u(padded(p))} for n, p in (
        ("empty", b""), ("one byte", b"a"), ("a short answer", b'{"choice":"approve"}'), ("one byte short of a block", b"x" * 4095),
        ("exactly a block", b"x" * 4096), ("ends in the marker byte", b"x\x80"), ("ends in zeros", b"x\x00\x00"))]
    bad_pads = [{"name": n, "padded": b64u(p)} for n, p in (
        ("nothing", b""), ("not a multiple of the block", b"a\x80" + b"\x00" * 100), ("a block of zeros", b"\x00" * 4096),
        ("no marker", b"a" * 4096), ("the marker a whole block before the end", b"a\x80" + b"\x00" * 8190))]

    # ---- assertions
    challenge = digest(response)
    good = one.assertion(challenge)

    def changed(a: dict, field: str) -> dict:
        raw = bytearray(base64.urlsafe_b64decode(a[field] + "=" * (-len(a[field]) % 4)))
        raw[-1] ^= 1
        return {**a, field: b64u(bytes(raw))}

    def reencoded(a: dict, how: str) -> dict:
        """The same signature in an encoding that is not DER: a strict verifier refuses it, and all three must be strict."""
        der = base64.urlsafe_b64decode(a["signature"] + "=" * (-len(a["signature"]) % 4))
        assert der[0] == 0x30 and der[1] < 0x80
        if how == "long length":
            der = bytes([0x30, 0x81, der[1]]) + der[2:]
        elif how == "zero":  # a zero in front of r that its sign does not need
            n = der[3]
            der = bytes([0x30, der[1] + 1, 0x02, n + 1, 0x00]) + der[4:]
        elif how == "no sign byte":  # r without the zero its sign needs: a negative number
            assert der[3] == 33 and der[4] == 0
            der = bytes([0x30, der[1] - 1, 0x02, 32]) + der[5:]
        else:  # a byte after s, inside the sequence
            der = bytes([0x30, der[1] + 1]) + der[2:] + bytes(1)
        return {**a, "signature": b64u(der)}

    # A signature whose r needs no sign byte, so that adding one is a pure re-encoding.
    plain_r = good
    while base64.urlsafe_b64decode(plain_r["signature"] + "==")[4] & 0x80 or base64.urlsafe_b64decode(plain_r["signature"] + "==")[3] != 32:
        plain_r = one.assertion(challenge)

    signed_r = good
    while base64.urlsafe_b64decode(signed_r["signature"] + "==")[3] != 33:
        signed_r = one.assertion(challenge)

    p384, weak = Device("p384", "p384"), Device("weak", "rsa1024")
    assertions = [
        {"name": "ES256, valid", "credential": one.cred(), "assertion": good, "problem": None},
        {"name": "RS256 with 2048 bits, valid", "credential": two.cred(), "assertion": two.assertion(challenge), "problem": None},
        {"name": "another challenge", "credential": one.cred(), "assertion": one.assertion(digest(request)), "problem": "challenge_mismatch"},
        {"name": "another origin", "credential": one.cred(), "assertion": one.assertion(challenge, origin="https://evil.example"), "problem": "origin_mismatch"},
        {"name": "cross-origin", "credential": one.cred(), "assertion": one.assertion(challenge, cross=True), "problem": "origin_mismatch"},
        {"name": "another relying party", "credential": one.cred(), "assertion": one.assertion(challenge, rp_id="evil.example"), "problem": "rp_id_mismatch"},
        {"name": "a registration, not an assertion", "credential": one.cred(), "assertion": one.assertion(challenge, kind="webauthn.create"), "problem": "client_data_type"},
        {"name": "user not present", "credential": one.cred(), "assertion": one.assertion(challenge, flags=0x04), "problem": "not_user_present"},
        {"name": "user not verified", "credential": one.cred(), "assertion": one.assertion(challenge, flags=0x01), "problem": "not_user_verified"},
        {"name": "signature changed", "credential": one.cred(), "assertion": changed(good, "signature"), "problem": "signature_invalid"},
        {"name": "authenticator data changed after signing", "credential": one.cred(), "assertion": changed(good, "authenticator_data"), "problem": "signature_invalid"},
        {"name": "signed by another key", "credential": one.cred(), "assertion": {**outsider.assertion(challenge), "credential_id": one.id}, "problem": "signature_invalid"},
        {"name": "a P-256 key declared as RS256", "credential": {**one.cred(), "alg": -257}, "assertion": good, "problem": "signature_invalid"},
        {"name": "an RSA key declared as ES256", "credential": {**two.cred(), "alg": -7}, "assertion": two.assertion(challenge), "problem": "signature_invalid"},
        {"name": "a P-384 key declared as ES256", "credential": p384.cred(), "assertion": p384.assertion(challenge), "problem": "signature_invalid"},
        {"name": "an RSA key of 1024 bits", "credential": weak.cred(), "assertion": weak.assertion(challenge), "problem": "signature_invalid"},
        {"name": "a signature with its length in the long form", "credential": one.cred(), "assertion": reencoded(good, "long length"), "problem": "signature_invalid"},
        {"name": "a signature with a needless leading zero", "credential": one.cred(), "assertion": reencoded(plain_r, "zero"), "problem": "signature_invalid"},
        {"name": "a signature whose r lost its sign byte", "credential": one.cred(), "assertion": reencoded(signed_r, "no sign byte"), "problem": "signature_invalid"},
        {"name": "a signature with a byte after s", "credential": one.cred(), "assertion": reencoded(good, "trailing"), "problem": "signature_invalid"},
        {"name": "an algorithm that is not offered", "credential": {**one.cred(), "alg": -8}, "assertion": good, "problem": "signature_invalid"},
    ]

    # ---- key statement chains, replayed from a device's anchor (the page) and from sequence 1 (a caller's pin)
    def anchor(st: dict) -> dict:
        return {"epoch": st["epoch"], "seq": st["seq"], "hash": b64u(digest(st))}

    def result(items: list[dict]) -> dict:
        last = items[-1]["statement"]
        hexed = digest(last).hex()[:32]
        return {"epoch": last["epoch"], "seq": last["seq"], "head": b64u(digest(last)), "credentials": last["credentials"],
                "enc_pubkey": enc, "fingerprint": " ".join(hexed[i:i + 4] for i in range(0, 32, 4))}

    def variant(change) -> list[dict]:
        items = copy.deepcopy(chain)
        change(items)
        return items

    def resign(items: list[dict], n: int, signer: Device) -> None:
        items[n] = item(items[n]["statement"], signer)

    def intruder(items: list[dict]) -> None:
        st = items[2]["statement"]
        st["credentials"] = sorted(st["credentials"] + [outsider.cred()], key=lambda c: c["id"])
        resign(items, 2, outsider)

    def with_prev(items: list[dict]) -> None:
        items[2]["statement"]["prev"] = b64u(digest(s1))
        resign(items, 2, two)

    def with_epoch(items: list[dict]) -> None:
        items[2]["statement"]["epoch"] = 2
        resign(items, 2, two)

    def with_enc(items: list[dict]) -> None:
        items[2]["statement"]["enc_pubkey"] = h32
        resign(items, 2, two)

    def with_note(items: list[dict]) -> None:
        items[2]["statement"]["note"] = "x"
        resign(items, 2, two)

    def unsorted(items: list[dict]) -> None:
        items[2]["statement"]["credentials"].reverse()
        resign(items, 2, two)

    def unlabelled(items: list[dict]) -> None:
        items[2]["statement"]["credentials"][0].pop("label")
        resign(items, 2, two)

    def noted_device(items: list[dict]) -> None:
        items[2]["statement"]["credentials"][0]["note"] = "x"
        resign(items, 2, two)

    def jumping(items: list[dict]) -> None:
        items[2]["statement"]["seq"] = 5
        resign(items, 2, two)

    def for_another(items: list[dict]) -> None:
        items[2]["statement"]["recipient_id"] = "someone-else"
        resign(items, 2, two)

    def skipping(items: list[dict]) -> None:
        del items[1]

    chains = [
        {"name": "from the first device's anchor", "anchor": anchor(s1), "items": chain, "result": result(chain)},
        {"name": "from the second device's anchor", "anchor": anchor(s2), "items": chain[1:], "result": result(chain)},
        {"name": "from the newest device's anchor, nothing after it", "anchor": anchor(s3), "items": chain[2:], "result": result(chain)},
        {"name": "the service withholds the newest statement", "anchor": anchor(s1), "items": chain[:2], "result": result(chain[:2])},
        {"name": "no statements at all", "anchor": anchor(s1), "items": [], "result": None},
        {"name": "the anchor statement is not the one the device remembers", "anchor": {**anchor(s1), "hash": h32}, "items": chain, "result": None},
        {"name": "a credential the service added, signed by itself", "anchor": anchor(s1), "items": variant(intruder), "result": None},
        {"name": "a statement signed by a device that was not yet in the set", "anchor": anchor(s1), "items": variant(lambda i: resign(i, 1, two)), "result": None},
        {"name": "a statement signed by a device outside the set", "anchor": anchor(s1), "items": variant(lambda i: resign(i, 2, outsider)), "result": None},
        {"name": "a statement that does not name the one before it", "anchor": anchor(s1), "items": variant(with_prev), "result": None},
        {"name": "a statement of another epoch", "anchor": anchor(s1), "items": variant(with_epoch), "result": None},
        {"name": "a statement that swaps the encryption key", "anchor": anchor(s1), "items": variant(with_enc), "result": None},
        {"name": "a statement with a field too many", "anchor": anchor(s1), "items": variant(with_note), "result": None},
        {"name": "a statement whose credentials are not sorted", "anchor": anchor(s1), "items": variant(unsorted), "result": None},
        {"name": "a statement with a device that has no label", "anchor": anchor(s1), "items": variant(unlabelled), "result": None},
        {"name": "a statement with a device entry that has a field too many", "anchor": anchor(s1), "items": variant(noted_device), "result": None},
        {"name": "a statement that skips a sequence number", "anchor": anchor(s1), "items": variant(jumping), "result": None},
        {"name": "a statement made for another recipient", "anchor": anchor(s1), "items": variant(for_another), "result": None},
        {"name": "a statement left out of the middle", "anchor": anchor(s1), "items": variant(skipping), "result": None},
        {"name": "a statement changed after it was signed", "anchor": anchor(s1),
         "items": variant(lambda i: i[2]["statement"].update(issued_at="2026-10-03T09:00:01Z")), "result": None},
    ]

    # ---- answers: what the page builds from what a person entered is what the caller accepts
    both = {"choices": [{"value": "ok", "label": "OK"}, {"value": "cancel", "label": "Cancel"}],
            "fields": [{"name": "qty", "label": "Quantity", "type": "number"}, {"name": "note", "label": "Note", "type": "text"}],
            "comment": {"max_length": 10}}
    answers = [
        {"name": "a choice alone", "schema": {"choices": both["choices"]}, "choice": "ok", "fields": None, "comment": None, "answer": {"choice": "ok"}},
        {"name": "a choice, optional fields left empty", "schema": both, "choice": "ok", "fields": {}, "comment": "", "answer": {"choice": "ok", "fields": {}}},
        {"name": "a choice, no fields object given at all", "schema": both, "choice": "ok", "fields": None, "comment": None, "answer": {"choice": "ok", "fields": {}}},
        {"name": "a choice with fields and a comment", "schema": both, "choice": "ok", "fields": {"qty": 3, "note": "x"}, "comment": "  fine  ",
         "answer": {"choice": "ok", "fields": {"qty": 3, "note": "x"}, "comment": "fine"}},
        {"name": "cancel drops the fields", "schema": both, "choice": "cancel", "fields": {"qty": 3}, "comment": "no", "answer": {"choice": "cancel", "comment": "no"}},
        {"name": "a comment cut to its limit", "schema": both, "choice": "ok", "fields": {}, "comment": "0123456789abc", "answer": {"choice": "ok", "fields": {}, "comment": "0123456789"}},
        {"name": "a form without choices", "schema": {"fields": both["fields"]}, "choice": None, "fields": {"qty": 1}, "comment": None, "answer": {"fields": {"qty": 1}}},
        {"name": "a comment where the schema has none", "schema": {"choices": both["choices"]}, "choice": "ok", "fields": None, "comment": "ignored", "answer": {"choice": "ok"}},
    ]

    out = {"note": "Written by tests/make_vectors.py; see there for how expectations are fixed.",
           "origin": ORIGIN, "rp_id": RP_ID, "recipient_id": "person", "enc_pubkey": enc,
           "shapes": shapes, "hashes": hashed, "timestamps": times, "padding": pads, "bad_padding": bad_pads,
           "challenge": b64u(challenge), "assertions": assertions, "chains": chains, "answers": answers}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "protocol.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(json.dumps({"status": "written", "path": "tests/vectors/protocol.json",
                      "vectors": sum(len(out[k]) for k in ("shapes", "hashes", "timestamps", "padding", "bad_padding", "assertions", "chains", "answers"))}))


if __name__ == "__main__":
    main()
