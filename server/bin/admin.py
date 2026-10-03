#!/usr/bin/env python3
"""Operator commands for a deployment: register callers, issue enrolment links."""

import os
import re
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from hitl.lib import HttpError, b64u, event, iso_at, now, origin, q, rows, token_hash, transaction, unb64u  # noqa: E402

USAGE = """Usage:
  admin.py add-caller <caller_id> <display_name> <display_domain> <pubkey_b64url>
  admin.py enrol-link <recipient_id> <display_name> [hours=24]
  admin.py reset-recipient <recipient_id>        recovery when no enrolled device survives
  admin.py list
"""
ID = re.compile(r"[a-z0-9._-]{1,64}")


def usage():
    sys.stderr.write(USAGE)
    sys.exit(64)


def fail(msg: str):
    sys.stderr.write(msg + "\n")
    sys.exit(65)


def main(args: list[str]) -> None:
    cmd = args.pop(0) if args else ""
    if cmd == "add-caller":
        if len(args) != 4:
            usage()
        id_, name, domain, pub = args
        try:
            ok = ID.fullmatch(id_) and len(unb64u(pub)) == 32
        except HttpError:
            ok = False
        if not ok:
            fail("invalid caller id or public key")
        q("""INSERT INTO callers (id, display_name, display_domain, pubkey, verified_since) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, display_domain = excluded.display_domain,
             pubkey = excluded.pubkey""", (id_, name, domain, pub, now()))
        print(f"caller {id_} registered")

    elif cmd == "enrol-link":
        if len(args) < 2:
            usage()
        id_, name = args[0], args[1]
        m = re.match(r"^\s*([+-]?\d+)", args[2]) if len(args) > 2 else None
        hours = int(m.group(1)) if m else (24 if len(args) <= 2 else 0)
        if not ID.fullmatch(id_) or hours < 1 or hours > 168:
            fail("invalid recipient id or hours")
        q("""INSERT INTO recipients (id, display_name, created_at) VALUES (?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name""", (id_, name, now()))
        token = b64u(secrets.token_bytes(24))
        q("INSERT INTO enrol_tokens (token_hash, recipient_id, expires_at) VALUES (?, ?, ?)",
          (token_hash(token), id_, iso_at(time.time() + hours * 3600)))
        event("hitl.recipient.enrol_started", None, None, {"recipient_id": id_, "via": "operator-link"})
        print(f"{origin()}/enroll/{token}")

    elif cmd == "reset-recipient":
        # Recovery with no surviving device (spec, Recipient keys): retire every credential and
        # drop the encryption key, so the person enrols again from scratch. Requests encrypted to
        # the old key stay unreadable. The new enrolment starts a new epoch with its own chain from
        # sequence 1; callers never follow a change of epoch on their own and must pin again, out of
        # band. Enrolment links issued before the reset die with it.
        if len(args) != 1:
            usage()
        id_ = args[0]
        if not rows("SELECT 1 FROM recipients WHERE id = ?", (id_,)):
            fail(f"unknown recipient {id_}")
        with transaction():
            n = q("UPDATE credentials SET retired_at = ? WHERE recipient_id = ? AND retired_at IS NULL", (now(), id_)).rowcount
            q("UPDATE recipients SET enc_pubkey = NULL, epoch = epoch + 1 WHERE id = ?", (id_,))
            q("DELETE FROM enrol_tokens WHERE recipient_id = ?", (id_,))
            event("hitl.recipient.reset", None, None, {"recipient_id": id_, "retired_credentials": n})
        print(f"recipient {id_} reset: {n} credential(s) retired; enrol again, then callers re-pin")

    elif cmd == "list":
        for c in rows("SELECT id, display_name, display_domain FROM callers ORDER BY id"):
            print(f"caller     {c['id']}  {c['display_name']} ({c['display_domain']})")
        for r in rows("""SELECT r.id, r.display_name, COUNT(c.id) AS n FROM recipients r
                         LEFT JOIN credentials c ON c.recipient_id = r.id AND c.retired_at IS NULL
                         GROUP BY r.id ORDER BY r.id"""):
            print(f"recipient  {r['id']}  {r['display_name']}  credentials={r['n']}")

    else:
        usage()


if __name__ == "__main__":
    main(sys.argv[1:])
