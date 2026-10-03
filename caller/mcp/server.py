"""hitl MCP bridge: lets an agent ask a person for a signed decision.

This process is a hitl caller. It holds the caller key and the pinned
recipient keys, and delegates every cryptographic step to caller/hitl.py,
so there is one implementation of the verification rules.

Tools:
  list_recipients  who can be asked (pinned recipients)
  ask_human        create a request; returns a link the agent must deliver
  check_human      pending, expired, or the verified answer with its proof

When an answer arrives, the watcher verifies and consumes it (exactly once) and
hands the full result, including the caller reference given to ask_human, to
the deployment through a delivery file. The deployment decides where the answer
goes, for example a comment on the work item named by the reference. A request
that expires, or whose answer fails verification, is delivered the same way with
that status, so the agent is never left waiting for something that cannot come.

The agent slug and the reference in a delivery file are what the agent said about
itself; the only identity this bridge verified is the token's, given as "caller".

Access: Bearer JWT of a machine identity listed in HITL_MCP_CALLERS
("identityId:name,..."), checked against the identity provider at
HITL_MCP_IDP_URL. With HITL_MCP_CALLERS empty the server refuses every call.
"""

import base64
import hashlib
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import uvicorn
from mcp.server.fastmcp import Context, FastMCP

log = logging.getLogger("hitl-mcp")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Loopback unless told otherwise; the Dockerfile sets 0.0.0.0.
HOST = os.environ.get("HITL_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8790"))
CALLER = os.environ.get("HITL_CALLER", "/app/hitl.py")
CALLER_TIMEOUT = 600  # a request with large attachments uploads them inside one run of the caller
STATE = os.environ.get("HITL_STATE", "/state")
# Longest link life ask_human grants, in minutes; the service has its own ceiling (HITL_MAX_TTL).
MAX_TTL_MINUTES = int(os.environ.get("HITL_MCP_MAX_TTL_MINUTES", "10080"))
IDP_URL = os.environ.get("HITL_MCP_IDP_URL", "").rstrip("/")
CALLERS = dict(
    pair.split(":", 1) for pair in os.environ.get("HITL_MCP_CALLERS", "").split(",") if ":" in pair
)
_VERIFIED: dict[str, float] = {}
_AGENT = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_REQUEST_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_RECIPIENT = re.compile(r"^[a-z0-9._-]{1,64}$")


def _identity(ctx: Context) -> tuple[str | None, str]:
    """(caller name, "") for a verified token, else (None, reason)."""
    request = getattr(ctx.request_context, "request", None)
    auth = request.headers.get("authorization", "") if request is not None else ""
    if not auth.lower().startswith("bearer "):
        return None, "a Bearer token is required"
    token = auth[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None, "the token is not a JWT"
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return None, "the token payload is unreadable"
    exp = float(payload.get("exp") or 0)
    if exp <= time.time():
        return None, "the token has expired"
    name = CALLERS.get(payload.get("identityId", ""))
    if not name:
        return None, "this identity may not use hitl"
    key = hashlib.sha256(token.encode()).hexdigest()
    if _VERIFIED.get(key, 0) > time.time():
        return name, ""
    req = urllib.request.Request(f"{IDP_URL}/api/v1/identities/details", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as r:
            ok = r.status == 200
    except urllib.error.HTTPError:
        ok = False
    except Exception as e:
        log.warning("identity provider unreachable: %s", e)
        return None, "the token could not be verified right now"
    if not ok:
        return None, "the identity provider rejected the token"
    _VERIFIED[key] = min(exp, time.time() + 300)
    return name, ""


def _run(*args: str) -> dict:
    """Runs the caller CLI; it always prints one JSON object."""
    try:
        p = subprocess.run([sys.executable, CALLER, *args], capture_output=True, text=True, timeout=CALLER_TIMEOUT,
                           env={**os.environ, "HITL_STATE": STATE})
    except subprocess.TimeoutExpired:
        return {"status": "hold", "reason": "caller_timeout"}
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        log.error("caller output unreadable: rc=%s out=%r err=%r", p.returncode, p.stdout[-500:], p.stderr[-500:])
        return {"status": "hold", "reason": "caller_failed"}


def _write(path: str, data: dict, mode: int) -> None:
    """Writes a JSON file with exactly this mode, whatever the process umask is."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, mode)


def _audit(request_id: str, data: dict) -> None:
    os.makedirs(f"{STATE}/mcp", 0o700, exist_ok=True)
    _write(f"{STATE}/mcp/{request_id}.json", data, 0o600)


def _denied(why: str) -> str:
    return json.dumps({"status": "error", "reason": f"not allowed: {why}"})


mcp = FastMCP(
    "hitl",
    instructions=(
        "Ask a person for a signed decision before an action that needs one. "
        "ask_human returns a link: deliver it to the person yourself over your usual channel. "
        "Pass the id of the work item the decision belongs to as reference. "
        "You do not need to wait or poll: when the person answers, the verified answer is "
        "delivered to that work item and you are woken as for any other work. "
        "Only the choice you offered as the go-ahead authorises the action; cancel never does. "
        "A delivered status of expired or rejected is not an approval: do not proceed. "
        "If a tool returns status hold, do not proceed and do not retry on your own: report to your operator."
    ),
    host=HOST,
    port=PORT,
)
mcp.settings.streamable_http_path = "/"


@mcp.tool()
def list_recipients(ctx: Context) -> str:
    """People you can ask. Only recipients whose keys this caller has pinned are listed."""
    who, why = _identity(ctx)
    if not who:
        return _denied(why)
    out = []
    pins = os.path.join(STATE, "pins")
    for name in sorted(os.listdir(pins)) if os.path.isdir(pins) else []:
        with open(os.path.join(pins, name)) as f:
            p = json.load(f)
        out.append({"recipient": p["recipient_id"], "devices": len(p["credentials"]), "pinned_at": p["pinned_at"]})
    return json.dumps({"status": "ok", "recipients": out})


@mcp.tool()
def ask_human(recipient: str, title: str, text: str, agent: str, choice_a: str = "Approve",
              choice_b: str = "Reject", allow_comment: bool = True, html: str = "",
              ttl_minutes: int = 1440, reference: str = "", choices: list[dict] | None = None,
              fields: list[dict] | None = None, attachments: list[dict] | None = None,
              assurance: str = "session", max_session_hours: int = 12, layout: str = "standard",
              allow_review: bool = False, ctx: Context = None) -> str:
    """Ask one person to take part: decide, choose, review, or fill in a short form.
    The content is encrypted to them.

    The person sees your title, text, optional HTML and attachments (images, PDFs, video and
    audio are shown on the page, other files are offered for download), then answers with a button
    and/or a form. You get back a link: deliver it to the person over your usual channel.

    Args:
        recipient: recipient id from list_recipients
        title: one-line question, e.g. "Send the weekly report to the team?"
        text: what will happen if they approve, in plain words
        agent: your own agent slug, recorded with the request
        choice_a: label for answer A (the action)
        choice_b: label for answer B (the alternative, e.g. "Edit first")
        allow_comment: let the person add a short comment
        html: optional HTML fragment to show, e.g. the email body; no scripts
        ttl_minutes: how long the link stays valid, 15 minutes to the deployment maximum
            (HITL_MCP_MAX_TTL_MINUTES, 7 days unless raised; the service must allow it too)
        reference: the work item this decision belongs to, e.g. task:215; the answer is delivered there
        choices: buttons instead of choice_a/choice_b, e.g. [{"value": "v1", "label": "Layout 1"}, ...].
            An empty list [] means no buttons: the person fills the form and presses Submit.
        fields: form fields, e.g. [{"name": "qty", "label": "Quantity", "type": "number", "min": 1,
            "required": true}]. Types: text, textarea, number (whole), date, select, multiselect,
            checkbox; select and multiselect need "options": [{"value": ..., "label": ...}].
        assurance: "session" (default) lets an unlocked session on the person's device confirm the
            answer with no extra fingerprint; "fresh" requires a new device confirmation on this answer.
            Use fresh for payments, contracts and anything hard to undo.
        max_session_hours: with session, the oldest session (1 to 24 hours) you accept.
        layout: "standard" (simple black and white page) or "full": your html is the whole page.
            In a full design, mark controls with data-hitl-field="<field name>", clickable
            options with data-hitl-choice="<value>", and use src="hitl:f0" (f0, f1, ... in
            attachment order) for attached images and video. No scripts; the person confirms
            in a bar that shows exactly what will be signed.
        allow_review: let the person open the link again after answering and see the request with
            their answer, read-only (for example to look up what they approved). Default off.
        attachments: files to show, e.g. [{"name": "label.png", "content_base64": "..."}]; optional
            "mime" and "caption". Shown in the given order after the text.
    """
    who, why = _identity(ctx)
    if not who:
        return _denied(why)
    agent = (agent or "").strip().lower()
    if not _AGENT.match(agent):
        return json.dumps({"status": "error", "reason": "agent must be your slug"})
    if not _RECIPIENT.match(recipient or ""):
        return json.dumps({"status": "error", "reason": "unknown recipient"})
    ttl = max(15, min(int(ttl_minutes), MAX_TTL_MINUTES)) * 60
    reference = (reference or "").strip()
    if len(reference) > 200 or not all(32 <= ord(ch) < 127 for ch in reference):
        return json.dumps({"status": "error", "reason": "reference must be at most 200 printable ASCII characters"})
    if choices is None:
        choices = [{"value": "A", "label": choice_a[:60]}, {"value": "B", "label": choice_b[:60]},
                   {"value": "cancel", "label": "Cancel"}]
    answers = {"choices": choices}
    if fields:
        answers["fields"] = fields
    if allow_comment:
        answers["comment"] = {"max_length": 500}
    blocks = [{"type": "text", "text": text[:4000]}] if text else []
    if html:
        blocks.append({"type": "html", "html": html[:200000]})
    with tempfile.TemporaryDirectory() as tmp:
        attach_args = []
        for i, a in enumerate(attachments or []):
            name = os.path.basename(str(a.get("name") or f"attachment-{i}"))[:100] or f"attachment-{i}"
            try:
                data = base64.b64decode(a.get("content_base64") or "", validate=True)
            except Exception:
                return json.dumps({"status": "error", "reason": f"attachment {name}: content_base64 is not valid base64"})
            ref = f"f{i}"
            path = os.path.join(tmp, f"{i}-{name}")
            with open(path, "wb") as f:
                f.write(data)
            attach_args += ["--attach", f"{ref}={path}"]
            mime = (a.get("mime") or "").lower()
            low = name.lower()
            kind = ("image" if mime.startswith("image/") or low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp"))
                    else "pdf" if mime == "application/pdf" or low.endswith(".pdf")
                    else "video" if mime.startswith("video/") or low.endswith((".mp4", ".webm", ".mov"))
                    else "audio" if mime.startswith("audio/") or low.endswith((".mp3", ".m4a", ".wav", ".ogg"))
                    else "file")
            block = {"type": kind, "ref": ref, "name": name}
            if a.get("caption"):
                block["caption"] = str(a["caption"])[:300]
            blocks.append(block)
        manifest = {"title": title[:200], "blocks": blocks, "answers": answers}
        if layout == "full":
            manifest["layout"] = "full"
            if html:
                # The design is the page: attachments are used from it via hitl: references.
                manifest["blocks"] = [b for b in blocks if b["type"] == "html"]
        mpath = os.path.join(tmp, "manifest.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f)
        if assurance not in ("session", "fresh"):
            return json.dumps({"status": "error", "reason": "assurance must be session or fresh"})
        policy = ["--assurance", assurance]
        if assurance == "session":
            policy += ["--max-session-age", f"{max(1, min(int(max_session_hours), 24))}h"]
        if allow_review:
            policy += ["--review"]
        res = _run("ask", recipient, "--manifest", mpath, "--ref", reference, "--ttl", str(ttl), *policy, *attach_args)
    if res.get("status") == "created" or (res.get("status") == "hold" and res.get("request_id")):
        # A hold with a request id: the service may hold the request although no link came back.
        # It is recorded like any other, so its outcome (most likely expired) is still delivered.
        _audit(res["request_id"], {"caller": who, "agent": agent, "reference": reference, "title": title[:200],
                                   "recipient": recipient, "created": {"request_id": res["request_id"]}})
    if res.get("status") == "created":
        res["next"] = ("Send this link to the recipient yourself, then carry on or stop. "
                       "The verified answer will be delivered to your reference and you will be woken; "
                       "do not poll.")
        log.info("ask_human %s by %s/%s for %s", res["request_id"], who, agent, recipient)
    return json.dumps(res)


def _answer_tool(command: str, request_id: str, ctx: Context) -> str:
    who, why = _identity(ctx)
    if not who:
        return _denied(why)
    if not _REQUEST_ID.match(request_id or ""):
        return json.dumps({"status": "error", "reason": "invalid request id"})
    # A request is visible to the identity that made it and to no other user of the bridge.
    try:
        with open(f"{STATE}/mcp/{request_id}.json") as f:
            owner = json.load(f).get("caller")
    except (OSError, ValueError):
        owner = None
    if owner != who:
        return json.dumps({"status": "error", "reason": "unknown request id"})
    return json.dumps(_run(command, request_id))


@mcp.tool()
def check_human(request_id: str, ctx: Context = None) -> str:
    """Whether the person answered: pending, expired, or answered with the verified
    answer and its proof. Not needed in normal work (the answer is delivered to your
    reference); useful to look at a request by hand."""
    return _answer_tool("check", request_id, ctx)



WAKE_DIR = os.environ.get("HITL_MCP_WAKE_DIR", "")
WAKE_MODE = 0o640
# Refusals that say the service did not give a usable reply, not that an answer failed verification.
# They are waited out like an unreachable service: the request still ends, by the caller's own clock.
NOT_AN_ANSWER = ("unknown_request", "statements_unavailable", "unknown_recipient")
POLL_SECONDS = int(os.environ.get("HITL_MCP_POLL_SECONDS", "30"))


def _watch() -> None:
    """Notices answers and expiries of requests made through ask_human. An answer is
    verified and consumed here, exactly once, and the full result (answer, label,
    reference, proof) is written as one delivery file per request into
    HITL_MCP_WAKE_DIR. Delivering it (to the work item, waking the agent) is the
    deployment's business."""
    audit_dir = f"{STATE}/mcp"
    while True:
        time.sleep(POLL_SECONDS)
        try:
            names = sorted(os.listdir(audit_dir)) if os.path.isdir(audit_dir) else []
        except OSError:
            continue
        for name in names:
            path = os.path.join(audit_dir, name)
            try:
                with open(path) as f:
                    a = json.load(f)
                if a.get("settled"):
                    continue
                rid = a["created"]["request_id"]
                res = _run("check", rid)
                if res.get("status") == "answered" and not res.get("consumed"):
                    consumed = _run("consume", rid)
                    # Anything but the answer itself (a timeout, a hold) is tried again on the next
                    # round. If the marker was written and the reply lost, check then says consumed
                    # and its verified result is what gets delivered: never a replay refusal in
                    # place of the approval it stands for.
                    if consumed.get("status") != "answered":
                        continue
                    res = consumed
                # pending and hold are waited out: the caller library itself reports expired, by its
                # own clock, once the deadline has passed, whether or not the service can be reached.
                # rejected is final when an answer failed verification: it authorises nothing.
                if res.get("status") not in ("answered", "expired", "rejected"):
                    continue
                if res.get("status") == "rejected" and res.get("reason") in NOT_AN_ANSWER:
                    continue
                if res.get("status") == "rejected":
                    log.warning("request %s rejected by verification: %s", rid, res.get("reason"))
                if WAKE_DIR:
                    wake = {"caller": a.get("caller", ""), "agent": a["agent"], "request_id": rid, "recipient": a["recipient"],
                            "reference": a.get("reference", ""), "title": a.get("title", ""), **res}
                    tmp = os.path.join(WAKE_DIR, f".{name}.tmp")
                    # The file holds the answer and its proof: readable by the owner and the group
                    # the deployment's consumer runs in, by nobody else, writable by the owner only.
                    _write(tmp, wake, WAKE_MODE)
                    os.rename(tmp, os.path.join(WAKE_DIR, name))
                a["settled"] = res["status"]
                _write(path, a, 0o600)
                log.info("request %s %s, wake queued for %s", a["created"]["request_id"], res["status"], a["agent"])
            except Exception as e:
                log.warning("watch %s: %s", name, e)


app = mcp.streamable_http_app()

if __name__ == "__main__":
    import threading
    threading.Thread(target=_watch, daemon=True).start()
    if not CALLERS or not IDP_URL:
        log.warning("HITL_MCP_CALLERS or HITL_MCP_IDP_URL is empty: every call will be refused")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
