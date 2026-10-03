# hitl MCP bridge

Lets an agent ask a person for a signed answer through three MCP tools. The bridge is a hitl caller: it holds the caller key and the pinned recipient keys, and runs `caller/hitl.py` for every cryptographic step, so there is one implementation of the verification rules.

## Tools

| Tool | What it does |
|---|---|
| `list_recipients` | The people this caller has pinned, and so can ask. |
| `ask_human` | Creates a request and returns a link. The agent delivers the link itself. |
| `check_human` | `pending`, `expired`, or the verified answer with its proof, for a request the same identity made. Not needed in normal work. |

`ask_human` takes the question (`title`, `text`, optional `html` and `attachments`), the allowed answers (`choice_a` and `choice_b`, or `choices`, and optional `fields`), and the policy (`assurance`, `max_session_hours`, `allow_review`, `ttl_minutes`). The tool's own description, which the agent sees, lists every argument.

## How an answer comes back

The agent does not wait or poll. A watcher in the bridge checks each open request every `HITL_MCP_POLL_SECONDS`. When a request is answered it verifies and consumes the answer, exactly once, and writes one file per request into `HITL_MCP_WAKE_DIR`:

```
<HITL_MCP_WAKE_DIR>/<request_id>.json
{"caller": "...", "agent": "...", "request_id": "...", "recipient": "...", "reference": "task:42", "title": "...",
 "status": "answered", "answer": {...}, "answer_label": "...", "assurance": "session", "proof_token": "...", ...}
```

A request that expires produces the same file with `"status": "expired"`, and one whose answer fails verification with `"status": "rejected"` and a `reason`. Neither is an approval. While the service cannot be reached, or answers without a usable reply, the bridge keeps waiting, and the request expires by the caller's own clock at its deadline. An answer that was verified and consumed is delivered as that answer even if the bridge was interrupted between the two steps. What happens to the file (which work item gets the answer, how the agent is woken) is the deployment's business. With `HITL_MCP_WAKE_DIR` unset nothing is written and the outcome is only available through `check_human`.

`caller` is the name of the identity whose token the bridge verified. `agent` and `reference` are what the agent said about itself and its work item; the bridge does not verify them, and the person sees the reference on the decision page before answering.

Delivery files are created with mode 0640: readable by the bridge's user and group, by nobody else. Run the consumer in that group. Whether it can remove a file depends on the directory, not on the file: give the group write access to the directory. The bridge's own records under `HITL_STATE/mcp/` are 0600.

## Setting up

1. Build from the repository root: `docker build -f caller/mcp/Dockerfile -t hitl-mcp .`
2. Create the caller identity in the directory that will be mounted at `/state`:
   `HITL_URL=https://decide.example.com HITL_STATE=./state python caller/hitl.py keygen my-bridge`
   and give the printed public key to the operator of the service (`admin.py add-caller`).
3. Pin each recipient the agents may ask, with the fingerprint the recipient reads to you from their own device:
   `HITL_URL=https://decide.example.com HITL_STATE=./state python caller/hitl.py pin alice --fingerprint "1a2b 3c4d ..."`
4. Run it with the state directory mounted and the settings below.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `HITL_URL` | none, required | Base URL of the hitl service. |
| `HITL_STATE` | `/state` | Caller state: key, pins, requests, consumed answers, and `mcp/` with one record per request. |
| `HITL_CALLER` | `/app/hitl.py` | Path of the caller CLI. |
| `HITL_MCP_HOST` | `127.0.0.1` | Address to listen on. The Dockerfile sets `0.0.0.0`. |
| `PORT` | `8790` | Port to listen on. |
| `HITL_MCP_CALLERS` | empty | Who may use the bridge: `identityId:name,identityId:name`. Empty means every call is refused. |
| `HITL_MCP_IDP_URL` | empty | Base URL of the identity provider. Empty means every call is refused. |
| `HITL_MCP_MAX_TTL_MINUTES` | `10080` | Longest link life `ask_human` grants. The service has its own ceiling, `HITL_MAX_TTL`. |
| `HITL_MCP_WAKE_DIR` | empty | Where delivery files are written. |
| `HITL_MCP_POLL_SECONDS` | `30` | How often open requests are checked. |

Extra CA certificates mounted into `/usr/local/share/ca-certificates` in the container are trusted at start.

## Who may call the bridge

Each MCP call must carry `Authorization: Bearer <JWT>`. The bridge accepts it when:

- the token has not expired,
- its `identityId` claim is listed in `HITL_MCP_CALLERS`,
- `GET <HITL_MCP_IDP_URL>/api/v1/identities/details` with the same token returns 200.

A verified token is remembered for at most five minutes. The bridge does not check the token's signature itself; it relies on the identity provider's answer.

This check fits identity providers that expose that endpoint and put `identityId` in the token. For another provider, change `_identity` in `server.py`: it is the only place that knows about the provider.
