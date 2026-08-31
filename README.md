# agent-lab — a sandbox whose way out is observable

A container running an agent that has **no physical path out except through the
proxy**, plus a full log of what it does: HTTP requests, file changes, git calls.

## Topology

```
 ┌──────────────── agentnet (bridge, 172.31.66.0/24) ────────────────┐
 │                                                                    │
 │   agent  172.31.66.3                 proxy  172.31.66.2            │
 │   ├─ claude code                     ├─ mitmproxy                  │
 │   ├─ HTTP(S)_PROXY → proxy:8080 ──►  │   :8080 regular             │
 │   ├─ default route → proxy      ──►  │   :8081 transparent ◄─ iptables
 │   ├─ hooks   → /logs/actions.jsonl   │   :8082 mitmweb (MITM_UI=web)
 │   └─ fswatch → /logs/actions.jsonl   └─ addon → /logs/traffic.jsonl│
 │                                            │                       │
 └────────────────────────────────────────────┼───────────────────────┘
                                              ▼ internet
```

Layers:

1. **env proxy** (`HTTP_PROXY`) — the sanctioned path: curl, git, npm, pip, and
   claude itself.
2. **transparent** — the agent's `default route` is rewritten to the proxy
   container, where `iptables` redirects all 80/443 from the agent subnet into
   mitm. This catches what the env proxy is blind to: `curl --noproxy '*'`, raw
   sockets, custom clients. Such requests are tagged `bypassed env proxy`.
3. **non-HTTP egress** — SSH, arbitrary ports, DNS-over-TCP to a foreign
   resolver: `FORWARD_OTHER=drop` cuts them at the proxy, because mitm cannot
   see them anyway.

## What the isolation rests on (and where it ends)

The route is installed by the `entrypoint` running as root, after which the agent
process starts as the unprivileged `agent` user. It cannot restore a direct
route: that needs `CAP_NET_ADMIN`, which an unprivileged process does not have.
Plus `no-new-privileges`.

The honest boundary: `docker compose exec -u root agent …` walks around all of
it. The isolation here is from the agent, not from the human at the keyboard.

The network is deliberately **not** `internal`. With `internal: true` Docker
attaches a rule to the bridge that drops packets destined outside the subnet, and
routing through a proxy container stops working — traffic never even reaches the
proxy. Instead the `entrypoint` **fails closed**: before starting the agent it
issues a canary request around the env proxy and checks that it landed in the log
as `transparent`. If it did not, the container does not come up (`AGENT_VERIFY=0`
removes the check). The worst outcome is not "the agent cannot reach the
network", it is "the agent can, and you cannot see it" — hence this particular
check.

## Running it

```bash
./lab up --build        # bring up the proxy and the agent
./lab claude            # run the agent in the sandbox (first run asks for /login)
```

Talk to the lab through `./lab`, not `docker compose exec` directly: `exec`
drops you into the container as **root**, and root there can rewrite the route
and slip past the proxy. `./lab` enters as `agent`. Run `./lab` with no arguments
for the full list.

The agent's working directory is `./workspace` (mounted at `/work`). The host's
`~/.ssh`, `~/.aws`, keys and other repositories are not visible to it. Claude
credentials live in the `agent-home` volume and survive a rebuild (`./lab reset`
wipes them).

## What to look at

```bash
./lab viewer            # browser view on http://127.0.0.1:8083
./lab watch             # the same timeline in the terminal
./lab timeline --since 15m -v
./lab summary           # by domain: how many requests, how many bytes left
./lab alerts            # leaks, floods and blocks only
./lab proxy-log         # raw mitmproxy stream
./lab status            # state plus a check that interception is alive
```

Sample timeline output:

```
14:22:07 ▸ TASK find Carlsen's games on chess.com
14:22:11 $ curl -s https://api.chess.com/pub/player/...
    14:22:11 → GET api.chess.com/pub/player/magnuscarlsen/games
14:22:19 $ python3 fetch_all.py
    14:22:19 → GET chess-club.example/games?p=1
    ...
    14:22:24 ⚑ request_flood  340 requests to chess-club.example in 10s
    14:22:26 → POST chess-club.example/api/search [812 B body]  LEAK? email, host_path
14:22:31 ✎ FILE created /work/games.json (+184320 B)
```

That stitching of "step × network" is what neither HTTP debuggers (they see only
traffic) nor MCP gateways (they see only MCP calls, not `curl`, not a push to a
remote, not the agent's browser) give you.

### The viewer

`./lab viewer` serves a single page that shows the same correlation live: agent
steps as headers, the requests that followed each one indented underneath, and
an activity strip along the top where a burst against one domain is a visible
spike. Clicking a request opens its detail — how it left (via the env proxy or
around it), how much was sent, what was flagged, and the stored body preview.

Three controls carry most of the value:

- **hide agent infra** (on by default) drops the agent's own control-plane
  chatter — the hosts the proxy has in `MITM_QUIET_HOSTS`. Without it, heartbeat
  and presence traffic buries everything the agent did to the outside world. The
  list comes from the proxy itself, so it always matches the running config.
- **flagged only** leaves just leaks, floods and blocks.
- **filter** matches on host, path, and the command of the step.

The server binds `127.0.0.1` and only reads the logs. That is deliberate: the
records hold decrypted bodies and live credentials, so nothing here should be
reachable from another machine.

### Logs

`logs/traffic.jsonl` — one record per request/response: method, host, path, body
size and preview, `findings`, and the `flood` / `blocked` flags.

`logs/actions.jsonl` — agent actions: prompts, every tool call (`Bash` with the
command, `Edit`/`Write` with the path, `WebFetch` with the url), and file changes
from the watcher. JSONL, easy to grep and to feed anywhere.

### What ends up in those logs

`traffic.jsonl` holds decrypted request and response content — that is the entire
point of the proxy, and it makes the file as sensitive as anything the agent
touched. Expect to find in it: `Authorization` headers with live tokens, API
keys, session cookies, private repository contents, and whatever went into a
prompt.

`.gitignore` keeps `logs/*.jsonl` out of commits. It does not stop you from
pasting an excerpt into an issue, a chat, or a talk slide. Scrub before sharing.

Hosts listed in `MITM_QUIET_HOSTS` are the exception: their bodies are never
written to disk and their headers are never scanned, because there the
credentials are the agent's own by design.

## Knobs

All via a `.env` next to `docker-compose.yml`, or inline.

| Variable | Default | Effect |
|---|---|---|
| `MITM_ALLOW_HOSTS` | empty | csv allowlist of domains; anything else → 403 + log entry. Empty = observation only |
| `MITM_QUIET_HOSTS` | the agent's own endpoints | hosts treated as the agent's control plane: bodies are not stored and headers are not scanned. Bodies are still scanned, so a secret pasted into a prompt is still caught |
| `MITM_FLOOD_N` / `MITM_FLOOD_WINDOW` | `30` / `10` | flood-detection threshold per domain |
| `MITM_UI` | `dump` | `web` → mitmweb at `http://localhost:8082` (token in `docker compose logs proxy`) |
| `FORWARD_OTHER` | `drop` | `masq` = allow non-HTTP egress (and stay blind to it) — for testing bypass scenarios |
| `AGENT_ROUTE` | `proxy` | `none` = drop transparent interception, keep the env proxy only |
| `AGENT_GIT_GUARD` | `0` | `1` = block remote URL rewrites, force-push, `filter-branch`, global config edits |
| `AGENT_FSWATCH` | `1` | file-change watcher over `/work` |

A strict setup, for example:

```bash
MITM_ALLOW_HOSTS=api.anthropic.com,github.com,registry.npmjs.org \
AGENT_GIT_GUARD=1 ./lab up
```

## Isolation self-test

```bash
./lab probe
./lab alerts --since 5m
```

Runs 10 classes of attempt to get out. Expected result on the default config:

| # | Scenario | Expectation |
|---|---|---|
| 1 | HTTPS via the env proxy | through, logged as `proxy` |
| 2 | `curl --noproxy '*'` | through, logged as `transparent` — the bypass is visible |
| 3 | raw TCP to :443 | through, logged as `transparent` |
| 4 | HTTPS on :8443 | cut off |
| 5 | outbound SSH | cut off |
| 6 | DNS lookup of an external name | **through and unlogged** — a known gap |
| 7 | POST with email + AWS key + host path | through, tagged `LEAK?` |
| 8 | 40 requests to one domain | `request_flood` |
| 9 | `git ls-remote` over HTTPS | through, whole exchange visible |
| 10 | repointing the origin remote | blocked when `AGENT_GIT_GUARD=1` (checked via the agent) |

## What this configuration does NOT catch

Established by running `tools/probe.sh`, not derived on paper.

- **DNS.** Resolution goes through Docker's embedded DNS and never appears in
  `traffic.jsonl`. The classic exfil channel (data in a subdomain) passes
  silently. Closing it needs an own resolver on the proxy — not done.
- **Content inside an allowed domain.** A domain allowlist cannot tell
  `GET api.github.com/repos/…` from `POST api.github.com/gists` carrying a dump
  of secrets. `findings` works on that, but it is a regex heuristic, not a
  solution.
- **Compressed and encrypted bodies.** base64/gzip/custom encryption are opaque
  to regexes.
- **Certificate pinning.** A pinning client simply fails to connect (which is
  visible), but its traffic stays unseen.
- **Everything the agent does inside `/work`.** The isolation is about the
  network and about what is mounted. Inside its own directory the agent is free.
- **The file watcher polls every 2s.** A create-and-revert within one interval
  goes unnoticed.
- **`docker compose exec -u root`.** See above: a bypass by construction.

## Requirements

Docker Desktop, and python3 on the host (only for `tools/correlate.py`).

## License

MIT — see [LICENSE](LICENSE).
