# Dynamic Zones API

## Why

A DNS name is the smallest possible request and one of the slowest to fulfil. A
student needs `myproject.students.example.edu` for a demo, a lecturer needs a
handful of names for a course, a Kubernetes cluster needs to prove domain
ownership to Let's Encrypt every few weeks — and all of it typically ends in a
ticket to whoever holds the zone file. The wait is longer than the work.

The obstacle is not effort but trust: giving someone write access to a zone means
giving it for the *whole* zone. So requests are funnelled through people who are
allowed to edit it, and automation gets a shared credential nobody dares rotate.

This service removes that trade-off. A policy states which names which people may
have; anyone matching it creates their zone themselves and gets a key that is
valid **for that zone only**. Machines then keep their own records up to date over
the standard protocol (RFC 2136), with no human in the loop and no credential
that reaches beyond one delegated name.

Put plainly: this is the self-service layer over a hardened
[PowerDNS](https://doc.powerdns.com/) installation. PowerDNS stays the
authoritative nameserver and does what it is good at; this service owns the
question PowerDNS has no opinion about — *who is allowed to have which name, and
with which key* — and configures it accordingly through its HTTP API.

It is an API and usable on its own: zones, records, keys and policy are all
reachable over HTTP, and it ships a generated TypeScript client. If you want a
browser interface rather than building one,
[**self-service-ui**](https://github.com/pfisterer/self-service-ui) is one — zone
and record management, API tokens, the policy view and ready-made snippets for
`nsupdate`, `external-dns` and `cert-manager`. Its README has screenshots.

## What it does

- **Policy-driven zone creation.** A rule says which zone names (`zone_pattern`,
  where `%u` stands for the requester) may be created by whom
  (`target_user_filter`: single addresses or `*@domain`), under which
  authoritative zone (`zone_soa`), and whether subdomains and co-ownership are
  permitted. Users can create exactly what a rule grants them — nothing else.
- **Per-zone TSIG keys.** Each zone gets its own key. It is what `nsupdate`,
  [external-dns](https://github.com/kubernetes-sigs/external-dns) or
  [cert-manager](https://cert-manager.io/) use to write records, and it cannot
  touch any other zone. Keys can be rotated.
- **Records in the browser or over the API.** The same records can be edited in
  the web UI or written by machines via RFC 2136.
- **PowerDNS as the authoritative server.** The service configures PowerDNS
  through its HTTP API and never edits zone files or the backend database itself.
  Backend (`gsqlite3` or `gpgsql`), DNSSEC and hardening are PowerDNS
  configuration, not this service's business.
- **Upstream delegation.** For the managed zones to resolve globally, the parent zone must delegate to this nameserver. Either configure that once upstream, or let this service keep its own `A`/`AAAA` record current in the upstream zone via RFC 2136 itself.
- **Shared zones and delegated policy administration.** A zone may have several owners; a *delegation* lets named people manage policy rules for one zone and its subdomains without being a global administrator. Anyone can list the delegations that apply to them (zone suffix and description); only super-admins see every delegation and whom it targets.
- **Zone events.** Problems observed with a zone — for example a client that keeps failing TSIG against it — are shown to the zone's owners, and to super-admins for all zones together with the owners to contact. The service stores and serves them; producing them is left to a monitoring system (see [Zone events](#zone-events)).
- **API tokens** for automation, optionally read-only (a read-only token is
  refused on anything but `GET`).

### Zones, rules and "orphaned" zones

A zone's relationship to a policy rule is **recomputed, never stored**. A zone is
*orphaned* when no current rule would produce that name for that owner — which
happens when a rule is edited or deleted. The zone and its records keep working;
what the owner loses is the right to manage it.

The remedy is therefore to **fix the rule**, not to delete the zone. A single typo
in a `target_user_filter` orphans every zone that rule covered, and deleting the
zones would destroy records that were never the problem. The UI lists orphaned
zones for administrators so the mistake is visible.

## API

The service is served under `/v1` and publishes its own OpenAPI description — that
spec is the authoritative reference, so it cannot drift from the implementation the
way a hand-written endpoint list does:

- **`GET /swagger.json`** — the OpenAPI spec
- A generated TypeScript client is published to npm as `@dhbw-cloud/dynamic-zones-client`.
  It used to be served from `/client/` and loaded by the browser at startup; consumers
  now depend on a version at build time, so a missing operation is a build error there
  instead of a silent no-op in the browser.

[self-service-ui](https://github.com/pfisterer/self-service-ui) renders the same
spec in the browser under *DNS Zones → API Documentation*, which is usually the
quickest way to look something up and try it out.

### MCP

`POST /mcp` speaks the Model Context Protocol, so an LLM client can work with zones and records on a person's behalf. It authenticates exactly like `/v1` — an API token from the tokens page — and every tool calls the same service method the REST handler calls, so an agent is bound by the same rules as the browser.

Two things differ from `/v1`, and both are deliberate:

- **The read-only rule is per operation, not per HTTP method.** Every MCP call is a POST, reads included, so `RejectWritesForReadOnlyTokens` (which sits on the `/v1` group) is not mounted here. A read-only token is simply not shown the mutating tools — a model picks from what it sees, and offering it a tool that always fails only invites retries.
- **No tool ever returns a TSIG key.** The record tools resolve the caller's own key inside the service (`AppData.OwnerTSIG`) and hand it straight to PowerDNS. The REST routes take the key from the request because the browser holds it already; a model must not be put in that position, since anything handed to it lands in its context, its transcript and its client's storage.

The destructive tools (`delete_zone`, `delete_policy_rule`, `delete_delegation`) require a distinguishing field to be echoed back. That is not a defence against prompt injection — injected text can quote a zone name as easily as invent one — and is not sold as one. It catches the likelier failure: a model that resolved "the old one" to the wrong zone. There is deliberately **no** tool that deletes an orphaned zone: an orphaned zone is nearly always a mistyped rule, and the remedy is to fix the rule.

### Zone events

`GET /v1/zone-events/` lists the live problems with the caller's zones (all zones for a super-admin), each with its class, severity, message, how often it was reported, and the zone's owners. Events are state, not history: there is one per source, class and zone, refreshed while the producer keeps reporting it, removed when it reports it resolved, and expired after `ZONE_EVENTS_TTL_HOURS` if it does neither — the safety net for a lost "resolved" notification.

Two endpoints accept events: `POST /v1/zone-events/` in a generic shape, and `POST /v1/zone-events/alertmanager`, which takes an Alertmanager webhook as is and turns every alert carrying a `zone` label into an event (class = `alertname`). The service knows nothing about the rules that fire them.

Both are part of the public `/v1` surface, so being logged in is not enough: only the single identity `ZONE_EVENTS_INGEST_SUBJECT` may post, anyone else gets `403`. Its token is not issued through the token API — it would then act as the admin who issued it — but provisioned from `ZONE_EVENTS_INGEST_TOKEN` at startup, so rotating it is changing the value and restarting, and emptying it revokes it. It must start with the API-token prefix `dynz_token_`, followed by at least 16 characters. What a leaked token can do is bounded further: events for zones this service does not manage or for classes not in `ZONE_EVENTS_ALLOWED_CLASSES` are skipped (and reported back in the response and in the log), text is truncated, a request carries at most 200 events, and ingest is capped at 120 requests a minute.

## Running it locally

**Prerequisites:** Go 1.26+ ([swag](https://github.com/swaggo/swag) is installed by `make` when missing), a reachable PowerDNS with its API enabled, a reachable OIDC issuer (startup fetches its discovery document, in development mode too), and optionally [air](https://github.com/air-verse/air) for live reload. Node.js is only needed to build the npm client package, Docker only for the tests.

A minimal PowerDNS for development (SQLite backend, API on 8080, DNS on 53 — published on 15353 when run in a container, which is what the defaults below expect):

```ini
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3
local-address=0.0.0.0
local-port=53
webserver-address=0.0.0.0
webserver-port=8080
webserver-allow-from=0.0.0.0/0
api=yes
api-key=my-default-api-key
dnsupdate=yes
```

Then:

```bash
make bundle  # once: generates the embedded swagger.json the server imports
make dev     # live-reload server on :8082
make test
make all     # swagger + binary
```

A fresh clone does not compile until `make bundle` (or `make all`) has generated `internal/generated_docs/`. Besides `OIDC_ISSUER_URL`/`OIDC_CLIENT_ID`, startup requires `UPSTREAM_DNS_NAME` and `UPSTREAM_DNS_ZONE` (see [Upstream nameserver](#upstream-nameserver)); set `API_MODE=development` in the environment or in `.env`.

`make test` runs integration tests: they start a PowerDNS container and the real application on `:8082`, so a running development server makes them fail with "address already in use", and they need the same OIDC and upstream variables.

`API_MODE=development` **bypasses authentication**: the caller asserts an identity
with the `X-Dummy-Auth-User` header. That is the whole login in development — and
the reason `API_MODE` must be `production` everywhere else. A production
deployment that accidentally ran in development mode showed empty zone and policy
lists, because every request was a different, unknown user.

A `run-development.sh` in the workspace that holds the sibling repositories (not part of this repository) starts PowerDNS, this API, the role-provider, the OpenStack management API and the web UI together.

## Configuration

All configuration is environment variables. A `.env` file in the working directory is loaded when present, in any mode, without overriding variables that are already set.

### Service

| Variable | Default | Purpose |
|---|---|---|
| `API_MODE` | `production` | `development` = auth bypass, see above |
| `API_BIND` | `:8082` | Listen address |
| `API_BASE_URL` | `http://localhost:8082` | Public URL, used in generated instructions |
| `API_TOKEN_TTL_HOURS` | `24` | Token lifetime when the request names none (any other lifetime may be requested) |
| `API_TOKEN_ALLOW_NEVER_EXPIRES` | `false` | Whether `ttl_hours: -1` (no expiry) is granted at all |
| `DB_TYPE` | `sqlite` | `sqlite` \| `postgres` \| `mysql` |
| `DB_CONNECTION_STRING` | in-memory SQLite | DSN for the chosen backend |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated origins for the browser client |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` | — | Bearer-token verification (required) |
| `DNS_POLICY_SUPERADMIN_EMAILS` | — | Comma-separated addresses that may manage all policy |
| `INITIAL_DATA_SCRIPT_PATH` | — | JS file that seeds rules/zones on first start |
| `EXTERNAL_DNS_IMAGE_VERSION` | `v0.19.0` | external-dns image version used in the generated external-dns manifest (a request can override it with `image-version`) |

### PowerDNS

| Variable | Default | Purpose |
|---|---|---|
| `PDNS_URL` | `http://localhost:8080` | PowerDNS HTTP API |
| `PDNS_API_KEY` | `my-default-api-key` | API key |
| `PDNS_VHOST` | `localhost` | The PowerDNS *server id* in the API path (`/api/v1/servers/<id>`), which is `localhost` in a stock install — not a network host |
| `PDNS_SERVER_ADDRESS`, `PDNS_SERVER_PORT` | `127.0.0.1`, `15353` | The **publicly reachable** address of this nameserver: announced upstream as its A/AAAA record and used to build the `dig` / cert-manager / external-dns examples. Validated as an IP, because a name would not work in either place |
| `PDNS_QUERY_TARGET` | `127.0.0.1:15353` | Where this service sends its **own** AXFR and RFC 2136 traffic. A `host:port` that only has to resolve from here, so in a cluster it is the PowerDNS Service — kept separate from the address above, which points at whatever fronts the nameserver publicly |
| `PDNS_ADVERTISED_NAMESERVER` | — | Public NS hostname shown in the examples instead of the bare address. Purely cosmetic: the NS/SOA of created zones is `UPSTREAM_DNS_NAME`.`UPSTREAM_DNS_ZONE` |
| `PDNS_SERVER_DEFAULT_TTL` | 1 year | Default record TTL |

### Upstream nameserver

`UPSTREAM_DNS_NAME` and `UPSTREAM_DNS_ZONE` are **always required**: together they are this nameserver's name (e.g. `ns` + `cloud-ns.example.org`), used as the NS/SOA of every zone the service creates, so startup refuses to run without them.

Keeping that name's `A`/`AAAA` record current in the parent zone is optional and runs only when `UPSTREAM_DNS_TSIG_NAME/_ALG/_SECRET` are all set. It then also needs `UPSTREAM_DNS_SERVER` (with `UPSTREAM_DNS_PORT`, default `53`), publishes `PDNS_SERVER_ADDRESS` with `UPSTREAM_DNS_TTL` (default `900`) and re-checks every `UPSTREAM_DNS_UPDATE_INTERVAL` seconds (default `3600`) — instead of relying on a one-off manual delegation. Leaving the TSIG key empty keeps an environment from writing upstream at all.

### Zone defaults

`ZONE_DEFAULTS_ADMIN_RECORDS` (JSON) are records written into every newly
created **user (leaf) zone**; `ZONE_DEFAULTS_SOA_RECORDS` go only into the
**SOA/base (intermediate) zones** the service creates above them.
`ZONE_DEFAULTS_ADMIN_TSIG_NAME/_ALG/_KEY` name the admin key that is added to
all of these zones. The split is deliberate: a record in the base zone cannot be
deleted or overridden with the user's own zone key.

This is where **CAA** belongs. A `CAA` record must name the certificate authority
that actually signs — not the ACME endpoint in front of it. Naming the proxy host
instead makes every wildcard issuance fail with an opaque CA error, and
`issuewild` must be present alongside `issue` or wildcard requests are refused.

### Zone events

| Variable | Default | Purpose |
|---|---|---|
| `ZONE_EVENTS_INGEST_SUBJECT` | `alertmanager@platform` | The only identity allowed to post events |
| `ZONE_EVENTS_INGEST_TOKEN` | — | Its token, provisioned into the token store at startup; empty disables ingest and revokes a previously provisioned token |
| `ZONE_EVENTS_ALLOWED_CLASSES` | `DnsClientMisconfig` | Comma-separated event classes accepted (case-sensitive; for Alertmanager, alert names) |
| `ZONE_EVENTS_TTL_HOURS` | `24` | Lifetime of an event that is not re-reported; must comfortably exceed the producer's re-notification interval, or events flap out of view |

## Build & CI

- `make all` — embedded swagger + binary
- `make test` — Go test suite (integration tests, needs Docker)
- `make dev` — live reload (needs `air`)
- `make npm-package` / `make npm-publish` — build and publish `@dhbw-cloud/dynamic-zones-client` (Node.js); publishing is a manual step, and a prerelease version goes to the `next` dist-tag instead of `latest`
- `make bump V=X.Y.Z` — set `VERSION` and the chart's `version`/`appVersion`; `make version-check` fails when they disagree

GitHub Actions builds and pushes the `linux/amd64` image to `ghcr.io/pfisterer/dynamic-zones`, but never overwrites a version that is already published — bump `VERSION` to release. Tests are not part of the image build; a separate `Checks` workflow runs `go vet` and the test suite on every push to `main` and every pull request. Image tags: `X.Y.Z-test.N` → staging, `X.Y.Z` → production. A stable version additionally gets a Git tag and a GitHub release whose notes are built from the commit subjects.

## Deployment

**Normally deployed as part of [cloud-self-service](https://github.com/pfisterer/cloud-self-service)**, the umbrella chart that composes this service with the other three and pins it by version — and a pinned chart version pins its `appVersion`, which pins the image tag. Installing this chart on its own works, but then nothing keeps it in step with the services it talks to.

A Helm chart lives in [`helm-chart/`](helm-chart). Its version always equals `VERSION`.

The chart is published as an OCI artifact on every push to `main` whose version is not published yet:

```sh
helm pull oci://ghcr.io/pfisterer/charts/dynamic-zones --version X.Y.Z
```

The zone-events ingest token has no chart value: it is read, optionally, from the key `zone-events-ingest-token` of the Secret named in `dynamicZonesAPI.existingSecret`. The Secret the chart creates itself does not carry that key, so without an `existingSecret` providing it, ingest stays disabled. The ingest subject, allowed classes and event TTL are not exposed as chart values, so the defaults above apply.

Values for this chart go under its chart name in the umbrella, where `dynamic-zones.enabled: false` leaves the service out of the installation altogether:

```yaml
dynamic-zones:
  dynamicZonesAPI:
    ...
```

### What "hardened PowerDNS" means here

An authoritative nameserver on the public internet is a reflection amplifier
waiting to be used, so PowerDNS should not be exposed directly. Put [dnsdist](https://dnsdist.org/) in front of it and keep PowerDNS itself reachable only inside the cluster:

- **ANY over UDP is truncated** (`TC=1`), which forces a legitimate client to retry
  over TCP and gives a spoofed reflection source nothing worth amplifying.
- **Per-source rate limiting** over UDP, likewise answered with `TC=1` rather than a
  drop, so rate-limited but genuine clients still get through over TCP.
- **Bogon and blocklist sources are dropped** outright.
- **RFC 2136 UPDATE traffic and internal networks** are routed to the PowerDNS pool
  — that is the path this service and its users' keys take.
- PowerDNS's **HTTP API is cluster-internal**. Only this service talks to it; the
  API key never leaves the namespace.

Two things that will bite whoever hardens it further:

- **`disable-axfr` breaks this service.** It uses zone transfers internally, so
  switching them off wholesale is not an option — restrict them by address instead.
- **dnsdist has to run with `hostNetwork`.** Behind the cluster's service proxy the
  source address of every query is rewritten, which silently defeats both the rate
  limiting and the blocklists above, since every packet then appears to come from
  the same host.

### PowerDNS backend

`gsqlite3` and `gpgsql` are both supported and chosen per environment. With
`gpgsql`, authoritative DNS depends on the database: if Postgres is gone, the
nameserver stops answering. On a single-node installation that matters less than it
sounds, but it is a coupling that did not exist with SQLite.

## Related projects

- [cloud-self-service](https://github.com/pfisterer/cloud-self-service) — the umbrella chart that composes all four
- [self-service-ui](https://github.com/pfisterer/self-service-ui) — the web interface
- [openstack-management-api](https://github.com/pfisterer/openstack-management-api) — the compute half of the platform

## License

See [LICENSE](./LICENSE).
