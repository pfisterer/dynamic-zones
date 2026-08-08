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
- **Upstream delegation.** For the managed zones to resolve globally, the parent
  zone must delegate to this nameserver. Either configure that once upstream, or
  let this service keep an `A`/`NS` record current in the upstream zone via
  RFC 2136 itself.
- **Shared zones and delegated policy administration.** A zone may have several
  owners; a *delegation* lets named people manage policy rules for one zone and
  its subdomains without being a global administrator.
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
- **`/client/`** — a generated TypeScript client (the web UI imports it at runtime)

[self-service-ui](https://github.com/pfisterer/self-service-ui) renders the same
spec in the browser under *DNS Zones → API Documentation*, which is usually the
quickest way to look something up and try it out.

## Running it locally

**Prerequisites:** Go 1.24+, Node.js (for the docs and client bundle),
a reachable PowerDNS with its API enabled, and optionally
[air](https://github.com/air-verse/air) for live reload.

A minimal PowerDNS for development (SQLite backend, API on 8080, DNS on 15353):

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
make dev     # live-reload server on :8082 (API_MODE=development)
make test
make all     # swagger + client bundle + binary
```

`API_MODE=development` **bypasses authentication**: the caller asserts an identity
with the `X-Dummy-Auth-User` header. That is the whole login in development — and
the reason `API_MODE` must be `production` everywhere else. A production
deployment that accidentally ran in development mode showed empty zone and policy
lists, because every request was a different, unknown user.

The deployment repo's `run-development.sh` starts PowerDNS, this API, the
role-provider and the web UI together.

## Configuration

All configuration is environment variables (`.env` is loaded in development).

### Service

| Variable | Default | Purpose |
|---|---|---|
| `API_MODE` | `production` | `development` = auth bypass, see above |
| `API_BIND` | `:8082` | Listen address |
| `API_BASE_URL` | `http://localhost:8082` | Public URL, used in generated instructions |
| `API_TOKEN_TTL_HOURS` | `24` | Lifetime of issued API tokens |
| `DB_TYPE` | `sqlite` | `sqlite` \| `postgres` \| `mysql` |
| `DB_CONNECTION_STRING` | in-memory SQLite | DSN for the chosen backend |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated origins for the browser client |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` | — | Bearer-token verification |
| `DNS_POLICY_SUPERADMIN_EMAILS` | — | Comma-separated addresses that may manage all policy |
| `INITIAL_DATA_SCRIPT_PATH` | — | JS file that seeds rules/zones on first start |

### PowerDNS

| Variable | Default | Purpose |
|---|---|---|
| `PDNS_URL` | `http://localhost:8080` | PowerDNS HTTP API |
| `PDNS_API_KEY` | `my-default-api-key` | API key |
| `PDNS_VHOST` | `localhost` | Virtual host in the API path |
| `PDNS_SERVER_ADDRESS`, `PDNS_SERVER_PORT` | `127.0.0.1`, `15353` | Where RFC 2136 updates are sent |
| `PDNS_ADVERTISED_NAMESERVER` | — | Nameserver name handed to users and put into NS records |
| `PDNS_SERVER_DEFAULT_TTL` | 1 year | Default record TTL |

### Upstream delegation (optional)

`UPSTREAM_DNS_SERVER`, `UPSTREAM_DNS_PORT`, `UPSTREAM_DNS_NAME`,
`UPSTREAM_DNS_ZONE`, `UPSTREAM_DNS_TSIG_NAME/_ALG/_SECRET`, `UPSTREAM_DNS_TTL`,
`UPSTREAM_DNS_UPDATE_INTERVAL` — when set, the service keeps its own record in the
parent zone current instead of relying on a one-off manual delegation.

### Zone defaults

`ZONE_DEFAULTS_SOA_RECORDS` and `ZONE_DEFAULTS_ADMIN_RECORDS` (JSON) are records
written into every newly created zone, with
`ZONE_DEFAULTS_ADMIN_TSIG_NAME/_ALG/_KEY` for the key used to write them.

This is where **CAA** belongs. A `CAA` record must name the certificate authority
that actually signs — not the ACME endpoint in front of it. Naming the proxy host
instead makes every wildcard issuance fail with an opaque CA error, and
`issuewild` must be present alongside `issue` or wildcard requests are refused.

## Build & CI

- `make all` — swagger + TypeScript client + binary
- `make test` — Go test suite
- `make dev` — live reload (needs `air`)

GitHub Actions builds and pushes the `linux/amd64` image to
`ghcr.io/pfisterer/dynamic-zones`. Tests are not part of the image build; run them
locally. Image tags: `X.Y.Z-test.N` → staging, `X.Y.Z` → production.

## Deployment

A Helm chart lives in [`helm-chart/`](helm-chart) and is deployed via ArgoCD from
the `dhbw-deployment` repo.

### What "hardened PowerDNS" means here

An authoritative nameserver on the public internet is a reflection amplifier
waiting to be used, so PowerDNS is not exposed directly. In the DHBW installation
[dnsdist](https://dnsdist.org/) sits in front of it and PowerDNS itself is only
reachable inside the cluster:

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

- [self-service-ui](https://github.com/pfisterer/self-service-ui) — the web interface
- [openstack-management-api](https://github.com/pfisterer/openstack-management-api) — the compute half of the platform

## License

See [LICENSE](./LICENSE).
