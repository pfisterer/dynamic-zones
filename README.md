# Dynamic Zones API

## Why

A DNS name is the smallest possible request and one of the slowest to fulfil. A student needs `myproject.students.example.edu` for a demo, a lecturer needs a handful of names for a course, a Kubernetes cluster needs to prove domain ownership to Let's Encrypt every few weeks — and all of it typically ends in a ticket to whoever holds the zone file. The wait is longer than the work.

The obstacle is not effort but trust: giving someone write access to a zone means giving it for the *whole* zone. So requests are funnelled through people who are allowed to edit it, and automation gets a shared credential nobody dares rotate.

This service removes that trade-off. A policy states which names which people may have; anyone matching it creates their zone themselves and gets a key that is valid **for that zone only**. Machines then keep their own records up to date over the standard protocol (RFC 2136), with no human in the loop and no credential that reaches beyond one delegated name.

Put plainly: this is the self-service layer over a hardened [PowerDNS](https://doc.powerdns.com/) installation. PowerDNS stays the authoritative nameserver and does what it is good at; this service owns the question PowerDNS has no opinion about — *who is allowed to have which name, and with which key* — and configures it accordingly through its HTTP API.

It is an API and usable on its own: zones, records, keys and policy are all reachable over HTTP, and it ships a generated TypeScript client. If you want a browser interface rather than building one, [**self-service-ui**](https://github.com/pfisterer/self-service-ui) is one — zone and record management, API tokens, the policy view and ready-made snippets for `nsupdate`, `external-dns` and `cert-manager`. Its README has screenshots.

## What it does

- **Policy-driven zone creation.** A rule says which zone names (`zone_pattern`, where `%u` stands for the requester's address and `%l` for its local part; see [Placeholders in zone patterns](#placeholders-in-zone-patterns-u-and-l)) may be created by whom (`target_user_filter`: addresses, `*@domain` patterns or groups of the role provider; see [Who a rule applies to](#who-a-rule-applies-to-user-filters-and-groups)), under which authoritative zone (`zone_soa`), and whether subdomains and co-ownership are permitted. Users can create exactly what a rule grants them — nothing else.
- **Per-zone TSIG keys.** Each zone gets its own key. It is what `nsupdate`, [external-dns](https://github.com/kubernetes-sigs/external-dns) or [cert-manager](https://cert-manager.io/) use to write records, and it cannot touch any other zone. Keys can be rotated.
- **Records in the browser or over the API.** The same records can be edited in the web UI or written by machines via RFC 2136.
- **PowerDNS as the authoritative server.** The service configures PowerDNS through its HTTP API and never edits zone files or the backend database itself. Backend (`gsqlite3` or `gpgsql`), DNSSEC and hardening are PowerDNS configuration, not this service's business.
- **Upstream delegation.** For the managed zones to resolve globally, the parent zone must delegate to this nameserver. Either configure that once upstream, or let this service keep its own `A`/`AAAA` record current in the upstream zone via RFC 2136 itself.
- **Shared zones and delegated policy administration.** A zone may have several owners, one of whom created it: only the creator (or a super-admin) may delete the zone, remove other owners or rotate everyone's keys, while an owner who joined or was added may leave and rotate their own key. A zone can also be shared with a group of the role provider (`POST /v1/zones/{zone}/groups`, `group:<id>` or `group:<id>#<relation>`): every member owns it and the zones below it with an own key for as long as they are in the group, may share it further and may delete it; their access appears with their next request and goes when they leave the group (checked again every 15 minutes), and when only members of a group that is gone are left, the zone is orphaned. Subzones are created below a zone the requester owns, never below somebody else's; a *delegation* lets named people manage policy rules for one zone and its subdomains without being a global administrator. Anyone can list the delegations that apply to them (zone suffix and description); only super-admins see every delegation and whom it targets.
- **Zone events.** Problems observed with a zone — for example a client that keeps failing TSIG against it — are shown to the zone's owners, and to super-admins for all zones together with the owners to contact. The service stores and serves them; producing them is left to a monitoring system (see [Zone events](#zone-events)).
- **CAA cannot be overridden from a user zone.** The enforced CAA sits in the base zones, but a CAA lookup takes the closest CAA record set, so a CAA record in a user's own zone would replace it for every name below. A periodic check finds such records and reports them as zone events, and can remove them (see [CAA check](#caa-check)).
- **A limit of zones per person** (`DNS_MAX_ZONES_PER_USER`, default 50): creating one more is refused with 403. Counted are the zones a person created and the zones they hold through a group share, subzones included, not those shared with them by address or joined; super-admins are exempt.
- **API tokens** for automation, optionally read-only (a read-only token is refused on anything but `GET`, and never sees a zone's TSIG key).

### Zones, rules and "orphaned" zones

A zone's relationship to a policy rule is **recomputed, never stored**. A zone is *orphaned* when no current rule would produce that name for its **creator** — which happens when a rule is edited or deleted. Co-owners of a shared zone got it by sharing or joining under the creator's rule, so whether a rule covers them themselves does not matter; a shared zone is listed once, under its creator. The zone and its records keep working; what the owner loses is the right to manage it.

The remedy is therefore to **fix the rule**, not to delete the zone. A single typo in a `target_user_filter` orphans every zone that rule covered, and deleting the zones would destroy records that were never the problem. The UI lists orphaned zones for administrators so the mistake is visible.

The zone list (`GET /v1/zones/`, and `list_my_zones` over MCP) tells for every top-level zone the zone it was given out of, as `zone_soa`: the governing rule's `zone_soa` (e.g. `users.dhbw.site` for a personal zone), or for a zone shared with the caller the SOA of the rule that governs it through its owners. It is the part of the name the user does not own, which the UI groups the zones by. It is left out for subzones, which carry their `parent` instead, and for a zone no rule governs any more.

### Placeholders in zone patterns: `%u` and `%l`

A `zone_pattern` may contain two placeholders, both replaced per user and made DNS-compliant by the same rules (characters other than letters, digits and `-` become `-`, runs of `-` collapse, leading and trailing `-` are dropped, everything lowercase):

| Placeholder | Stands for | `dennis.pfisterer@dhbw.de` | `s252690@student.dhbw-mannheim.de` |
|---|---|---|---|
| `%u` | the whole e-mail address, `@` written as `-at-` | `dennis-pfisterer-at-dhbw-de` | `s252690-at-student-dhbw-mannheim-de` |
| `%l` | only the local part, before the `@` | `dennis-pfisterer` | `s252690` |

`%l` gives shorter names and works with any `target_user_filter`, groups included. Since it drops the domain, two people can be granted the same name (`max@a.de` and `max@b.de`); and making an address DNS-compliant maps different addresses to the same text under both placeholders (`max.muster` and `max_muster` → `max-muster`). A zone belongs to whoever created it first. Anyone else whose address leads to a name that somebody else's zone already has is offered a **variant** instead: the placeholder's text with a short hash of their full address appended (`max-muster-3f9a1c.users.dhbw.site`). The hash depends only on the address, so a person always gets the same variant; once they created it, it stays theirs (and covered by the rule) even after the zone that forced it is deleted. Existing zones are never renamed, and the name somebody else holds is refused to them (it is no longer offered). Where readable names per domain matter, a rule per domain can carry the domain's abbreviation in the pattern itself, e.g. `%l-stma.users.dhbw.site` for `*@student.dhbw-mannheim.de` (→ `s252690-stma.users.dhbw.site`) next to `%l.users.dhbw.site` for `*@dhbw.de` (→ `dennis-pfisterer.users.dhbw.site`).

To introduce `%l` where `%u` rules exist, **keep the `%u` rules and add a `%l` rule per domain**. Replacing a `%u` rule would orphan every zone it granted, since a zone must still match a rule (see above); with both rules each person can have both names. To have new users get only the short name, mark the `%u` rule as deprecated (below).

### Who a rule applies to: user filters and groups

A rule's `target_user_filter` (and a delegation's) is a comma-separated list; the rule applies to whoever matches **any** entry:

| Entry | Matches |
|---|---|
| `max@dhbw.de` | that address (case-insensitive) |
| `*@dhbw.de`, `s25*@student.dhbw-mannheim.de` | addresses matching the pattern (one `*`) |
| `user:max@dhbw.de` | that address, like the plain form; the token the role provider and the UI's people picker use |
| `group:wwi23seb` | every member of the group, as resolved by the [role provider](https://github.com/pfisterer/role-provider-service) (nested groups and patterns included) |
| `group:wwi23seb#studierende` | the members holding that relation in the group |

Group entries need a role provider (`ROLE_PROVIDER_URL`, `ROLE_PROVIDER_API_TOKEN`, see [Configuration](#role-provider)); without one they match nobody and e-mail entries work exactly as before. The service asks `GET /v1/users/{email}/tokens` and reuses the answer for 60 seconds per person, so a membership change counts within a minute. The filter is at most 255 characters.

**When the role provider is unreachable.** Every answer is kept for 24 hours as fallback, and after a failed request the role provider is not asked again for 15 seconds, so an outage does not make requests wait for timeouts. What happens then follows one principle — *a zone that exists is the owner's by the zones table; the rules decide only about new zones and about orphaning* — and an unknown answer never grants anything new:

- **Existing zones keep working.** Records, keys and ownership never depended on the rules. Where the rules are asked about a zone that exists — the orphan list, deleting an orphaned zone, the governing rule of a shared zone (its sharing and subdomain flags, `zone_soa`) — a group entry that cannot be checked counts as covering it, and the log says so. An unreachable role provider never orphans a zone.
- **New zones through group entries are refused** while the person's tokens are unknown (unreachable and nothing of the last 24 hours cached): creating or joining a zone only a group entry would grant answers 503 with a message saying the group service is unreachable and to try again later. Zone offers leave such rules out until the answer is back. A zone no rule would grant even with every group counted is refused with 403 as always, so nobody gets in on an unknown answer.
- **Delegations through group entries** grant nothing while unknown (strict), and the rules a plain user may see are likewise only those that match for certain.
- **E-mail and `user:` entries keep working**, they need no role provider.

### Deprecated rules

A rule with `deprecated: true` keeps the zones it already granted but offers no new ones:

- **Existing zones keep working fully.** The rule still covers them, so they are not orphaned, and every check that asks whether a rule grants a zone to its owner still says yes: records, keys, key rotation, deletion, sharing with further owners (if `sharing_allowed`) and subzones below the zone (if `allow_subdomains`; the parent exists, so a subzone is no new grant).
- **No new zones.** In the zone list (`GET /v1/zones/`, `list_my_zones`) a deprecated rule contributes only a zone the user already owns, marked `deprecated: true`; it offers no zone to create, none to join and lists none as taken. Creating a zone that only deprecated rules grant is refused with 403, naming the zones the current rules offer instead; joining one through the policy is refused as well. If a current rule grants the same name, the current rule wins. A deleted zone of a deprecated rule cannot be created again.

The column defaults to `false` (added by AutoMigrate), so existing rules behave as before. Switching it off again offers the zones again.

### Zone names

A zone has exactly one spelling: every entry point (REST, MCP, the record endpoints) trims it, lower-cases it and drops one trailing dot before anything else looks at it, and only that canonical form is stored — PowerDNS treats `X.P`, `x.p` and `x.p.` as one zone, so a second spelling must never look like a different, unclaimed one. A name must be a plain host name of at least two labels, each label 1–63 characters of `[a-z0-9-]` without a leading or trailing hyphen, at most 253 characters in total. Underscores, wildcards and empty labels are refused rather than repaired, and an over-long name is refused with its length.

## API

The service is served under `/v1` and publishes its own OpenAPI description — that spec is the authoritative reference, so it cannot drift from the implementation the way a hand-written endpoint list does:

- **`GET /swagger.json`** — the OpenAPI spec
- **`GET /healthz`** and **`GET /readyz`** — the probes, unauthenticated: alive while the process serves; ready while the database answers (503 with the failing checks under `failed`). The identity provider's keys are listed under `degraded` without making it 503, since API tokens and dyndns updates work without the provider
- A generated TypeScript client is published to npm as `@dhbw-cloud/dynamic-zones-client`. It used to be served from `/client/` and loaded by the browser at startup; consumers now depend on a version at build time, so a missing operation is a build error there instead of a silent no-op in the browser.

Every text meant for people — error messages, refusals, the MCP tools' answers — exists in German and English. The caller picks with `Accept-Language`; German is the default when the header is missing or names neither, and answers carry `Vary: Accept-Language`. An error answer also carries a stable `code` (e.g. `unauthenticated`, `act_as_forbidden`) for clients to match on instead of the text, and a 5xx says only "internal error" while the cause goes to the log. Log messages stay English.

[self-service-ui](https://github.com/pfisterer/self-service-ui) renders the same spec in the browser under *DNS Zones → API Documentation*, which is usually the quickest way to look something up and try it out.

### MCP

`POST /mcp` speaks the Model Context Protocol, so an LLM client can work with zones and records on a person's behalf. It authenticates exactly like `/v1` — an API token from the tokens page — and every tool calls the same service method the REST handler calls, so an agent is bound by the same rules as the browser.

Two things differ from `/v1`, and both are deliberate:

- **The read-only rule is per operation, not per HTTP method.** Every MCP call is a POST, reads included, so `RejectWritesForReadOnlyTokens` (which sits on the `/v1` group) is not mounted here. A read-only token is simply not shown the mutating tools — a model picks from what it sees, and offering it a tool that always fails only invites retries.
- **No tool ever returns a TSIG key.** The record tools resolve the caller's own key inside the service (`AppData.OwnerTSIG`) and hand it straight to PowerDNS. The REST routes take the key from the request because the browser holds it already; a model must not be put in that position, since anything handed to it lands in its context, its transcript and its client's storage.

The destructive tools (`delete_zone`, `delete_policy_rule`, `delete_delegation`) require a distinguishing field to be echoed back. That is not a defence against prompt injection — injected text can quote a zone name as easily as invent one — and is not sold as one. It catches the likelier failure: a model that resolved "the old one" to the wrong zone. There is deliberately **no** tool that deletes an orphaned zone: an orphaned zone is nearly always a mistyped rule, and the remedy is to fix the rule.

### Zone events

`GET /v1/zone-events/` lists the live problems with the caller's zones (all zones for a super-admin), each with its class, severity, message, how often it was reported, and the zone's owners. Events are state, not history: there is one per source, class and zone, refreshed while the producer keeps reporting it, removed when it reports it resolved, and expired after `ZONE_EVENTS_TTL_HOURS` if it does neither — the safety net for a lost "resolved" notification.

Two endpoints accept events: `POST /v1/zone-events/` in a generic shape, and `POST /v1/zone-events/alertmanager`, which takes an Alertmanager webhook as is and turns every alert carrying a `zone` label into an event (class = `alertname`). The service knows nothing about the rules that fire them.

Both are part of the public `/v1` surface, so being logged in is not enough: only the single identity `ZONE_EVENTS_INGEST_SUBJECT` may post, anyone else gets `403`. Its token is not issued through the token API — it would then act as the admin who issued it — but provisioned from `ZONE_EVENTS_INGEST_TOKEN` at startup, so rotating it is changing the value and restarting, and emptying it revokes it. It must start with the API-token prefix `dynz_token_`, followed by at least 16 characters. The ingest token works on the two ingest routes only; anywhere else in `/v1` and on `/mcp` it is refused with `403`. What a leaked token can do is bounded further: events for zones this service does not manage or for classes not in `ZONE_EVENTS_ALLOWED_CLASSES` are skipped (and reported back in the response and in the log), text is truncated, a request carries at most 200 events, and ingest is capped at 120 requests a minute.

### CAA check

Every `CAA_CHECK_INTERVAL_MINUTES` (default 60, the first run a minute after startup; `0` switches it off) the service reads the record sets of all stored zones from PowerDNS. A zone with a CAA record set gets a zone event of source `caa-check`, class `UserZoneCAA`, listing the record sets; its owners see it like every other zone event, super-admins see all. The event is refreshed by each run that still finds the records and resolved by the first that does not (and expires after three intervals, at least an hour, if the check stops). A record set whose entries all repeat the enforced CAA (`ZONE_DEFAULTS_SOA_RECORDS`, e.g. in a zone that was an intermediate zone before somebody adopted it) restricts nothing further and is not reported.

With `CAA_CHECK_DELETE_RECORDS=true` (default `false`) the check removes such record sets itself and reports that instead (class `UserZoneCAARemoved`), which stays visible until it expires after `ZONE_EVENTS_TTL_HOURS`. These events are written by the service itself, so `ZONE_EVENTS_ALLOWED_CLASSES` (which guards the ingest) does not need to list them.

## Running it locally

**Prerequisites:** Go 1.26+ (`go.mod` pins the toolchain, go1.27.4, which the `go` command fetches itself) ([swag](https://github.com/swaggo/swag) is installed by `make` when missing), a reachable PowerDNS with its API enabled, a reachable OIDC issuer (unless `OIDC_JWKS_URL` is set, startup fetches its discovery document, in development mode too), and optionally [air](https://github.com/air-verse/air) for live reload. Node.js is only needed to build the npm client package, Docker only for the tests.

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

A fresh clone does not compile until `make bundle` (or `make all`) has generated `internal/generated_docs/`. Besides `OIDC_ISSUER_URL`/`OIDC_CLIENT_ID`, startup requires `PDNS_API_KEY`, `UPSTREAM_DNS_NAME` and `UPSTREAM_DNS_ZONE` (see [Upstream nameserver](#upstream-nameserver)); set `API_MODE=development` in the environment or in `.env`.

`make test` runs integration tests: they start a PowerDNS container and the real application on a free loopback port (so a running development server does not get in the way), in development mode with an in-memory SQLite database, and they need the same OIDC and upstream variables (from `.env` locally; CI sets them).

`API_MODE=development` **bypasses authentication**: a request without a bearer is the dev user `DEV_AUTH_USER` (default `root.admin@uni.example`). That is the whole login in development — and the reason `API_MODE` must be `production` everywhere else. Other people are reached as in production, with `X-Act-As` (below), so the dev user should be a super admin.

A super admin (`DNS_POLICY_SUPERADMIN_EMAILS`) may act on behalf of another person, e.g. for a ticket, by sending `X-Act-As: <email>` — the header every service of the platform reads, each checking it against its own admins. The request then is that person's: their zones, their policy rules, their `%u` and `%l`, and no super-admin rights unless they have them. Writes are logged with both. Not with an API token (403); the person's own API tokens are managed like everything else of theirs. `GET /v1/me` reports `may_act_as` and `acting_as`.

A `run-development.sh` in the workspace that holds the sibling repositories (not part of this repository) starts PowerDNS, this API, the role-provider, the OpenStack management API and the web UI together. For this service it amounts to:

```bash
# PowerDNS from the power-dns-lua repository: API on :8080, DNS on :15353 (the PDNS_* defaults)
API_MODE=development DEV_AUTH_USER=root.admin@uni.example \
  DNS_POLICY_SUPERADMIN_EMAILS=root.admin@uni.example \
  PDNS_API_KEY=my-default-api-key \
  ROLE_PROVIDER_URL=http://localhost:8085 ROLE_PROVIDER_API_TOKEN=dev-read \
  air                                         # the API on :8082
sh scripts/dev-seed-zones.sh http://localhost:8082
```

The OIDC and upstream variables come from a local `.env`, as does `INITIAL_DATA_SCRIPT_PATH=initial_data_provider.js`. That script seeds the policy rules when the database has none — among them rules that give the dev user `root.admin@uni.example` zones like a busy admin's on production. `scripts/dev-seed-zones.sh` waits for `/readyz` and then creates those zones as the dev user: the personal zone `root-admin-at-uni-example.users.dhbw.site` with three subzones, `test.` and `bigdata.pfisterer.users.dhbw.site` (the latter with a subzone), and the shared team zones `wi-ma.dhbw.site` and `services.dhbw.cloud` with their subzones and two co-owners each from the mock identities (`admin@cs.example`, `faculty@cs.example`, `faculty@bio.example`). The database is in memory, so after a restart (air restarts on every change) run the script again; a zone or owner that already exists only answers with an error, which the script prints and ignores.

## Configuration

All configuration is environment variables. A `.env` file in the working directory is loaded when present, in any mode, without overriding variables that are already set.

### Service

| Variable | Default | Purpose |
|---|---|---|
| `API_MODE` | `production` | `development` = auth bypass, see above |
| `API_BIND` | `:8082` | Listen address |
| `API_BASE_URL` | `http://localhost:8082` | Public URL, used in generated instructions |
| `API_TOKEN_TTL_HOURS` | `24` | Token lifetime when the request names none (any other lifetime up to `API_TOKEN_MAX_TTL_HOURS` may be requested) |
| `API_TOKEN_MAX_TTL_HOURS` | `8760` (1 year) | Longest lifetime a request may ask for; longer requests are refused, not shortened |
| `API_TOKEN_ALLOW_NEVER_EXPIRES` | `false` | Whether `ttl_hours: -1` (no expiry) is granted at all |
| `DB_TYPE` | `sqlite` | `sqlite` \| `postgres` \| `mysql` |
| `DB_CONNECTION_STRING` | in-memory SQLite | DSN for the chosen backend |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated origins for the browser client |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` | — | Bearer-token verification (required) |
| `OIDC_JWKS_URL` | — | The provider's key set (`…/protocol/openid-connect/certs` on Keycloak). Set it and startup asks the provider nothing, so an identity provider that is down cannot keep this service from starting; empty discovers the address from the issuer, which needs the provider to answer right then. A token that cannot be checked while the provider is away is answered 503, not 401 |
| `DEV_AUTH_USER` | `root.admin@uni.example` | Who a request without a bearer is in development mode; ignored otherwise |
| `DNS_POLICY_SUPERADMIN_EMAILS` | — | Comma-separated addresses that may manage all policy and act on behalf of others |
| `DNS_MAX_ZONES_PER_USER` | `50` | Zones one person may create (subzones included, zones held through a group share too, zones shared by address or joined not); `0` = no limit; super-admins are exempt |
| `INITIAL_DATA_SCRIPT_PATH` | — | JavaScript file run at every start with a `policy` object (`getAll`, `createRule`, `updateRule`, `deleteRule`, …); the bundled `initial_data_provider.js` seeds the policy rules only when there are none |
| `EXTERNAL_DNS_IMAGE_VERSION` | `v0.19.0` | external-dns image version used in the generated external-dns manifest (a request can override it with `image-version`, which must be a Docker image tag) |

### PowerDNS

| Variable | Default | Purpose |
|---|---|---|
| `PDNS_URL` | `http://localhost:8080` | PowerDNS HTTP API |
| `PDNS_API_KEY` | — (required) | API key; there is no default, startup fails without it |
| `PDNS_VHOST` | `localhost` | The PowerDNS *server id* in the API path (`/api/v1/servers/<id>`), which is `localhost` in a stock install — not a network host |
| `PDNS_SERVER_ADDRESS`, `PDNS_SERVER_PORT` | `127.0.0.1`, `15353` | The **publicly reachable** address of this nameserver: announced upstream as its A/AAAA record and used to build the `dig` / cert-manager / external-dns examples. Validated as an IP, because a name would not work in either place |
| `PDNS_QUERY_TARGET` | `127.0.0.1:15353` | Where this service sends its **own** AXFR and RFC 2136 traffic. A `host:port` that only has to resolve from here, so in a cluster it is the PowerDNS Service — kept separate from the address above, which points at whatever fronts the nameserver publicly |
| `PDNS_ADVERTISED_NAMESERVER` | — | Public NS hostname shown in the examples instead of the bare address. Purely cosmetic: the NS/SOA of created zones is `UPSTREAM_DNS_NAME`.`UPSTREAM_DNS_ZONE` |
| `PDNS_SERVER_DEFAULT_TTL` | 1 year | Default record TTL |

### Upstream nameserver

`UPSTREAM_DNS_NAME` and `UPSTREAM_DNS_ZONE` are **always required**: together they are this nameserver's name (e.g. `ns` + `cloud-ns.example.org`), used as the NS/SOA of every zone the service creates, so startup refuses to run without them.

Keeping that name's `A`/`AAAA` record current in the parent zone is optional and runs only when `UPSTREAM_DNS_TSIG_NAME/_ALG/_SECRET` are all set. It then also needs `UPSTREAM_DNS_SERVER` (with `UPSTREAM_DNS_PORT`, default `53`), publishes `PDNS_SERVER_ADDRESS` with `UPSTREAM_DNS_TTL` (default `900`) and re-checks every `UPSTREAM_DNS_UPDATE_INTERVAL` seconds (default `3600`) — instead of relying on a one-off manual delegation. Leaving the TSIG key empty keeps an environment from writing upstream at all.

### Zone defaults

`ZONE_DEFAULTS_ADMIN_RECORDS` (JSON) are records written into every newly created **user (leaf) zone**; `ZONE_DEFAULTS_SOA_RECORDS` go only into the **SOA/base (intermediate) zones** the service creates above them. `ZONE_DEFAULTS_ADMIN_TSIG_NAME/_ALG/_KEY` name the admin key that is added to all of these zones. The split is deliberate: a record in the base zone cannot be deleted or overridden with the user's own zone key.

This is where **CAA** belongs. A `CAA` record must name the certificate authority that actually signs — not the ACME endpoint in front of it. Naming the proxy host instead makes every wildcard issuance fail with an opaque CA error, and `issuewild` must be present alongside `issue` or wildcard requests are refused.

### Role provider

| Variable | Default | Purpose |
|---|---|---|
| `ROLE_PROVIDER_URL` | — | [role-provider-service](https://github.com/pfisterer/role-provider-service), e.g. `http://role-provider-service:8085`; empty = no role provider, group entries in user filters match nobody |
| `ROLE_PROVIDER_API_TOKEN` | — | A **read** token of the role provider (one of its `API_TOKENS`); required when the URL is set, startup fails without it |

Cache and outage behaviour: see [Who a rule applies to](#who-a-rule-applies-to-user-filters-and-groups). In the chart: `dynamicZonesAPI.roleProvider.url`, and the token from the key `role-provider-api-token` of the Secret (`dynamicZonesAPI.existingSecret`, or `dynamicZonesAPI.roleProvider.apiToken` when the chart creates it).

### Zone events

| Variable | Default | Purpose |
|---|---|---|
| `ZONE_EVENTS_INGEST_SUBJECT` | `alertmanager@platform` | The only identity allowed to post events |
| `ZONE_EVENTS_INGEST_TOKEN` | — | Its token, provisioned into the token store at startup; empty disables ingest and revokes a previously provisioned token |
| `ZONE_EVENTS_ALLOWED_CLASSES` | `DnsClientMisconfig` | Comma-separated event classes accepted (case-sensitive; for Alertmanager, alert names) |
| `ZONE_EVENTS_TTL_HOURS` | `24` | Lifetime of an event that is not re-reported; must comfortably exceed the producer's re-notification interval, or events flap out of view |
| `CAA_CHECK_INTERVAL_MINUTES` | `60` | Interval of the [CAA check](#caa-check); `0` = off |
| `CAA_CHECK_DELETE_RECORDS` | `false` | Whether the CAA check removes the CAA record sets it finds in user zones |

## Build & CI

- `make all` — embedded swagger + binary
- `make test` — Go test suite (integration tests, needs Docker)
- `make dev` — live reload (needs `air`)
- `make npm-package` / `make npm-publish` — build and publish `@dhbw-cloud/dynamic-zones-client` (Node.js); publishing is a manual step, and a prerelease version goes to the `next` dist-tag instead of `latest`
- `make bump V=X.Y.Z` — set `VERSION` and the chart's `version`/`appVersion`; `make version-check` fails when they disagree

**Releasing from this machine.** Waiting for CI is optional: `make bump V=x.y.z`, commit as `release x.y.z`, then `make publish`. It runs the tests (`make test`), builds the image for linux/amd64 (the build stage runs on the building machine and cross-compiles — the SQLite driver needs cgo, which is cross-compiled with tonistiigi/xx, so an arm64 Mac builds at native speed), pushes the image and the chart to GHCR and only then pushes the commits — well under a minute. CI then finds the version published and only verifies that it builds; Git tags and GitHub releases of stable versions are still made by CI. `make publish` refuses uncommitted changes and a version that is already published, so a registry version is always exactly one commit. It needs `docker login ghcr.io` and `helm registry login ghcr.io` with a token that may write packages.

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

An authoritative nameserver on the public internet is a reflection amplifier waiting to be used, so PowerDNS should not be exposed directly. Put [dnsdist](https://dnsdist.org/) in front of it and keep PowerDNS itself reachable only inside the cluster:

- **ANY over UDP is truncated** (`TC=1`), which forces a legitimate client to retry over TCP and gives a spoofed reflection source nothing worth amplifying.
- **Per-source rate limiting** over UDP, likewise answered with `TC=1` rather than a drop, so rate-limited but genuine clients still get through over TCP.
- **Bogon and blocklist sources are dropped** outright.
- **RFC 2136 UPDATE traffic and internal networks** are routed to the PowerDNS pool — that is the path this service and its users' keys take.
- PowerDNS's **HTTP API is cluster-internal**. Only this service talks to it; the API key never leaves the namespace.

Two things that will bite whoever hardens it further:

- **`disable-axfr` breaks this service.** It uses zone transfers internally, so switching them off wholesale is not an option — restrict them by address instead.
- **dnsdist has to run with `hostNetwork`.** Behind the cluster's service proxy the source address of every query is rewritten, which silently defeats both the rate limiting and the blocklists above, since every packet then appears to come from the same host.

### PowerDNS backend

`gsqlite3` and `gpgsql` are both supported and chosen per environment. With `gpgsql`, authoritative DNS depends on the database: if Postgres is gone, the nameserver stops answering. On a single-node installation that matters less than it sounds, but it is a coupling that did not exist with SQLite.

## Related projects

- [cloud-self-service](https://github.com/pfisterer/cloud-self-service) — the umbrella chart that composes all four
- [self-service-ui](https://github.com/pfisterer/self-service-ui) — the web interface
- [openstack-management-api](https://github.com/pfisterer/openstack-management-api) — the compute half of the platform

## License

See [LICENSE](./LICENSE).
