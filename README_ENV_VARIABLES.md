
## ⚙️ Environment Variables Reference

| **Variable Name** | **Default Value** | **Validation** | **Description** |
| :---: | :---: | :---: | :--- |
| **Zone Provider Settings** | | | |
| `ZONE_PROVIDER_WEBHOOK_BEARER_TOKEN` | `''` | Required if **Provider** is set to `webhook` | The webhook bearer token for zone provider "webhook" |
| `ZONE_PROVIDER_SCRIPT_PATH` | `''` | Required if **Provider** is set to `script`<br>Custom rule: `omitempty` | The script path for zone provider "script" |
| `ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_NAME` | `''` | Custom rule: `omitempty` | TSIG key name for admin updates, added to all zones (intermediate and requested)provider |
| `ZONE_PROVIDER_FIXED_DOMAIN_SOA` | `example.com, example2.org` | Required if **Provider** is set to `fixed` | Comma-separated list of fixed domains where SOA of this nameserver starts (in the same order as FixedDomainSuffixes, e.g., "example.com, example2.org") |
| `ZONE_PROVIDER_TYPE` | `fixed` | Must be one of: `fixed, webhook, script` | The type of zone provider |
| `ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_KEY` | `''` | Custom rule: `omitempty` | TSIG key for for admin updates, added to all zones (intermediate and requested)provider |
| `ZONE_PROVIDER_DEFAULT_RECORDS` | `[]` | Custom rule: `omitempty` | List of default records to create in each new zone for "fixed" provider (e.g., ""[{"name":"_acme-challenge","type":"CNAME","content":"auth.my-proxy.int","ttl":300}]"") |
| `ZONE_PROVIDER_WEBHOOK_URL` | `''` | Required if **Provider** is set to `webhook`<br>Custom rule: `omitempty`<br>Must be a valid URL | The webhook URL for zone provider "webhook" |
| `ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_ALG` | `''` | Custom rule: `omitempty` | TSIG algorithm for for admin updates, added to all zones (intermediate and requested)provider |
| `ZONE_PROVIDER_FIXED_DOMAIN_SUFFIXES` | `test.example.com, demo.example2.org` | Required if **Provider** is set to `fixed` | No doc comment provided. |
| **General Settings** | | | |
| `API_MODE` | `'production' (defaults to false)` | *(None)* | Flag indicating if the application is running in development mode |
| **Upstream DNS Updates** | | | |
| `UPSTREAM_DNS_TSIG_ALG` | `''` | *(None)* | TSIG algorithm for DNS updates |
| `UPSTREAM_DNS_UPDATE_INTERVAL` | `60 * 60` | *(None)* | Interval in seconds between DNS updates |
| `UPSTREAM_DNS_TSIG_SECRET` | `''` | Custom rule: `omitempty`<br>Must be a valid Base64 string | TSIG secret for authenticating DNS updates |
| `UPSTREAM_DNS_TTL` | `900` | *(None)* | Time to live for DNS records |
| `UPSTREAM_DNS_ZONE` | `''` | **Required** | DNS zone to be updated, also the zone this server is authoritative for (e.g., "example.com") |
| `UPSTREAM_DNS_NAME` | `''` | *(None)* | The name of the record (relative to the zone, e.g., "_acme-challenge") |
| `UPSTREAM_DNS_TSIG_NAME` | `''` | *(None)* | TSIG key name for authenticating DNS updates |
| `UPSTREAM_DNS_SERVER` | `''` | *(None)* | The DNS server to which updates will be sent |
| **PowerDNS Configuration** | | | |
| `PDNS_URL` | `http://localhost:8080` | **Required**<br>Must be a valid URL | The URL of the PowerDNS API (e.g., http://localhost:8080) |
| `PDNS_API_KEY` | `my-default-api-key` | **Required** | The API key for authenticating with PowerDNS |
| `PDNS_VHOST` | `localhost` | **Required** | The vhost header to use when connecting to PowerDNS |
| `PDNS_SERVER_ADDRESS` | `localhost` | **Required**<br>Must be a valid IP address | The address where the Power DNS server listens for queries (e.g., 127.0.0.53) |
| **Storage Configuration** | | | |
| `DB_TYPE` | `sqlite` | Must be one of: `sqlite, postgres, mysql` | The type of database to use |
| `DB_CONNECTION_STRING` | `file::memory:?cache=shared` | **Required** | The connection string for the database (using GORM format) |
| **API Server Configuration** | | | |
| `OIDC_CLIENT_ID` | `''` | Required if **AuthProvider** is set to `oidc` | The OIDC client ID for authentication |
| `EXTERNAL_DNS_IMAGE_VERSION` | `v0.19.0` | **Required** | The version of the external DNS image to use |
| `API_BIND` | `:8082` | **Required** | The bind string for the Gin web server (e.g., ":8082") |
| `API_AUTH_PROVIDER` | `''` | Must be one of: `fake, oidc` | The authentication provider to use (e.g., "oidc", "fake") |
| `API_BASE_URL` | `http://localhost:8082` | **Required**<br>Must be a valid URL | The base URL for the web server (e.g., "http://localhost:8082") |
| `OIDC_ISSUER_URL` | `''` | Required if **AuthProvider** is set to `oidc`<br>Must be a valid URL | The OIDC issuer URL for authentication |
| `API_TOKEN_TTL_HOURS` | `24` | *(None)* | The TTL (in hours) for API tokens |
