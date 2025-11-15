
## ⚙️ Environment Variables Reference

### Upstream DNS Updates

| **Variable Name**                            | **Default Value**   | **Description**                              |
| :------------------------------------------- | :------------------ | :------------------------------------------- |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_NAME`       | `'' (empty string)` | TSIG key name for authenticating DNS updates |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_ALG`        | `'' (empty string)` | TSIG algorithm for DNS updates               |
| `DYNAMIC_ZONES_UPSTREAM_DNS_NAME`            | `'' (empty string)` | Name within the DNS zone to be updated       |
| `DYNAMIC_ZONES_UPSTREAM_DNS_SERVER`          | `'' (empty string)` | The DNS server to which updates will be sent |
| `DYNAMIC_ZONES_UPSTREAM_DNS_PORT`            | `53`                | Port of the DNS server                       |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TTL`             | `900`               | Time to live for DNS records                 |
| `DYNAMIC_ZONES_UPSTREAM_DNS_UPDATE_INTERVAL` | `60 * 60`           | Interval in seconds between DNS updates      |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_SECRET`     | `'' (empty string)` | TSIG secret for authenticating DNS updates   |
| `DYNAMIC_ZONES_UPSTREAM_DNS_ZONE`            | `'' (empty string)` | DNS zone to be updated                       |

### PowerDNS Configuration

| **Variable Name**              | **Default Value**       | **Description**                                                               |
| :----------------------------- | :---------------------- | :---------------------------------------------------------------------------- |
| `PDNS_VHOST`                   | `localhost`             | The vhost header to use when connecting to PowerDNS                           |
| `DYNAMIC_ZONES_SERVER_ADDRESS` | `localhost`             | The address where the Power DNS server listens for queries (e.g., 127.0.0.53) |
| `PDNS_URL`                     | `http://localhost:8080` | The URL of the PowerDNS API (e.g., http://localhost:8080)                     |
| `PDNS_API_KEY`                 | `my-default-api-key`    | The API key for authenticating with PowerDNS                                  |

### Storage Configuration

| **Variable Name**                        | **Default Value**            | **Description**                                                |
| :--------------------------------------- | :--------------------------- | :------------------------------------------------------------- |
| `DYNAMIC_ZONES_API_DB_TYPE`              | `sqlite`                     | The type of database to use (e.g., sqlite, postgres, or mysql) |
| `DYNAMIC_ZONES_API_DB_CONNECTION_STRING` | `file::memory:?cache=shared` | The connection string for the database (using GORM format)     |

### API Server Configuration

| **Variable Name**                          | **Default Value**       | **Description**                                                 |
| :----------------------------------------- | :---------------------- | :-------------------------------------------------------------- |
| `DYNAMIC_ZONES_API_BIND`                   | `:8082`                 | The bind string for the Gin web server (e.g., ":8082")          |
| `OIDC_ISSUER_URL`                          | `'' (empty string)`     | The OIDC issuer URL for authentication                          |
| `DYNAMIC_ZONES_API_BASE_URL`               | `http://localhost:8082` | The base URL for the web server (e.g., "http://localhost:8082") |
| `DYNAMIC_ZONES_API_TOKEN_TTL_HOURS`        | `24`                    | The TTL (in hours) for API tokens                               |
| `DYNAMIC_ZONES_EXTERNAL_DNS_IMAGE_VERSION` | `v0.19.0`               | The version of the external DNS image to use                    |
| `DYNAMIC_ZONES_API_AUTH_PROVIDER`          | `'' (empty string)`     | The authentication provider to use (e.g., "oidc", "fake")       |
| `OIDC_CLIENT_ID`                           | `'' (empty string)`     | The OIDC client ID for authentication                           |

### Zone Provider Settings

| **Variable Name**                   | **Default Value**           | **Description**                 |
| :---------------------------------- | :-------------------------- | :------------------------------ |
| `DYNAMIC_ZONES_API_DOMAIN_SUFFIXES` | `example.com, example2.org` | No documentation comment found. |

### General Settings

| **Variable Name**        | **Default Value**                  | **Description**                                                   |
| :----------------------- | :--------------------------------- | :---------------------------------------------------------------- |
| `DYNAMIC_ZONES_API_MODE` | `'production' (defaults to false)` | Flag indicating if the application is running in development mode |
