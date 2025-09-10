# Dynamic DNS Zone Provisioning API

This project provides an API service that allows users to dynamically create and manage DNS zones. It is particularly useful in automated environments such as Kubernetes.

## Overview

The API enables:

- **Dynamic DNS zone creation**: Users can request new DNS zones via the API.
- **Zone updates via RFC2136**: The created zones can be managed using RFC2136-compliant tools like `nsupdate` or Kubernetes' [external-dns](https://github.com/kubernetes-sigs/external-dns). [RCF2136](https://datatracker.ietf.org/doc/html/rfc2136) (Dynamic Updates in the Domain Name System) is a protocol for dynamic updates to DNS zones, allowing for real-time changes without manual intervention.
- **PowerDNS integration**: The service configures a [PowerDNS](https://doc.powerdns.com/) server through its API, enabling read and write access to managed zones.
- **Upstream DNS updates**: To integrate the configured PowerDNS server into the global DNS infrastructure, an upstream DNS server must be configured to delegate the managed zones. Alternatively, this project can itself update an A record in the upstream DNS via RFC2136.


### Prerequisites

Before you begin, ensure the following tools and services are installed and configured:

- **[Go (Golang)](https://go.dev/)**: Required for compiling and running the application.
- **[Air](https://github.com/cosmtrek/air)** (live reload for Go apps, optional but recommended): For hot-reloading during development.
- **[PowerDNS](https://www.powerdns.com/)**: Either running locally or in a container, with the [API enabled](https://doc.powerdns.com/authoritative/http-api/).
- **[Node.js and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)**: For building the API documentation and JavaScript client

### Development Setup

1. **Clone the repository**

    See GitHub's URL for cloning the repository.

1. **Start PowerDNS**:

    Create a PowerDNS configuration file (e.g., `pdns.conf`) with the following content:

    ```ini
    # PowerDNS configuration file
    local-address=0.0.0.0
    local-port=53

    # logLevel: 0 = emergency, 1 = alert, 2 = critical, 3 = error, 4 = warning, 5 = notice, 6 = info, 7 = debug
    loglevel=7

    # SQLite3
    launch=gsqlite3
    gsqlite3-database=/var/lib/powerdns/pdns.sqlite3

    # API
    webserver-address=0.0.0.0
    webserver-port=8080
    webserver-allow-from=0.0.0.0/0
    webserver-loglevel=normal # none, normal, detailed
    api=yes
    api-key=my-default-api-key # Replace with a secure key

    # Allow DSN updates but deny from any source here
    # cf. https://doc.powerdns.com/authoritative/dnsupdate.html#dnsupdate-metadata
    dnsupdate=yes
    allow-dnsupdate-from=
    dnsupdate-require-tsig=true
    ```

    Start PowerDNS (e.g, using Docker):

    ```bash
    docker run --rm -it \
    --name pdns-lua \
    -v $(pwd)/pdns.conf:/etc/powerdns/pdns.conf \
    -p 15353:53 \
    -p 15353:53/udp \
    -p 8080:8080 \
    powerdns/pdns-auth-master 
    ```

1. **Run with Air (development mode)**:

    ```bash
    air
    ```

1. **Run manually (production mode)**:

    ```bash
    make
    ./build/dynamic-zones-api
    ```
## Usage

### Docker-based Setup

#### Run using Docker

There are pre-built Docker images [available on GitHub Container Registry](https://github.com/pfisterer/dynamic-zones/pkgs/container/dynamic-zones). Check there for available tags or use the `latest` tag. Replace `KEY=VALUE` with the necessary environment variables as described in the [Configuration](#configuration) section.

You can then run it with:

```bash
docker run -d -p 8082:8082 -e KEY=VALUE \
    ghcr.io/pfisterer/dynamic-zones:latest
```

 or put the variables in a `.env` file and use `--env-file .env`.

```bash
docker run -d -p 8082:8082 --env-file .env \
    ghcr.io/pfisterer/dynamic-zones:latest
```

#### Build Local Docker Image

To build and run the API using Docker, you can use the provided `Makefile`:

```bash
make docker-build
```

This will create a Docker image for the API service. 

#### Build and Push multi-architecture Docker image

To build and push a multi-architecture Docker image, you can use the `Makefile`:

```bash
make multi-arch-build
```

## Configuration Settings

Configuration is done through environment variables. For a full list of available configuration options, refer to the `GetAppConfigFromEnvironment` function in `internal/app_setup.go`.

You’ll need to configure:
| **Environment Variable**                     | **Example Value**            | **Description**                                                 |
| -------------------------------------------- | ---------------------------- | --------------------------------------------------------------- |
| **General Settings**                         |                              |                                                                 |
| `DYNAMIC_ZONES_API_MODE`                     | `production`                 | Run mode; use `development` to enable dev mode                  |
| `DYNAMIC_ZONES_API_DOMAIN_SUFFIXES`          | `example.com, example2.org`  | Comma-separated list of allowed domain suffixes for new zones   |
| `DYNAMIC_ZONES_SERVER_DEFAULT_TTL`           | `31536000` (1 year)          | Default TTL in seconds for records in created zones             |
| `DYNAMIC_ZONES_API_DB_TYPE`                  | `sqlite`                     | Database backend type (e.g., `sqlite`, `postgres`, etc.)        |
| `DYNAMIC_ZONES_API_DB_CONNECTION_STRING`     | `file::memory:?cache=shared` | Connection string for the selected database                     |
| **API Server**                               |                              |                                                                 |
| `DYNAMIC_ZONES_API_BIND`                     | `:8082`                      | Address and port where the API service listens                  |
| `DYNAMIC_ZONES_API_BASE_URL`                 | `http://localhost:8082`      | Base URL used for building API responses and redirects          |
| **PowerDNS Configuration**                   |                              |                                                                 |
| `PDNS_URL`                                   | `http://localhost:8080`      | Base URL of the PowerDNS API                                    |
| `PDNS_VHOST`                                 | `localhost`                  | PowerDNS virtual host name                                      |
| `PDNS_API_KEY`                               | `my-default-api-key`         | API key for authenticating with PowerDNS                        |
| `DYNAMIC_ZONES_SERVER_ADDRESS`               | `localhost`                  | Address where the PowerDNS server listens                       |
| `DYNAMIC_ZONES_SERVER_PORT`                  | `15353`                      | Port number of the PowerDNS server (should be 53 in production) |
| **User Authentication**                      |                              |                                                                 |
| `DYNAMIC_ZONES_API_AUTH_PROVIDER`            | `""`                         | Authentication provider (`fake` or `oidc`)                      |
| `OIDC_ISSUER_URL`                            | `""`                         | OIDC issuer URL for authentication                              |
| `OIDC_CLIENT_ID`                             | `""`                         | Client ID for OIDC authentication                               |
| **Upstream DNS Updates**                     |                              |                                                                 |
| `DYNAMIC_ZONES_UPSTREAM_DNS_SERVER`          | `""`                         | Hostname or IP of the upstream DNS server for zone delegation   |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_NAME`       | `""`                         | TSIG key name used for authenticated DNS updates                |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_ALG`        | `""`                         | TSIG algorithm used (e.g., `hmac-sha256`)                       |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_SECRET`     | `""`                         | TSIG secret for secure DNS updates                              |
| `DYNAMIC_ZONES_UPSTREAM_DNS_PORT`            | `53`                         | Port number of the upstream DNS server                          |
| `DYNAMIC_ZONES_UPSTREAM_DNS_ZONE`            | `""`                         | Zone name in the upstream DNS server for delegation             |
| `DYNAMIC_ZONES_UPSTREAM_DNS_NAME`            | `""`                         | Name (typically an A record) to update in the upstream zone     |
| `DYNAMIC_ZONES_UPSTREAM_DNS_TTL`             | `900`                        | TTL (Time To Live) in seconds for upstream DNS records          |
| `DYNAMIC_ZONES_UPSTREAM_DNS_UPDATE_INTERVAL` | `3600`                       | How often (in seconds) the upstream record is updated           |

## Releasing a New Version

To release a new version of the API, follow these steps:
- Update the file `VERSION` with the new version number.
- Commit and push the changes to Github.
- Github Actions will automatically build the new version and create a release.

## License

 Apache License Version 2.0. See `LICENSE` file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
