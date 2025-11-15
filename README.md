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

Configuration is done through environment variables. 

For a full list of available configuration options, see [README_ENV_VARIABLES.md](README_ENV_VARIABLES.md) or refer to the `GetAppConfigFromEnvironment` function in `internal/app_setup.go`.

## Releasing a New Version

To release a new version of the API, follow these steps:
- Update the file `internal/helper/VERSION` with the new version number.
- Commit and push the changes to Github.
- Github Actions will automatically build the new version and create a release.

## License

 Apache License Version 2.0. See `LICENSE` file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
