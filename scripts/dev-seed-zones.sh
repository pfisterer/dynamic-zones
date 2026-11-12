#!/bin/sh
# Creates the dev user's zones (rules in initial_data_provider.js) on a local dynamic-zones-api in development mode, where a request without a bearer is the dev user root.admin@uni.example. Meant for a fresh in-memory database; a zone or owner that already exists only answers with an error, which is printed and ignored.
# Usage: scripts/dev-seed-zones.sh [base-url]   (default http://localhost:8082)
B="${1:-http://localhost:8082}"
ME=root-admin-at-uni-example.users.dhbw.site

i=0
until curl -fs -o /dev/null "$B/readyz"; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then echo "dev-seed-zones: dynamic-zones-api not ready"; exit 1; fi
    sleep 2
done

zone() { printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/v1/zones/$1")" "$1"; }
owner() { printf '%s %s + %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"email\":\"$2\"}" "$B/v1/zones/$1/owners")" "$1" "$2"; }

# Parents before their subzones: a subzone needs its stored parent.
for z in "$ME" "data-eng-wdski24a.$ME" "gridflex.$ME" "iot.$ME" \
    test.pfisterer.users.dhbw.site bigdata.pfisterer.users.dhbw.site ws2627.bigdata.pfisterer.users.dhbw.site \
    wi-ma.dhbw.site crm.wi-ma.dhbw.site \
    services.dhbw.cloud gpu.services.dhbw.cloud staging.gpu.services.dhbw.cloud itlabs.services.dhbw.cloud \
    llm.services.dhbw.cloud staging.llm.services.dhbw.cloud mail.services.dhbw.cloud workflow-auth.services.dhbw.cloud; do
    zone "$z"
done

# Co-owners, so the tree shows shared zones as on prod.
for z in wi-ma.dhbw.site crm.wi-ma.dhbw.site; do
    owner "$z" admin@cs.example
    owner "$z" faculty@cs.example
done
for z in services.dhbw.cloud gpu.services.dhbw.cloud staging.gpu.services.dhbw.cloud itlabs.services.dhbw.cloud llm.services.dhbw.cloud staging.llm.services.dhbw.cloud mail.services.dhbw.cloud workflow-auth.services.dhbw.cloud; do
    owner "$z" admin@cs.example
    owner "$z" faculty@bio.example
done
