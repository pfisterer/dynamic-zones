package helper

import _ "embed"

//go:embed "external-dns.yaml.tmpl"
var ExternalDNSYamlTemplate string

//go:embed "VERSION"
var AppVersion string
