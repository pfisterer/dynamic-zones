package helper

import _ "embed"

//go:embed "external-dns-helm-values.yaml.tmpl"
var ExternalDNSValuesYamlTemplate string

//go:embed "external-dns-secret.yaml.tmpl"
var ExternalDNSSecretYamlTemplate string

//go:embed "VERSION"
var AppVersion string
