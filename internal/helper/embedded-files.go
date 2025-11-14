package helper

import _ "embed"

//go:embed "external-dns-helm-values.yaml.tmpl"
var ExternalDNSValuesYamlTemplate string

//go:embed "VERSION"
var AppVersion string
