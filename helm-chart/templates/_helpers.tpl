{{/* Base chart name */}}
{{- define "dynamic-zones.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/* Fully qualified release name */}}
{{- define "dynamic-zones.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* Chart label */}}
{{- define "dynamic-zones.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/* Common labels, optionally scoped to a component */}}
{{- define "dynamic-zones.labels" -}}
app.kubernetes.io/name: {{ include "dynamic-zones.name" .context }}
helm.sh/chart: {{ include "dynamic-zones.chart" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
{{- if .component }}
app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end }}

{{/* Selector labels, optionally scoped to a component */}}
{{- define "dynamic-zones.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dynamic-zones.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- if .component }}
app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end }}

{{/*
Component-scoped name.

The suffix is dropped where it would only repeat what the base name already
says — the main component is called "dynamic-zones" and so is the chart, which
used to produce "dynamic-zones-dynamic-zones". Secondary components (postgres,
…) still get their suffix.
*/}}
{{- define "dynamic-zones.componentName" -}}
{{- $ctx := .context -}}
{{- $component := .component | default "" -}}
{{- $base := include "dynamic-zones.fullname" $ctx -}}
{{- if or (not $component) (eq $base $component) (hasSuffix (printf "-%s" $component) $base) -}}
{{- $base -}}
{{- else -}}
{{- printf "%s-%s" $base $component | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/* Component-scoped name with optional suffix for individual resources */}}
{{- define "dynamic-zones.resourceName" -}}
{{- $base := include "dynamic-zones.componentName" . -}}
{{- $suffix := .name | default "" -}}
{{- if $suffix -}}
{{- printf "%s-%s" $base $suffix | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $base -}}
{{- end -}}
{{- end }}

{{/* Standard rollout annotations to trigger pod restarts on config/template changes */}}
{{- define "dynamic-zones.rolloutAnnotations" -}}
# 1. Responds to any change in the Values (becomes a JSON string -> Hash)
checksum/values: {{ .Values | toJson | sha256sum }}
# 2. Responds to the path of the Templates (as a string)
checksum/all-templates: {{ .Template.BasePath | sha256sum }}
{{- end }}
