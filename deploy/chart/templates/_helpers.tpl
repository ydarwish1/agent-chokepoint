{{/*
Name helpers. Standard app.kubernetes.io/* convention — the NetworkPolicy's
podSelector and the Deployment's selector both render from
`agent-chokepoint.selectorLabels`, so they cannot drift apart. A NetworkPolicy
whose podSelector matches nothing is silently vacuous, which would make every
"the NetworkPolicy blocked it" claim in this directory meaningless.
*/}}

{{- define "agent-chokepoint.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agent-chokepoint.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agent-chokepoint.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The ONLY definition of the matching labels. Used by the Deployment
selector, the pod template, and the NetworkPolicy podSelector. */}}
{{- define "agent-chokepoint.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agent-chokepoint.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agent-chokepoint.labels" -}}
helm.sh/chart: {{ include "agent-chokepoint.chart" . }}
{{ include "agent-chokepoint.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Dedicated ServiceAccount, named for the release. */}}
{{- define "agent-chokepoint.serviceAccountName" -}}
{{- include "agent-chokepoint.fullname" . -}}
{{- end -}}
