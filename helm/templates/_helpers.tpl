{{/*
Expand the name of the chart.
*/}}
{{- define "quic-proxy-waf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "quic-proxy-waf.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "quic-proxy-waf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "quic-proxy-waf.labels" -}}
helm.sh/chart: {{ include "quic-proxy-waf.chart" . }}
{{ include "quic-proxy-waf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "quic-proxy-waf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quic-proxy-waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
WAF labels
*/}}
{{- define "quic-proxy-waf.waf.labels" -}}
{{ include "quic-proxy-waf.labels" . }}
app.kubernetes.io/component: waf
{{- end }}

{{/*
Proxy labels
*/}}
{{- define "quic-proxy-waf.proxy.labels" -}}
{{ include "quic-proxy-waf.labels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
WAF selector labels
*/}}
{{- define "quic-proxy-waf.waf.selectorLabels" -}}
{{ include "quic-proxy-waf.selectorLabels" . }}
app.kubernetes.io/component: waf
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "quic-proxy-waf.proxy.selectorLabels" -}}
{{ include "quic-proxy-waf.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Create the name of the WAF service
*/}}
{{- define "quic-proxy-waf.waf.serviceName" -}}
{{- printf "%s-waf" (include "quic-proxy-waf.fullname" .) }}
{{- end }}

{{/*
WAF image
*/}}
{{- define "quic-proxy-waf.waf.image" -}}
{{- $tag := .Values.waf.image.tag | default .Values.global.tag | default .Chart.AppVersion }}
{{- printf "%s/%s:%s" .Values.global.registry .Values.waf.image.repository $tag }}
{{- end }}

{{/*
Proxy image
*/}}
{{- define "quic-proxy-waf.proxy.image" -}}
{{- $tag := .Values.proxy.image.tag | default .Values.global.tag | default .Chart.AppVersion }}
{{- printf "%s/%s:%s" .Values.global.registry .Values.proxy.image.repository $tag }}
{{- end }}