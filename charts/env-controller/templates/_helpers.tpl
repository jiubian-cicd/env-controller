{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}

{{- define "env.controller.name" -}}
{{- default "env-controller" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

