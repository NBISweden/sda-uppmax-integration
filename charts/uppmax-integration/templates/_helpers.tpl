{{/*
Expand the name of the chart.
*/}}
{{- define "uppmax-integration.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}