{{/*
Expand the name of the chart.
*/}}
{{- define "uppmax-integration.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "TLSissuer" -}}
    {{- if and .Values.global.tls.clusterIssuer .Values.global.tls.issuer }}
        {{- fail "Only one of global.tls.issuer or global.tls.clusterIssuer should be set" }}
    {{- end -}}

    {{- if .Values.global.tls.issuer }}
        {{- printf "%s" .Values.global.tls.issuer }}
    {{- else if and .Values.global.tls.clusterIssuer }}
        {{- printf "%s" .Values.global.tls.clusterIssuer }}
    {{- end -}}
{{- end -}}
