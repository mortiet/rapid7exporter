{{/*
Expand the name of the chart.
*/}}
{{- define "rapid7exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rapid7exporter.fullname" -}}
{{- printf "%s-%s" (include "rapid7exporter.name" .) .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rapid7exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
  {{ include "rapid7exporter.fullname" . }}
{{- else -}}
  {{- default "" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
