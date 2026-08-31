{{- define "webapp.name" -}}
{{- .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "webapp.fullname" -}}
{{- include "webapp.name" . -}}
{{- end -}}

{{- define "webapp.labels" -}}
app: {{ include "webapp.name" . }}
app.kubernetes.io/name: {{ include "webapp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "webapp.image" -}}
{{- if .Values.image.fullRef -}}
{{- .Values.image.fullRef -}}
{{- else if and .Values.image.repository .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- else -}}
{{- fail "no image: set image.fullRef (digest-pinned) or image.repository:tag" -}}
{{- end -}}
{{- end -}}
