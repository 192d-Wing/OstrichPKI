{{/*
OstrichPKI Helm Chart Helper Templates

COMPLIANCE MAPPING:
- NIST 800-53: CM-2 (Baseline Configuration)
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "ostrich-pki.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "ostrich-pki.fullname" -}}
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
{{- define "ostrich-pki.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ostrich-pki.labels" -}}
helm.sh/chart: {{ include "ostrich-pki.chart" . }}
{{ include "ostrich-pki.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ostrich-pki.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ostrich-pki.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ostrich-pki.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ostrich-pki.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create image name with registry
*/}}
{{/*
Per-service image name.

Each service ships as its own image, published as
  <registry>/<service>-service:<tag>
by .github/workflows/docker-publish.yml (e.g. ghcr.io/192d-wing/ca-service).

Call with: (dict "service" "ca" "repository" .Values.ca.image.repository "tag" .Values.ca.image.tag "root" .)
- service:    short name ("ca","acme","est","ocsp"); used to derive "<service>-service"
- repository: optional per-service override of the full image repository
- tag:        optional per-service tag override
- root:       the root context (.)
*/}}
{{- define "ostrich-pki.image" -}}
{{- $registry := .root.Values.global.imageRegistry | default .root.Values.image.registry -}}
{{- $repository := .repository | default (printf "%s-service" .service) -}}
{{- $tag := .tag | default .root.Values.image.tag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- end }}

{{/*
In-cluster CA gRPC URL. The CA exposes REST (http) and gRPC on a single
Service named "<fullname>-ca"; gRPC listens on .Values.ca.grpc.service.port.
*/}}
{{- define "ostrich-pki.caGrpcUrl" -}}
{{- printf "http://%s-ca:%d" (include "ostrich-pki.fullname" .) (.Values.ca.grpc.service.port | int) -}}
{{- end }}

{{/*
Init container that blocks until the CA has been bootstrapped (an issuing,
non-root CA certificate exists). Used by est/ocsp/acme, which finalize against
the CA over gRPC and cannot serve before it is ready.
*/}}
{{- define "ostrich-pki.waitForCa" -}}
- name: wait-ca
  image: postgres:16-alpine
  command: ["sh", "-c"]
  args:
    - |
      until psql "$DATABASE_URL" -tAc "SELECT 1 FROM ca_certificates WHERE is_root = false LIMIT 1" 2>/dev/null | grep -q 1; do
        echo "waiting for CA bootstrap..."; sleep 3;
      done
  env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "ostrich-pki.databaseSecretName" . }}
          key: {{ include "ostrich-pki.databasePasswordKey" . }}
    - name: DATABASE_URL
      value: {{ include "ostrich-pki.databaseUrl" . }}
{{- end }}

{{/*
Database URL construction
*/}}
{{- define "ostrich-pki.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s-postgresql:5432/%s" .Values.postgresql.auth.username (include "ostrich-pki.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s:%d/%s" .Values.externalDatabase.user .Values.externalDatabase.host (.Values.externalDatabase.port | int) .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
Database secret name
*/}}
{{- define "ostrich-pki.databaseSecretName" -}}
{{- if .Values.postgresql.enabled }}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecret }}
{{- else }}
{{- printf "%s-postgresql" (include "ostrich-pki.fullname" .) }}
{{- end }}
{{- else }}
{{- if .Values.externalDatabase.existingSecret }}
{{- .Values.externalDatabase.existingSecret }}
{{- else }}
{{- printf "%s-external-db" (include "ostrich-pki.fullname" .) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Database password key in secret
*/}}
{{- define "ostrich-pki.databasePasswordKey" -}}
{{- if .Values.postgresql.enabled }}
password
{{- else }}
{{- .Values.externalDatabase.existingSecretPasswordKey | default "password" }}
{{- end }}
{{- end }}

{{/*
Common environment variables for all services
*/}}
{{- define "ostrich-pki.commonEnv" -}}
- name: RUST_LOG
  value: {{ .Values.logging.level | quote }}
- name: LOG_JSON
  value: {{ .Values.logging.json | quote }}
- name: DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "ostrich-pki.databaseSecretName" . }}
      key: {{ include "ostrich-pki.databasePasswordKey" . }}
- name: DATABASE_URL
  value: {{ include "ostrich-pki.databaseUrl" . }}
{{- end }}

{{/*
Pod security context
*/}}
{{- define "ostrich-pki.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext }}
{{- end }}

{{/*
Container security context
*/}}
{{- define "ostrich-pki.securityContext" -}}
{{- toYaml .Values.securityContext }}
{{- end }}
