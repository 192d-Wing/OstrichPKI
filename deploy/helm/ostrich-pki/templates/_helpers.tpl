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
In-cluster CA gRPC URL. The CA exposes REST and gRPC on a single Service named
"<fullname>-ca"; gRPC listens on .Values.ca.grpc.service.port and only speaks
TLS 1.3 mutual TLS, so the scheme is always https. The CA gRPC server
certificate SAN must contain the host "<fullname>-ca" (or set
<component>.caGrpc.serverName to a name it does contain).

COMPLIANCE MAPPING:
- NIST 800-53: SC-8 (Transmission Confidentiality), AC-17 (mTLS inter-service)
*/}}
{{- define "ostrich-pki.caGrpcUrl" -}}
{{- printf "https://%s-ca:%d" (include "ostrich-pki.fullname" .) (.Values.ca.grpc.service.port | int) -}}
{{- end }}

{{/*
CA gRPC client allowlist, ";"-joined for CA_GRPC_ALLOWED_CLIENT_SUBJECTS
(commas are RDN separators inside a DN, so ";" delimits entries). Fails
rendering on an empty list or an entry containing ";" (fail closed: the CA
would refuse to start anyway).

COMPLIANCE MAPPING:
- NIST 800-53: AC-3 (Access Enforcement), AC-6 (Least Privilege), CM-6
- NIAP PP-CA: FDP_ACF.1, FMT_SMF.1
*/}}
{{- define "ostrich-pki.caGrpcAllowedSubjects" -}}
{{- $subjects := .Values.ca.grpc.allowedClientSubjects | default list -}}
{{- if not $subjects -}}
{{- fail "ca.grpc.allowedClientSubjects must list at least one client certificate subject DN (e.g. CN=acme-server); the CA gRPC API refuses to start with an empty allowlist" -}}
{{- end -}}
{{- range $subjects -}}
{{- if or (not .) (contains ";" .) -}}
{{- fail (printf "ca.grpc.allowedClientSubjects entry %q is empty or contains ';' (the list delimiter)" (toString .)) -}}
{{- end -}}
{{- end -}}
{{- join ";" $subjects -}}
{{- end }}

{{/*
CA gRPC mTLS client helpers for a gRPC client component (acme/est).

- caGrpcClientSecret: (dict "component" "acme" "cfg" .Values.acme.caGrpc)
  returns the client Secret name, failing rendering if it is unset.
- caGrpcClientEnv:    (dict "cfg" .Values.acme.caGrpc "root" .)
  returns the CA_GRPC_* env entries. The Secret is mounted read-only at
  /app/ca-grpc-client by the calling deployment template.

Rendering fails when clientTls.existingSecret is unset: the CA accepts only
mutually authenticated TLS 1.3, so a client without a certificate cannot work
(fail closed at deploy time rather than at first issuance). CA_GRPC_INSECURE is
never set by this chart.

COMPLIANCE MAPPING:
- NIST 800-53: SC-8, AC-17, IA-3, IA-5(2), SC-12 (key only via Secret file)
- NIAP PP-CA: FCS_TLSC_EXT.2, FTP_ITC.1
*/}}
{{- define "ostrich-pki.caGrpcClientSecret" -}}
{{- required (printf "%s.caGrpc.clientTls.existingSecret is required: the CA gRPC API only accepts mTLS client certificates (see docs/runbooks/ca-grpc-mtls.md)" .component) .cfg.clientTls.existingSecret -}}
{{- end }}

{{- define "ostrich-pki.caGrpcClientEnv" -}}
- name: CA_GRPC_URL
  value: {{ include "ostrich-pki.caGrpcUrl" .root | quote }}
- name: CA_GRPC_CLIENT_CERT_FILE
  value: {{ .cfg.clientTls.certFile | quote }}
- name: CA_GRPC_CLIENT_KEY_FILE
  value: {{ .cfg.clientTls.keyFile | quote }}
- name: CA_GRPC_CA_CERT_FILE
  value: {{ .cfg.clientTls.caFile | quote }}
{{- if .cfg.serverName }}
- name: CA_GRPC_SERVER_NAME
  value: {{ .cfg.serverName | quote }}
{{- end }}
{{- end }}

{{/*
Init container that blocks until the CA has been bootstrapped (an issuing,
CA certificate exists). Used by ca/est/ocsp/acme, which cannot serve before
the explicitly enabled bootstrap Job has completed.
the CA over gRPC and cannot serve before it is ready.
*/}}
{{- define "ostrich-pki.waitForCa" -}}
- name: wait-ca
  image: {{ include "ostrich-pki.postgresClientImage" . }}
  imagePullPolicy: {{ .Values.postgresClientImage.pullPolicy }}
  command: ["sh", "-c"]
  args:
    - |
      until psql "$DATABASE_URL" -tAc "SELECT 1 FROM ca_certificates WHERE not_after > NOW() LIMIT 1" 2>/dev/null | grep -q 1; do
        echo "waiting for CA bootstrap..."; sleep 3;
      done
  env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "ostrich-pki.databaseSecretName" . }}
          key: {{ include "ostrich-pki.databasePasswordKey" . | trim | quote }}
    - name: DATABASE_URL
      value: {{ include "ostrich-pki.databaseUrl" . }}
{{- end }}

{{/*
Name of the PVC containing the non-extractable SoftHSM token state.
*/}}
{{- define "ostrich-pki.hsmClaimName" -}}
{{- .Values.ca.hsm.tokenPersistence.existingClaim | default (printf "%s-hsm" (include "ostrich-pki.fullname" .)) -}}
{{- end }}

{{/*
Digest-pinned PostgreSQL client image for readiness init containers.
*/}}
{{- define "ostrich-pki.postgresClientImage" -}}
{{- $image := printf "%s:%s" .Values.postgresClientImage.repository .Values.postgresClientImage.tag -}}
{{- if .Values.postgresClientImage.digest -}}
{{- printf "%s@%s" $image .Values.postgresClientImage.digest -}}
{{- else -}}
{{- $image -}}
{{- end -}}
{{- end }}

{{/*
Database URL construction
*/}}
{{- define "ostrich-pki.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s-postgresql:5432/%s?sslmode=disable" .Values.postgresql.auth.username .Release.Name .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s:%d/%s?sslmode=%s" .Values.externalDatabase.user .Values.externalDatabase.host (.Values.externalDatabase.port | int) .Values.externalDatabase.database (.Values.externalDatabase.sslMode | default "require") }}
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
{{- printf "%s-postgresql" .Release.Name }}
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
      key: {{ include "ostrich-pki.databasePasswordKey" . | trim | quote }}
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
