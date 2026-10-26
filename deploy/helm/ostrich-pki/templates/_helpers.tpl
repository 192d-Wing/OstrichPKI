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
CA gRPC per-role client subject lists (per-method authorization).

- caGrpcClientSubjects: (dict "key" "acmeClientSubjects" "subjects" .Values.ca.grpc.acmeClientSubjects)
  returns one list ";"-joined for the matching CA_GRPC_*_CLIENT_SUBJECTS
  variable (commas are RDN separators inside a DN, so ";" delimits entries).
  An empty list renders "". Fails rendering when the value is not a list or an
  entry is empty or contains ";".
- caGrpcClientPolicy: (root context) validates the lists together and renders
  nothing. Fails rendering when the removed ca.grpc.allowedClientSubjects is
  set, when acmeClientSubjects and estClientSubjects are both empty (the CA
  needs at least one issuer client), or when the same DN string appears in more
  than one list (a client identity holds exactly one role). This is an exact-
  string early warning; ca-server repeats the check on the canonical RFC 4514
  form and refuses to start on any overlap (fail closed either way).

Roles (fixed in ca-server): acme/est = Issuer (IssueCertificate, GetCaInfo,
ListProfiles; requestor bound to "acme::"/"est::"); admin = Admin
(RevokeCertificate, GenerateCrl, CheckRevocationStatus, GetCaInfo,
ListProfiles; never IssueCertificate). Any unmapped RPC is denied.

COMPLIANCE MAPPING:
- NIST 800-53: AC-3 (Access Enforcement), AC-5 (Separation of Duties),
  AC-6 (Least Privilege), CM-6 (Configuration Settings)
- NIAP PP-CA: FDP_ACF.1, FMT_SMR.2, FMT_MTD.1
*/}}
{{- define "ostrich-pki.caGrpcClientSubjects" -}}
{{- $key := .key -}}
{{- $subjects := .subjects | default list -}}
{{- if not (kindIs "slice" $subjects) -}}
{{- fail (printf "ca.grpc.%s must be a list of subject DNs (one DN per item), not %s" $key (kindOf $subjects)) -}}
{{- end -}}
{{- range $subjects -}}
{{- if or (not .) (contains ";" (toString .)) -}}
{{- fail (printf "ca.grpc.%s entry %q is empty or contains ';' (the list delimiter)" $key (toString .)) -}}
{{- end -}}
{{- end -}}
{{- join ";" $subjects -}}
{{- end }}

{{/*
CA gRPC per-namespace issuance profile allowlists.

- caGrpcAllowedProfiles: (dict "key" "acmeAllowedProfiles" "profiles" .Values.ca.grpc.acmeAllowedProfiles)
  returns the list ";"-joined for CA_GRPC_{ACME,EST}_ALLOWED_PROFILES. Fails
  rendering when the value is not a list, an entry is empty or contains ";",
  or an entry names the intermediate_ca profile: CA profiles are never
  issuable by an Issuer client. ca-server additionally refuses to start on any
  unknown profile or any profile with basic_constraints_ca.
- caGrpcClientPolicy (below) fails rendering when a namespace with client
  subjects has an empty profile list (no silent "nothing allowed").

COMPLIANCE MAPPING:
- NIST 800-53: AC-3 (Access Enforcement), AC-6 (Least Privilege),
  CM-6 (Configuration Settings), CM-7 (Least Functionality)
- NIAP PP-CA: FDP_ACF.1, FMT_MTD.1
*/}}
{{- define "ostrich-pki.caGrpcAllowedProfiles" -}}
{{- $key := .key -}}
{{- $profiles := .profiles | default list -}}
{{- if not (kindIs "slice" $profiles) -}}
{{- fail (printf "ca.grpc.%s must be a list of profile names (one per item), not %s" $key (kindOf $profiles)) -}}
{{- end -}}
{{- range $profiles -}}
{{- $p := toString . -}}
{{- if or (not (trim $p)) (contains ";" $p) -}}
{{- fail (printf "ca.grpc.%s entry %q is empty or contains ';' (the list delimiter)" $key $p) -}}
{{- end -}}
{{- if eq (lower (trim $p)) "intermediate_ca" -}}
{{- fail (printf "ca.grpc.%s must not list %q: CA profiles are never allowed for gRPC Issuer clients" $key $p) -}}
{{- end -}}
{{- end -}}
{{- join ";" $profiles -}}
{{- end }}

{{- define "ostrich-pki.caGrpcClientPolicy" -}}
{{- $grpc := .Values.ca.grpc -}}
{{- if hasKey $grpc "allowedClientSubjects" -}}
{{- fail "ca.grpc.allowedClientSubjects was removed: split it into ca.grpc.acmeClientSubjects, ca.grpc.estClientSubjects and ca.grpc.adminClientSubjects (one role per DN; ca-server also refuses CA_GRPC_ALLOWED_CLIENT_SUBJECTS). See docs/runbooks/ca-grpc-mtls.md" -}}
{{- end -}}
{{- $lists := dict
      "acmeClientSubjects" ($grpc.acmeClientSubjects | default list)
      "estClientSubjects" ($grpc.estClientSubjects | default list)
      "adminClientSubjects" ($grpc.adminClientSubjects | default list) -}}
{{- range $key, $subjects := $lists -}}
{{- $_ := include "ostrich-pki.caGrpcClientSubjects" (dict "key" $key "subjects" $subjects) -}}
{{- end -}}
{{- if and (not $lists.acmeClientSubjects) (not $lists.estClientSubjects) -}}
{{- fail "ca.grpc.acmeClientSubjects and ca.grpc.estClientSubjects are both empty: list at least one issuer client subject DN (e.g. CN=acme-server); the CA gRPC API refuses to start with no issuer client" -}}
{{- end -}}
{{- range $ns := list "acme" "est" -}}
{{- $profKey := printf "%sAllowedProfiles" $ns -}}
{{- $profiles := get $grpc $profKey | default list -}}
{{- $_ := include "ostrich-pki.caGrpcAllowedProfiles" (dict "key" $profKey "profiles" $profiles) -}}
{{- if and (get $lists (printf "%sClientSubjects" $ns)) (not $profiles) -}}
{{- fail (printf "ca.grpc.%sClientSubjects is set but ca.grpc.%s is empty: list the end-entity profiles that namespace may request (ca-server refuses to start otherwise)" $ns $profKey) -}}
{{- end -}}
{{- end -}}
{{- $seen := dict -}}
{{- range $key := list "acmeClientSubjects" "estClientSubjects" "adminClientSubjects" -}}
{{- range (get $lists $key) -}}
{{- $dn := toString . -}}
{{- $prev := get $seen $dn -}}
{{- if and $prev (ne $prev $key) -}}
{{- fail (printf "gRPC client subject %q is listed in both ca.grpc.%s and ca.grpc.%s; a client identity may hold one role" $dn $prev $key) -}}
{{- end -}}
{{- $_ := set $seen $dn $key -}}
{{- end -}}
{{- end -}}
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

{{/*
ACME dns-01 upstream resolvers (acme.dns01Resolvers -> ACME_DNS01_RESOLVERS).

(root context) Validates the list and returns it ","-joined ("" when empty).
Used by the acme Deployment (env value) and the acme NetworkPolicy (one
ipBlock per entry). Fails rendering when:
- the value is not a list, or has more than 8 entries (MAX_DNS01_RESOLVERS);
- an entry is not a plain IPv4 dotted-quad or a plain hex IPv6 literal. No
  prefix length ('/'), port, zone ('%'), whitespace or newline is accepted,
  so an entry can never widen the rendered ipBlock or inject YAML;
- an entry is an IPv4-mapped IPv6 address (::ffff:a.b.c.d / ::ffff:xxxx:xxxx).
  acme-server canonicalises those to IPv4, so a /128 ipBlock for the mapped
  form would never match the actual traffic. List the plain IPv4 literal;
- the same string appears twice.
This is an early, syntax-level check. acme-server repeats full validation at
startup (unspecified, multicast, broadcast and duplicate after
canonicalisation all refuse startup), so both layers fail closed.

COMPLIANCE MAPPING:
- NIST 800-53: CM-6 (Configuration Settings), SC-7 (Boundary Protection),
  SI-10 (Information Input Validation)
*/}}
{{- define "ostrich-pki.acmeDns01Resolvers" -}}
{{- $resolvers := .Values.acme.dns01Resolvers | default list -}}
{{- if not (kindIs "slice" $resolvers) -}}
{{- fail (printf "acme.dns01Resolvers must be a list of IP literals (one per item), not %s" (kindOf $resolvers)) -}}
{{- end -}}
{{- if gt (len $resolvers) 8 -}}
{{- fail (printf "acme.dns01Resolvers has %d entries; at most 8 are allowed (MAX_DNS01_RESOLVERS)" (len $resolvers)) -}}
{{- end -}}
{{- $ipv4 := `^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$` -}}
{{- $ipv6 := `^[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}$` -}}
{{- $mapped := `(?i)^[0:]*:ffff:` -}}
{{- range $resolvers -}}
{{- if not (kindIs "string" .) -}}
{{- fail (printf "acme.dns01Resolvers entry %v must be a string IP literal, not %s" . (kindOf .)) -}}
{{- end -}}
{{- if not (or (regexMatch $ipv4 .) (regexMatch $ipv6 .)) -}}
{{- fail (printf "acme.dns01Resolvers entry %q is not a plain IPv4 or IPv6 literal (no prefix length '/', port, zone, whitespace or newline)" .) -}}
{{- end -}}
{{- if regexMatch $mapped . -}}
{{- fail (printf "acme.dns01Resolvers entry %q is an IPv4-mapped IPv6 address; list the plain IPv4 literal instead (the NetworkPolicy ipBlock must match the address acme-server actually uses)" .) -}}
{{- end -}}
{{- end -}}
{{- if ne (len (uniq $resolvers)) (len $resolvers) -}}
{{- fail "acme.dns01Resolvers contains a duplicate entry" -}}
{{- end -}}
{{- join "," $resolvers -}}
{{- end }}

{{/*
namespaceSelector (inline flow map) for the cluster DNS egress peer used by
every NetworkPolicy. Default networkPolicy.dnsNamespace "" renders {} (any
namespace; unchanged behaviour). Setting it (recommended: "kube-system", or
the namespace that runs cluster DNS) renders a kubernetes.io/metadata.name
match (label set on every namespace by Kubernetes >= 1.22), so a pod labelled
k8s-app=kube-dns in any other namespace cannot receive the services' DNS
traffic. Opt-in SC-7 hardening.

COMPLIANCE MAPPING:
- NIST 800-53: SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement)
*/}}
{{- define "ostrich-pki.dnsNamespaceSelector" -}}
{{- with .Values.networkPolicy.dnsNamespace -}}
{{- dict "matchLabels" (dict "kubernetes.io/metadata.name" (toString .)) | toJson -}}
{{- else -}}
{}
{{- end -}}
{{- end }}
