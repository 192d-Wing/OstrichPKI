# Notify subsystem (certificate-expiry notifications)

Decoupled notification pipeline: the CA publishes per-certificate schedules to
**NATS JetStream**; the **notify-scheduler** stores them in its own Postgres and
publishes due emails to `email.send`; the **notify-sender** delivers them via an
SMTP relay.

```
CA (producer) ──cert.expiry.notify──▶ NATS JetStream ──▶ notify-scheduler ──email.send──▶ notify-sender ──▶ SMTP
                                                              │ (own Postgres: schedules + dedup)
```

## Components
| Resource | Purpose |
|---|---|
| `nats` | JetStream broker (`NOTIFY` stream; subjects `cert.expiry.notify`, `email.send`) |
| `notify-postgres` | Dedicated DB for the notify-service (schedules + send dedup) — independent of `ostrich_pki` |
| `notify-scheduler` | Consumes schedules; ticks on day/time/frequency; publishes due emails |
| `notify-sender` | Consumes emails; delivers via SMTP (plain or STARTTLS) |

## Prerequisites
1. **DB secret** (also used to build the connection string):
   ```sh
   PW='choose-a-strong-password'
   kubectl -n ostrich-pki create secret generic notify-db-secret \
     --from-literal=password="$PW" \
     --from-literal=database-url="postgres://notify:${PW}@notify-postgres:5432/notify"
   ```
2. **SMTP relay + config** — edit the git-controlled variable file
   [`notify.env`](notify.env) (`SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`,
   `SMTP_SECURITY` (none|starttls|tls), `SMTP_TLS_PORT`, `NATS_URL`,
   `NOTIFY_TICK_SECONDS`). kustomize folds it into a
   hashed `notify-config` ConfigMap that both deployments read via `envFrom`, so
   editing it and re-applying rolls the pods automatically. The sender refuses to
   start without `SMTP_HOST`. If the relay needs auth, put the password in a
   `notify-smtp-secret` and uncomment `SMTP_PASSWORD` in `notify-deployments.yaml`
   (secrets never go in `notify.env`).

## Deploy
```sh
kubectl apply -k deploy/kubernetes/notify/
kubectl -n ostrich-pki rollout status deploy/nats deploy/notify-postgres \
  deploy/notify-scheduler deploy/notify-sender
```

## Smoke test (publish a schedule by hand)
```sh
# from a NATS box / nats CLI pod:
nats --server nats://nats:4222 pub cert.expiry.notify '{
  "certificate":"cn=test.oopl.dev.mil",
  "valid_from":"2026-01-01T00:00:00Z",
  "valid_to":"2026-07-15T00:00:00Z",
  "notification_emails":["you@oopl.dev.mil"],
  "notification_frequency":"daily",
  "notification_time":"00:00:00Z",
  "notification_days":["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"],
  "notification_subject":"Certificate Expiration Notification",
  "notification_body":"test.oopl.dev.mil expires soon — please renew.",
  "notify_days_before_expiration":90
}'
```
The scheduler upserts it; on the next tick (≤5 min) it queues an email and the
sender delivers it.
