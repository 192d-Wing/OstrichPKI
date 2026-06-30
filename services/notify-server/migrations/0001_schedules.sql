-- notify-service schema (its own database; independent of ostrich_pki).

-- One active notification schedule per certificate (upserted by the producer).
CREATE TABLE IF NOT EXISTS schedules (
    certificate          text PRIMARY KEY,
    valid_from           timestamptz NOT NULL,
    valid_to             timestamptz NOT NULL,
    notification_emails  text[]      NOT NULL DEFAULT '{}',
    frequency            text        NOT NULL DEFAULT 'weekly',
    notification_time    time        NOT NULL DEFAULT '09:00:00',
    notification_days    text[]      NOT NULL DEFAULT '{}',
    subject              text        NOT NULL,
    body                 text        NOT NULL DEFAULT '',
    notify_days_before   integer     NOT NULL DEFAULT 90,
    active               boolean     NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_schedules_active ON schedules (active, valid_to);

-- De-dup ledger: at most one send per (certificate, window). The scheduler
-- atomically claims a window before publishing an email job, so a cert is
-- emailed at most once per send-day even across scheduler restarts/replicas.
CREATE TABLE IF NOT EXISTS sent_notifications (
    certificate text        NOT NULL,
    window_key  text        NOT NULL,
    queued_at   timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz,
    PRIMARY KEY (certificate, window_key)
);
