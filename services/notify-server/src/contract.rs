//! Message contract shared by the producer (CA) and the notify-service roles.
//!
//! The types live in the `ostrich-notify-contract` crate so the producer and
//! both notify roles share one compiler-checked definition; this module just
//! re-exports them for the rest of the service.

pub use ostrich_notify_contract::{
    EmailJob, NotifyMessage, STREAM_NAME, SUBJECT_EMAIL, SUBJECT_NOTIFY, parse_time, period_key,
    send_weekdays,
};
