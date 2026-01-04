//! Audit event sinks for persistence
//!
//! NIST 800-53: AU-9 - Protection of audit information
//! NIST 800-53: AU-10 - Non-repudiation

use crate::{AuditEvent, Error, Result};
use async_trait::async_trait;
use ostrich_db::{DatabasePool, repository::AuditRepository};

/// Trait for audit event sinks
///
/// NIST 800-53: AU-4 - Audit storage capacity
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record an audit event
    ///
    /// NIST 800-53: AU-2 - Auditable events
    /// NIST 800-53: AU-9(3) - Cryptographic protection via hash chain
    async fn record(&self, event: &mut AuditEvent) -> Result<()>;

    /// Verify the integrity of the audit log
    ///
    /// NIST 800-53: AU-9(3) - Verify audit information integrity
    async fn verify_integrity(&self) -> Result<bool>;

    /// Query events by various criteria
    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>>;
}

/// Criteria for querying audit events
#[derive(Debug, Clone)]
pub struct QueryCriteria {
    /// Filter by actor
    pub actor: Option<String>,

    /// Filter by event type
    pub event_type: Option<String>,

    /// Filter by time range
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,

    /// Limit number of results
    pub limit: Option<i64>,

    /// Offset for pagination
    pub offset: Option<i64>,
}

impl Default for QueryCriteria {
    fn default() -> Self {
        Self {
            actor: None,
            event_type: None,
            start_time: None,
            end_time: None,
            limit: Some(100),
            offset: None,
        }
    }
}

/// Database-backed audit sink with hash chain integrity
///
/// NIST 800-53: AU-9 - Audit information stored in database
/// NIST 800-53: AU-9(3) - Hash chain for integrity protection
pub struct DatabaseAuditSink {
    repository: AuditRepository,
}

impl DatabaseAuditSink {
    /// Create a new database audit sink
    pub fn new(pool: DatabasePool) -> Self {
        Self {
            repository: AuditRepository::new(pool),
        }
    }

    /// Convert database model to audit event
    fn from_db_model(db_event: ostrich_db::models::AuditEvent) -> AuditEvent {
        use crate::{EventOutcome, EventType};

        // Parse event type
        let event_type = match db_event.event_type.as_str() {
            "authentication" => EventType::Authentication,
            "authorization" => EventType::Authorization,
            "certificate_issuance" => EventType::CertificateIssuance,
            "certificate_revocation" => EventType::CertificateRevocation,
            "crl_generation" => EventType::CrlGeneration,
            "key_generation" => EventType::KeyGeneration,
            "key_escrow" => EventType::KeyEscrow,
            "key_recovery" => EventType::KeyRecovery,
            "key_destruction" => EventType::KeyDestruction,
            "configuration_change" => EventType::ConfigurationChange,
            "access_violation" => EventType::AccessViolation,
            "token_lifecycle" => EventType::TokenLifecycle,
            "acme_protocol" => EventType::AcmeProtocol,
            "est_protocol" => EventType::EstProtocol,
            "system" => EventType::System,
            "database" => EventType::Database,
            _ => EventType::Other,
        };

        // Parse outcome
        let outcome = match db_event.outcome.as_str() {
            "success" => EventOutcome::Success,
            "failure" => EventOutcome::Failure,
            _ => EventOutcome::Error,
        };

        AuditEvent {
            id: db_event.id,
            event_type,
            actor: db_event.actor,
            target: db_event.target,
            action: db_event.action,
            outcome,
            details: db_event.details,
            ip_address: db_event.ip_address,
            user_agent: db_event.user_agent,
            session_id: db_event.session_id,
            previous_hash: db_event.previous_hash,
            event_hash: db_event.event_hash,
            timestamp: db_event.timestamp,
        }
    }
}

#[async_trait]
impl AuditSink for DatabaseAuditSink {
    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        // Compute event hash with chain integrity
        event.event_hash = event.compute_hash();

        // Store in database (repository will handle previous_hash linking)
        let db_event = event.to_db_model();
        self.repository
            .append(&db_event)
            .await
            .map_err(Error::Database)?;

        tracing::debug!(
            "Audit event recorded: {} - {} {} on {}",
            event.event_type.as_str(),
            event.actor,
            event.action,
            event.target
        );

        // Log security-relevant events at info level
        if event.event_type.is_security_relevant() {
            tracing::info!(
                "Security event: {} by {} on {} - {}",
                event.action,
                event.actor,
                event.target,
                event.outcome.as_str()
            );
        }

        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        self.repository
            .verify_chain()
            .await
            .map_err(Error::Database)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let db_events = if let Some(actor) = criteria.actor {
            self.repository
                .find_by_actor(&actor, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let Some(event_type) = criteria.event_type {
            self.repository
                .find_by_type(&event_type, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let (Some(start), Some(end)) = (criteria.start_time, criteria.end_time) {
            self.repository
                .find_by_time_range(start, end, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else {
            use ostrich_db::repository::Repository;
            self.repository
                .list(criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        };

        Ok(db_events.into_iter().map(Self::from_db_model).collect())
    }
}

/// In-memory audit sink for testing
///
/// WARNING: Not suitable for production use - no persistence
#[cfg(any(test, feature = "testing"))]
pub struct MemoryAuditSink {
    events: tokio::sync::RwLock<Vec<AuditEvent>>,
}

#[cfg(any(test, feature = "testing"))]
impl Default for MemoryAuditSink {
    fn default() -> Self {
        Self {
            events: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        let mut events = self.events.write().await;

        // Get previous hash
        event.previous_hash = events.last().map(|e| e.event_hash.clone());

        // Compute this event's hash
        event.event_hash = event.compute_hash();

        events.push(event.clone());
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        let events = self.events.read().await;

        if events.is_empty() {
            return Ok(true);
        }

        let mut prev_hash: Option<Vec<u8>> = None;

        for event in events.iter() {
            if event.previous_hash != prev_hash {
                return Ok(false);
            }

            // Verify hash computation
            let computed_hash = event.compute_hash();
            if computed_hash != event.event_hash {
                return Ok(false);
            }

            prev_hash = Some(event.event_hash.clone());
        }

        Ok(true)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let mut filtered: Vec<AuditEvent> = events
            .iter()
            .filter(|e| {
                if let Some(ref actor) = criteria.actor
                    && e.actor != *actor
                {
                    return false;
                }
                if let Some(ref event_type) = criteria.event_type
                    && e.event_type.as_str() != event_type
                {
                    return false;
                }
                if let Some(start) = criteria.start_time
                    && e.timestamp < start
                {
                    return false;
                }
                if let Some(end) = criteria.end_time
                    && e.timestamp > end
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Apply limit and offset
        let offset = criteria.offset.unwrap_or(0) as usize;
        let limit = criteria.limit.unwrap_or(100) as usize;

        if offset < filtered.len() {
            filtered = filtered[offset..].to_vec();
        } else {
            filtered.clear();
        }

        if filtered.len() > limit {
            filtered.truncate(limit);
        }

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventBuilder, EventOutcome, EventType};

    #[tokio::test]
    async fn test_memory_sink_chain_integrity() {
        let sink = MemoryAuditSink::new();

        // Record first event
        let mut event1 = AuditEventBuilder::new(
            EventType::Authentication,
            "user1",
            "system",
            "login",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event1).await.unwrap();

        // Record second event
        let mut event2 = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            "ca-service",
            "cert-123",
            "issue",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event2).await.unwrap();

        // Verify integrity
        assert!(sink.verify_integrity().await.unwrap());

        // Verify chain link
        assert_eq!(event2.previous_hash, Some(event1.event_hash.clone()));
    }

    #[tokio::test]
    async fn test_memory_sink_query() {
        let sink = MemoryAuditSink::new();

        // Record events
        for i in 0..5 {
            let mut event = AuditEventBuilder::new(
                EventType::Authentication,
                format!("user{}", i),
                "system",
                "login",
                EventOutcome::Success,
            )
            .build();

            sink.record(&mut event).await.unwrap();
        }

        // Query all events
        let criteria = QueryCriteria::default();
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 5);

        // Query by actor
        let criteria = QueryCriteria {
            actor: Some("user2".to_string()),
            ..Default::default()
        };
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user2");
    }
}
