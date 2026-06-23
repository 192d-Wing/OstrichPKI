//! Trust Anchor Management Protocol (RFC 5934) repository.
//!
//! Persists the TAMP *manager's* authoritative view of each target's trust
//! anchor store, community memberships, and — critically — the per-signer
//! monotonic sequence numbers that provide durable replay protection
//! (RFC 5934 §4.1). The sequence-number advance is performed under a row lock
//! so concurrent message processing cannot race past the anti-replay check.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (trust anchor management), SC-23 (replay protection),
//!   AU-2 (auditable lifecycle), SI-10 (validated DER persisted verbatim)
//! - NIAP PP-CA: FMT_SMF.1 (management functions), FPT_STM.1 (timestamps)
//! - RFC 5934 §1.3.2 (trust anchor store), §4.1 (sequence numbers)

use crate::{DatabasePool, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A managed TAMP target (a module, community set, URI, or broadcast).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TampTargetRow {
    pub id: Uuid,
    pub label: String,
    pub target_der: Vec<u8>,
    pub uses_apex: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A trust anchor installed in a target's store.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TampTrustAnchorRow {
    pub id: Uuid,
    pub target_id: Uuid,
    pub pub_key_spki: Vec<u8>,
    pub key_id: Option<Vec<u8>>,
    pub ta_title: Option<String>,
    pub is_apex: bool,
    pub ta_der: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// A single mutation to a target's trust-anchor store, applied as part of an
/// atomic batch (RFC 5934 §4.3 / §4.5). Building the batch first and applying
/// it in one transaction keeps a multi-edit update all-or-nothing.
#[derive(Debug, Clone)]
pub enum TrustAnchorWrite {
    /// Insert a trust anchor (apex or subordinate).
    Insert {
        pub_key_spki: Vec<u8>,
        key_id: Option<Vec<u8>>,
        ta_title: Option<String>,
        is_apex: bool,
        ta_der: Vec<u8>,
    },
    /// Remove the trust anchor identified by this DER SubjectPublicKeyInfo.
    Remove { pub_key_spki: Vec<u8> },
    /// Update the trust anchor identified by this DER SubjectPublicKeyInfo.
    Update {
        pub_key_spki: Vec<u8>,
        ta_der: Vec<u8>,
    },
}

/// Repository for TAMP manager state.
#[derive(Clone)]
pub struct TampRepository {
    pool: DatabasePool,
}

impl TampRepository {
    /// Create a new TAMP repository.
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    // ===================== Targets =====================

    /// Look up a target by its canonical DER `TargetIdentifier`.
    pub async fn find_target_by_der(&self, target_der: &[u8]) -> Result<Option<TampTargetRow>> {
        let row =
            sqlx::query_as::<_, TampTargetRow>("SELECT * FROM tamp_targets WHERE target_der = $1")
                .bind(target_der)
                .fetch_optional(self.pool.pool())
                .await?;
        Ok(row)
    }

    /// Fetch a target by id.
    pub async fn get_target(&self, id: &Uuid) -> Result<Option<TampTargetRow>> {
        let row = sqlx::query_as::<_, TampTargetRow>("SELECT * FROM tamp_targets WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;
        Ok(row)
    }

    /// Get an existing target by DER, or create it. Returns the target id.
    ///
    /// RFC 5934 §4.1 - targets are identified by their TargetIdentifier.
    pub async fn get_or_create_target(
        &self,
        target_der: &[u8],
        label: &str,
        uses_apex: bool,
    ) -> Result<Uuid> {
        if let Some(existing) = self.find_target_by_der(target_der).await? {
            return Ok(existing.id);
        }
        let id = Uuid::new_v4();
        // ON CONFLICT guards against a concurrent insert racing the check above.
        let row_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO tamp_targets (id, label, target_der, uses_apex)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (target_der) DO UPDATE SET updated_at = now()
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(label)
        .bind(target_der)
        .bind(uses_apex)
        .fetch_one(self.pool.pool())
        .await?;
        Ok(row_id)
    }

    // ===================== Sequence numbers (replay protection) =====================

    /// Atomically check that `new_seq` is strictly greater than the stored
    /// baseline for `(target, signer)` and, if so, advance the baseline.
    ///
    /// Returns `true` if the message is fresh (and the baseline was advanced),
    /// `false` if it is a replay (`new_seq <= stored`).
    ///
    /// RFC 5934 §4.1 - sequence numbers are strictly increasing per signer; the
    /// `SELECT ... FOR UPDATE` row lock makes the check-and-advance atomic.
    /// NIST 800-53: SC-23 - replay protection.
    pub async fn check_and_advance_seq(
        &self,
        target_id: &Uuid,
        signer_key_id: &[u8],
        new_seq: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.pool().begin().await?;

        let current: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT last_seq_number FROM tamp_sequence_numbers
            WHERE target_id = $1 AND signer_key_id = $2
            FOR UPDATE
            "#,
        )
        .bind(target_id)
        .bind(signer_key_id)
        .fetch_optional(&mut *tx)
        .await?;

        match current {
            Some(stored) if new_seq <= stored => {
                // Replay (or stale) — leave the baseline untouched.
                tx.rollback().await?;
                Ok(false)
            }
            Some(_) => {
                sqlx::query(
                    r#"
                    UPDATE tamp_sequence_numbers
                    SET last_seq_number = $3, updated_at = now()
                    WHERE target_id = $1 AND signer_key_id = $2
                    "#,
                )
                .bind(target_id)
                .bind(signer_key_id)
                .bind(new_seq)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(true)
            }
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO tamp_sequence_numbers
                        (id, target_id, signer_key_id, last_seq_number)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(target_id)
                .bind(signer_key_id)
                .bind(new_seq)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(true)
            }
        }
    }

    /// Current sequence-number baseline for a signer, if any.
    pub async fn get_seq(&self, target_id: &Uuid, signer_key_id: &[u8]) -> Result<Option<i64>> {
        let v: Option<i64> = sqlx::query_scalar(
            "SELECT last_seq_number FROM tamp_sequence_numbers \
             WHERE target_id = $1 AND signer_key_id = $2",
        )
        .bind(target_id)
        .bind(signer_key_id)
        .fetch_optional(self.pool.pool())
        .await?;
        Ok(v)
    }

    /// Reset (adjust) a signer's sequence-number baseline (RFC 5934 §4.9).
    pub async fn reset_seq(
        &self,
        target_id: &Uuid,
        signer_key_id: &[u8],
        value: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO tamp_sequence_numbers (id, target_id, signer_key_id, last_seq_number)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (target_id, signer_key_id)
            DO UPDATE SET last_seq_number = $4, updated_at = now()
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(target_id)
        .bind(signer_key_id)
        .bind(value)
        .execute(self.pool.pool())
        .await?;
        Ok(())
    }

    /// Atomically allocate the next strictly increasing outbound sequence
    /// number for `(target, signer)` and return it (RFC 5934 §4.1).
    ///
    /// Unlike a read-then-write, the increment happens in a single upsert
    /// statement, so concurrent issuers can never allocate the same number.
    /// NIST 800-53: SC-23 - replay protection for issued messages.
    pub async fn allocate_next_seq(&self, target_id: &Uuid, signer_key_id: &[u8]) -> Result<i64> {
        let next: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO tamp_sequence_numbers (id, target_id, signer_key_id, last_seq_number)
            VALUES ($1, $2, $3, 1)
            ON CONFLICT (target_id, signer_key_id)
            DO UPDATE SET last_seq_number = tamp_sequence_numbers.last_seq_number + 1,
                          updated_at = now()
            RETURNING last_seq_number
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(target_id)
        .bind(signer_key_id)
        .fetch_one(self.pool.pool())
        .await?;
        Ok(next)
    }

    /// All `(signer_key_id, last_seq_number)` baselines for a target.
    pub async fn list_sequence_numbers(&self, target_id: &Uuid) -> Result<Vec<(Vec<u8>, i64)>> {
        let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT signer_key_id, last_seq_number FROM tamp_sequence_numbers \
             WHERE target_id = $1 ORDER BY signer_key_id",
        )
        .bind(target_id)
        .fetch_all(self.pool.pool())
        .await?;
        Ok(rows)
    }

    // ===================== Trust anchors =====================

    /// Whether a trust anchor with the given SPKI already exists for a target.
    pub async fn trust_anchor_exists(&self, target_id: &Uuid, spki: &[u8]) -> Result<bool> {
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM tamp_trust_anchors WHERE target_id = $1 AND pub_key_spki = $2",
        )
        .bind(target_id)
        .bind(spki)
        .fetch_optional(self.pool.pool())
        .await?;
        Ok(exists.is_some())
    }

    /// Insert a trust anchor into a target's store.
    ///
    /// The `(target_id, pub_key_spki)` UNIQUE constraint (and the single-apex
    /// partial index) enforce RFC 5934 invariants at the database layer.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_trust_anchor(
        &self,
        target_id: &Uuid,
        pub_key_spki: &[u8],
        key_id: Option<&[u8]>,
        ta_title: Option<&str>,
        is_apex: bool,
        ta_der: &[u8],
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO tamp_trust_anchors
                (id, target_id, pub_key_spki, key_id, ta_title, is_apex, ta_der)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(target_id)
        .bind(pub_key_spki)
        .bind(key_id)
        .bind(ta_title)
        .bind(is_apex)
        .bind(ta_der)
        .execute(self.pool.pool())
        .await?;
        Ok(id)
    }

    /// Update a trust anchor identified by its SPKI. Returns true if a row was
    /// changed (RFC 5934 §4.3 change operation).
    pub async fn update_trust_anchor(
        &self,
        target_id: &Uuid,
        pub_key_spki: &[u8],
        key_id: Option<&[u8]>,
        ta_title: Option<&str>,
        ta_der: &[u8],
    ) -> Result<bool> {
        let res = sqlx::query(
            r#"
            UPDATE tamp_trust_anchors
            SET key_id = $3, ta_title = $4, ta_der = $5
            WHERE target_id = $1 AND pub_key_spki = $2
            "#,
        )
        .bind(target_id)
        .bind(pub_key_spki)
        .bind(key_id)
        .bind(ta_title)
        .bind(ta_der)
        .execute(self.pool.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove a trust anchor by SPKI. Returns true if a row was deleted.
    pub async fn remove_trust_anchor(&self, target_id: &Uuid, spki: &[u8]) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM tamp_trust_anchors WHERE target_id = $1 AND pub_key_spki = $2",
        )
        .bind(target_id)
        .bind(spki)
        .execute(self.pool.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Apply a batch of trust-anchor writes to a target's store in a single
    /// transaction (RFC 5934 §4.3). Either every write commits or none does, so
    /// a partial failure can never leave the store in a half-applied state.
    pub async fn apply_trust_anchor_writes(
        &self,
        target_id: &Uuid,
        writes: &[TrustAnchorWrite],
    ) -> Result<()> {
        let mut tx = self.pool.pool().begin().await?;
        for write in writes {
            apply_one_write(&mut tx, target_id, write).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Apply a community membership update atomically (RFC 5934 §4.7: remove
    /// then add, all-or-nothing).
    pub async fn apply_community_update(
        &self,
        target_id: &Uuid,
        remove: &[String],
        add: &[String],
    ) -> Result<()> {
        let mut tx = self.pool.pool().begin().await?;
        for oid in remove {
            sqlx::query("DELETE FROM tamp_communities WHERE target_id = $1 AND community_oid = $2")
                .bind(target_id)
                .bind(oid)
                .execute(&mut *tx)
                .await?;
        }
        for oid in add {
            sqlx::query(
                r#"
                INSERT INTO tamp_communities (id, target_id, community_oid)
                VALUES ($1, $2, $3)
                ON CONFLICT (target_id, community_oid) DO NOTHING
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(target_id)
            .bind(oid)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Apply an apex update atomically (RFC 5934 §4.5): optionally clear the
    /// subordinate trust anchors and/or communities, remove any existing apex,
    /// and install the new apex — all in one transaction so the destructive
    /// clear can never be left without a new apex installed.
    ///
    /// The apex is always an *insert* (taking explicit fields rather than a
    /// general [`TrustAnchorWrite`]) so the "no apex remaining" footgun of a
    /// remove/update is impossible by construction.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_apex_update(
        &self,
        target_id: &Uuid,
        clear_trust_anchors: bool,
        clear_communities: bool,
        apex_pub_key_spki: &[u8],
        apex_key_id: Option<&[u8]>,
        apex_ta_title: Option<&str>,
        apex_ta_der: &[u8],
    ) -> Result<()> {
        let mut tx = self.pool.pool().begin().await?;
        if clear_trust_anchors {
            sqlx::query("DELETE FROM tamp_trust_anchors WHERE target_id = $1 AND is_apex = FALSE")
                .bind(target_id)
                .execute(&mut *tx)
                .await?;
        }
        if clear_communities {
            sqlx::query("DELETE FROM tamp_communities WHERE target_id = $1")
                .bind(target_id)
                .execute(&mut *tx)
                .await?;
        }
        // Remove any existing apex (or a same-key row) before installing the new.
        sqlx::query("DELETE FROM tamp_trust_anchors WHERE target_id = $1 AND pub_key_spki = $2")
            .bind(target_id)
            .bind(apex_pub_key_spki)
            .execute(&mut *tx)
            .await?;
        apply_one_write(
            &mut tx,
            target_id,
            &TrustAnchorWrite::Insert {
                pub_key_spki: apex_pub_key_spki.to_vec(),
                key_id: apex_key_id.map(|k| k.to_vec()),
                ta_title: apex_ta_title.map(|t| t.to_string()),
                is_apex: true,
                ta_der: apex_ta_der.to_vec(),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ===================== Target response signers =====================

    /// Register (or update) a target's response-signing key (RFC 5934 §2.2.1).
    ///
    /// The manager verifies a target's signed confirmations / status responses
    /// against the SPKI registered here, located by the SignerInfo SKI — not
    /// against a key supplied alongside the message. NIST 800-53: SC-12 / SI-10.
    pub async fn register_target_signer(
        &self,
        target_id: &Uuid,
        signer_key_id: &[u8],
        spki: &[u8],
        description: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let row_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO tamp_target_signers (id, target_id, signer_key_id, spki, description)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (target_id, signer_key_id)
            DO UPDATE SET spki = $4, description = $5, updated_at = now()
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(target_id)
        .bind(signer_key_id)
        .bind(spki)
        .bind(description)
        .fetch_one(self.pool.pool())
        .await?;
        Ok(row_id)
    }

    /// Resolve the verifying SPKI for a target's signer by subjectKeyIdentifier.
    pub async fn find_target_signer_spki(
        &self,
        target_id: &Uuid,
        signer_key_id: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let spki: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT spki FROM tamp_target_signers \
             WHERE target_id = $1 AND signer_key_id = $2",
        )
        .bind(target_id)
        .bind(signer_key_id)
        .fetch_optional(self.pool.pool())
        .await?;
        Ok(spki)
    }

    /// List a target's trust anchors.
    pub async fn list_trust_anchors(&self, target_id: &Uuid) -> Result<Vec<TampTrustAnchorRow>> {
        let rows = sqlx::query_as::<_, TampTrustAnchorRow>(
            "SELECT * FROM tamp_trust_anchors WHERE target_id = $1 ORDER BY created_at",
        )
        .bind(target_id)
        .fetch_all(self.pool.pool())
        .await?;
        Ok(rows)
    }

    /// Remove all non-apex trust anchors for a target (RFC 5934 §4.5
    /// clearTrustAnchors). The apex is replaced separately by an apex update.
    pub async fn clear_trust_anchors(&self, target_id: &Uuid) -> Result<u64> {
        let res =
            sqlx::query("DELETE FROM tamp_trust_anchors WHERE target_id = $1 AND is_apex = FALSE")
                .bind(target_id)
                .execute(self.pool.pool())
                .await?;
        Ok(res.rows_affected())
    }

    // ===================== Communities =====================

    /// List a target's community OIDs (dotted strings).
    pub async fn list_communities(&self, target_id: &Uuid) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT community_oid FROM tamp_communities WHERE target_id = $1 ORDER BY community_oid",
        )
        .bind(target_id)
        .fetch_all(self.pool.pool())
        .await?;
        Ok(rows)
    }

    /// Add a community membership (idempotent). Returns true if newly added.
    pub async fn add_community(&self, target_id: &Uuid, community_oid: &str) -> Result<bool> {
        let res = sqlx::query(
            r#"
            INSERT INTO tamp_communities (id, target_id, community_oid)
            VALUES ($1, $2, $3)
            ON CONFLICT (target_id, community_oid) DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(target_id)
        .bind(community_oid)
        .execute(self.pool.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove a community membership. Returns true if a row was deleted.
    pub async fn remove_community(&self, target_id: &Uuid, community_oid: &str) -> Result<bool> {
        let res =
            sqlx::query("DELETE FROM tamp_communities WHERE target_id = $1 AND community_oid = $2")
                .bind(target_id)
                .bind(community_oid)
                .execute(self.pool.pool())
                .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove all community memberships for a target (RFC 5934 §4.5
    /// clearCommunities).
    pub async fn clear_communities(&self, target_id: &Uuid) -> Result<u64> {
        let res = sqlx::query("DELETE FROM tamp_communities WHERE target_id = $1")
            .bind(target_id)
            .execute(self.pool.pool())
            .await?;
        Ok(res.rows_affected())
    }

    // ===================== Message log =====================

    /// Record an issued or received TAMP message for provenance (AU-3).
    #[allow(clippy::too_many_arguments)]
    pub async fn log_message(
        &self,
        target_id: Option<&Uuid>,
        direction: &str,
        content_type: &str,
        message_name: &str,
        seq_number: Option<i64>,
        signer_key_id: Option<&[u8]>,
        status_code: Option<&str>,
        message_der: &[u8],
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO tamp_message_log
                (id, target_id, direction, content_type, message_name,
                 seq_number, signer_key_id, status_code, message_der)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(id)
        .bind(target_id)
        .bind(direction)
        .bind(content_type)
        .bind(message_name)
        .bind(seq_number)
        .bind(signer_key_id)
        .bind(status_code)
        .bind(message_der)
        .execute(self.pool.pool())
        .await?;
        Ok(id)
    }
}

/// Apply a single [`TrustAnchorWrite`] on an open transaction.
async fn apply_one_write(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    target_id: &Uuid,
    write: &TrustAnchorWrite,
) -> Result<()> {
    match write {
        TrustAnchorWrite::Insert {
            pub_key_spki,
            key_id,
            ta_title,
            is_apex,
            ta_der,
        } => {
            sqlx::query(
                r#"
                INSERT INTO tamp_trust_anchors
                    (id, target_id, pub_key_spki, key_id, ta_title, is_apex, ta_der)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(target_id)
            .bind(pub_key_spki)
            .bind(key_id.as_deref())
            .bind(ta_title.as_deref())
            .bind(is_apex)
            .bind(ta_der)
            .execute(&mut **tx)
            .await?;
        }
        TrustAnchorWrite::Remove { pub_key_spki } => {
            sqlx::query(
                "DELETE FROM tamp_trust_anchors WHERE target_id = $1 AND pub_key_spki = $2",
            )
            .bind(target_id)
            .bind(pub_key_spki)
            .execute(&mut **tx)
            .await?;
        }
        TrustAnchorWrite::Update {
            pub_key_spki,
            ta_der,
        } => {
            sqlx::query(
                "UPDATE tamp_trust_anchors SET ta_der = $3 \
                 WHERE target_id = $1 AND pub_key_spki = $2",
            )
            .bind(target_id)
            .bind(pub_key_spki)
            .bind(ta_der)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}
