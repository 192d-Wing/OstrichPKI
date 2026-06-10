-- Migration 00006: KRA escrow uses an ephemeral, Shamir-split KEK
--
-- The original escrowed_keys schema assumed a long-lived wrapping key stored
-- in kra_storage_keys (escrowed_keys.wrapping_key_id NOT NULL REFERENCES
-- kra_storage_keys). The escrow implementation now generates a FRESH per-escrow
-- 256-bit KEK, AES-256-GCM-wraps the private key, splits the KEK into M-of-N
-- Shamir shares for the recovery agents, and NEVER stores the KEK. So there is
-- no stored wrapping key to reference: the NOT NULL FK made every escrow insert
-- fail (the generated wrapping_key_id had no matching kra_storage_keys row).
--
-- This migration makes wrapping_key_id nullable and drops the FK. The column is
-- retained (nullable) for backward compatibility and possible future
-- HSM-resident-KEK designs.
--
-- COMPLIANCE MAPPING:
--   NIST 800-53: SC-12 (Key Establishment) - per-escrow ephemeral KEK
--   NIST 800-53: CM-3 (Configuration Change Control) - schema change is checked in
--   NIAP PP-CA: FCS_CKM.2 (Key Distribution) - KEK distributed as Shamir shares

ALTER TABLE escrowed_keys
    ALTER COLUMN wrapping_key_id DROP NOT NULL;

ALTER TABLE escrowed_keys
    DROP CONSTRAINT IF EXISTS escrowed_keys_wrapping_key_id_fkey;
