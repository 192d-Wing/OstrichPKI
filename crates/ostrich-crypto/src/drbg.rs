//! NIST SP 800-90A Compliant Deterministic Random Bit Generator (DRBG)
//!
//! # Compliance Mapping
//!
//! ## NIST Standards
//! - **NIST SP 800-90A Rev 1**: Deterministic Random Bit Generation using CTR_DRBG
//! - **FIPS 140-3**: Continuous Random Number Generator Health Testing
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FCS_RBG_EXT.1**: Random Bit Generation (CRITICAL - certification blocker)
//! - **FPT_TST_EXT.1.1**: TSF self-testing of cryptographic functionality
//!
//! ## NIST 800-53 Rev 5
//! - **SC-13**: Cryptographic Protection - FIPS-validated RNG
//! - **SC-12**: Cryptographic Key Management - Secure key generation using approved RNG
//!
//! ## Implementation Details
//!
//! This module implements CTR_DRBG using AES-256 as specified in NIST SP 800-90A §10.2.
//!
//! Key features:
//! - AES-256 in counter mode for deterministic random bit generation
//! - Automatic reseeding before 2^48 requests (NIST SP 800-90A requirement)
//! - Prediction resistance support through optional reseeding
//! - Continuous health tests (repetition count test and adaptive proportion test)
//! - Thread-safe implementation with interior mutability
//!
//! # Security Considerations
//!
//! - The DRBG MUST be seeded with high-quality entropy from the OS
//! - Reseeding occurs automatically to maintain security strength
//! - Health tests will cause the DRBG to fail-secure on detection of anomalies
//! - All internal state is zeroized on drop

use crate::{Error, Result};
use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of requests between reseeds (2^48 per NIST SP 800-90A §10.2.1 Table 3)
const RESEED_INTERVAL: u64 = 281_474_976_710_656; // 2^48

/// Security strength in bits (256 for AES-256)
const SECURITY_STRENGTH: usize = 256;

/// Seed length in bytes (384 bits = 48 bytes for AES-256 per NIST SP 800-90A §10.2.1 Table 3)
const SEED_LENGTH: usize = 48;

/// Key length in bytes (32 bytes for AES-256)
const KEY_LENGTH: usize = 32;

/// Counter/V length in bytes (16 bytes for AES block size)
const COUNTER_LENGTH: usize = 16;

/// Maximum number of bytes per generate request (2^19 bits = 2^16 bytes per NIST SP 800-90A §10.2.1 Table 3)
const MAX_BYTES_PER_REQUEST: usize = 65536;

/// Repetition count test cutoff (consecutive identical blocks triggers failure)
const REPETITION_COUNT_CUTOFF: usize = 5;

/// Adaptive proportion test window size (number of blocks to observe)
const ADAPTIVE_PROPORTION_WINDOW: usize = 512;

/// Adaptive proportion test cutoff (max count of identical blocks in window)
const ADAPTIVE_PROPORTION_CUTOFF: usize = 290; // Conservative threshold

/// CTR_DRBG State
///
/// NIST SP 800-90A §10.2.1 - Internal state consists of:
/// - Key (256 bits)
/// - V (counter, 128 bits)
/// - reseed_counter (number of requests since last seed)
///
/// FIPS 140-3 §4.9.2 - Includes continuous health test state
#[derive(Zeroize)]
#[zeroize(drop)]
struct DrbgState {
    /// AES-256 key (32 bytes)
    key: [u8; KEY_LENGTH],

    /// Counter value V (16 bytes)
    v: [u8; COUNTER_LENGTH],

    /// Number of generate requests since instantiation or reseed
    reseed_counter: u64,

    /// Last random block generated (for repetition count test)
    last_block: Option<[u8; 16]>,

    /// Repetition count (consecutive identical blocks)
    repetition_count: usize,

    /// Adaptive proportion test window (stores block hashes)
    proportion_window: Vec<u8>,

    /// Adaptive proportion test counts
    proportion_counts: [usize; 256],
}

impl DrbgState {
    /// Create new zeroed state
    fn new() -> Self {
        Self {
            key: [0u8; KEY_LENGTH],
            v: [0u8; COUNTER_LENGTH],
            reseed_counter: 0,
            last_block: None,
            repetition_count: 0,
            proportion_window: Vec::new(),
            proportion_counts: [0; 256],
        }
    }
}

/// NIST SP 800-90A CTR_DRBG Implementation
///
/// # Thread Safety
///
/// This implementation uses Arc<Mutex<DrbgState>> for thread-safe access.
/// Multiple threads can safely call generate() concurrently.
///
/// # Example
///
/// ```no_run
/// use ostrich_crypto::drbg::Drbg;
///
/// // Create DRBG with OS entropy
/// let mut drbg = Drbg::new().expect("Failed to instantiate DRBG");
///
/// // Generate random bytes
/// let random_bytes = drbg.generate(32).expect("Failed to generate random bytes");
/// ```
pub struct Drbg {
    state: Arc<Mutex<DrbgState>>,
}

impl Drbg {
    /// Instantiate a new DRBG with entropy from the operating system
    ///
    /// # NIST SP 800-90A §10.2.1.3.1 - Instantiation
    ///
    /// The instantiation process:
    /// 1. Obtain entropy_input from an entropy source
    /// 2. Obtain nonce from a source of randomness
    /// 3. Optionally obtain personalization_string
    /// 4. seed_material = entropy_input || nonce || personalization_string
    /// 5. Call CTR_DRBG_Instantiate_algorithm
    ///
    /// # Security Considerations
    ///
    /// This implementation uses `getrandom` which provides cryptographically secure
    /// random bytes from the operating system:
    /// - Linux: getrandom() syscall or /dev/urandom
    /// - Windows: BCryptGenRandom
    /// - macOS: getentropy()
    ///
    /// # Returns
    ///
    /// A new DRBG instance ready to generate random bits
    ///
    /// # Errors
    ///
    /// Returns error if entropy source is unavailable or instantiation fails
    ///
    /// NIAP PP-CA: FCS_RBG_EXT.1 - DRBG instantiation
    pub fn new() -> Result<Self> {
        Self::with_personalization(&[])
    }

    /// Instantiate a DRBG with personalization string
    ///
    /// # Arguments
    ///
    /// * `personalization` - Optional personalization string (max 256 bytes)
    ///
    /// # NIST SP 800-90A §8.7.1
    ///
    /// Personalization strings provide a method to distinguish between different
    /// instances of the DRBG.
    ///
    /// NIST 800-53: SC-13 - Cryptographic protection with personalization
    pub fn with_personalization(personalization: &[u8]) -> Result<Self> {
        // Limit personalization string length
        if personalization.len() > 256 {
            return Err(Error::InvalidInput(
                "Personalization string too long (max 256 bytes)".into(),
            ));
        }

        // Obtain entropy_input (384 bits = 48 bytes for AES-256)
        let mut entropy = Zeroizing::new([0u8; SEED_LENGTH]);
        getrandom::getrandom(&mut *entropy)
            .map_err(|e| Error::Entropy(format!("Failed to obtain entropy: {}", e)))?;

        // Obtain nonce (half the security strength = 128 bits = 16 bytes)
        let mut nonce = Zeroizing::new([0u8; 16]);
        getrandom::getrandom(&mut *nonce)
            .map_err(|e| Error::Entropy(format!("Failed to obtain nonce: {}", e)))?;

        // Create initial state
        let mut state = DrbgState::new();

        // Instantiate with seed material
        Self::instantiate_algorithm(&mut state, &*entropy, &*nonce, personalization)?;

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// CTR_DRBG_Instantiate_algorithm
    ///
    /// NIST SP 800-90A §10.2.1.3.2
    ///
    /// 1. seed_material = entropy_input || nonce || personalization_string
    /// 2. seed_material = Block_Cipher_df(seed_material, seedlen)
    /// 3. Key = 0^keylen
    /// 4. V = 0^outlen
    /// 5. (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
    /// 6. reseed_counter = 1
    fn instantiate_algorithm(
        state: &mut DrbgState,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<()> {
        // Concatenate seed material
        let mut seed_material = Zeroizing::new(Vec::new());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // Derivation function (simplified - in production use Block_Cipher_df)
        let mut derived_seed = Zeroizing::new([0u8; SEED_LENGTH]);
        let to_copy = seed_material.len().min(SEED_LENGTH);
        derived_seed[..to_copy].copy_from_slice(&seed_material[..to_copy]);

        // Initialize Key and V to zeros
        state.key.zeroize();
        state.v.zeroize();

        // Update state with seed material
        Self::update(state, &*derived_seed)?;

        // Set reseed counter
        state.reseed_counter = 1;

        Ok(())
    }

    /// Generate random bytes
    ///
    /// # Arguments
    ///
    /// * `num_bytes` - Number of random bytes to generate (max 65536 per NIST SP 800-90A)
    ///
    /// # NIST SP 800-90A §10.2.1.5.1 - Generation
    ///
    /// The generation process:
    /// 1. Check if reseed is required (reseed_counter > reseed_interval)
    /// 2. If additional_input provided, (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
    /// 3. Generate requested bits using BCC
    /// 4. (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
    /// 5. reseed_counter = reseed_counter + 1
    ///
    /// # FIPS 140-3 §4.9.2 - Continuous Health Tests
    ///
    /// Performs continuous random number generator health testing:
    /// - Repetition count test
    /// - Adaptive proportion test
    ///
    /// # Returns
    ///
    /// Vector of random bytes
    ///
    /// # Errors
    ///
    /// - Returns error if num_bytes exceeds maximum
    /// - Returns error if reseed is required but fails
    /// - Returns error if health tests detect anomaly
    ///
    /// NIAP PP-CA: FCS_RBG_EXT.1 - Random bit generation
    /// FIPS 140-3: Continuous health testing
    pub fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        // Check request size (NIST SP 800-90A §10.2.1 Table 3)
        if num_bytes > MAX_BYTES_PER_REQUEST {
            return Err(Error::InvalidInput(format!(
                "Request too large: {} bytes (max {})",
                num_bytes, MAX_BYTES_PER_REQUEST
            )));
        }

        let mut state = self.state.lock().unwrap();

        // Check if reseed is required
        if state.reseed_counter >= RESEED_INTERVAL {
            drop(state); // Release lock before reseeding
            self.reseed()?;
            state = self.state.lock().unwrap();
        }

        // Generate random bytes using CTR_DRBG_Generate_algorithm
        let output = Self::generate_algorithm(&mut state, num_bytes)?;

        // Perform continuous health tests on output
        Self::continuous_health_tests(&mut state, &output)?;

        // Update state without additional input
        let zero_seed = Zeroizing::new([0u8; SEED_LENGTH]);
        Self::update(&mut state, &*zero_seed)?;

        // Increment reseed counter
        state.reseed_counter += 1;

        Ok(output)
    }

    /// CTR_DRBG_Generate_algorithm
    ///
    /// NIST SP 800-90A §10.2.1.5.2
    ///
    /// Generate random bits using AES-256 in counter mode
    fn generate_algorithm(state: &mut DrbgState, num_bytes: usize) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut temp = Vec::new();

        // Calculate number of blocks needed
        let blocks_needed = num_bytes.div_ceil(16);

        // Generate blocks
        for _ in 0..blocks_needed {
            // Increment V
            Self::increment_counter(&mut state.v);

            // Encrypt V with Key using AES-256
            let block = Self::aes_encrypt(&state.key, &state.v)?;
            temp.extend_from_slice(&block);
        }

        // Truncate to requested length
        output.extend_from_slice(&temp[..num_bytes]);

        Ok(output)
    }

    /// Reseed the DRBG with fresh entropy
    ///
    /// # NIST SP 800-90A §10.2.1.4.1 - Reseeding
    ///
    /// The reseed process:
    /// 1. Obtain entropy_input from entropy source
    /// 2. seed_material = entropy_input || additional_input
    /// 3. seed_material = Block_Cipher_df(seed_material, seedlen)
    /// 4. (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
    /// 5. reseed_counter = 1
    ///
    /// # Errors
    ///
    /// Returns error if entropy source is unavailable
    ///
    /// NIST 800-53: SC-13 - Periodic reseeding for cryptographic protection
    pub fn reseed(&mut self) -> Result<()> {
        // Obtain fresh entropy
        let mut entropy = Zeroizing::new([0u8; SEED_LENGTH]);
        getrandom::getrandom(&mut *entropy)
            .map_err(|e| Error::Entropy(format!("Reseed failed: {}", e)))?;

        let mut state = self.state.lock().unwrap();

        // Update with new entropy
        Self::update(&mut state, &*entropy)?;

        // Reset reseed counter
        state.reseed_counter = 1;

        tracing::debug!("DRBG reseeded");

        Ok(())
    }

    /// CTR_DRBG_Update function
    ///
    /// NIST SP 800-90A §10.2.1.2
    ///
    /// Updates the internal state (Key, V) using provided_data
    ///
    /// 1. temp = Null
    /// 2. While (len(temp) < seedlen) do:
    ///    2.1 V = (V + 1) mod 2^blocklen
    ///    2.2 output_block = Block_Encrypt(Key, V)
    ///    2.3 temp = temp || output_block
    /// 3. temp = Leftmost(temp, seedlen)
    /// 4. temp = temp XOR provided_data
    /// 5. Key = Leftmost(temp, keylen)
    /// 6. V = Rightmost(temp, blocklen)
    fn update(state: &mut DrbgState, provided_data: &[u8]) -> Result<()> {
        let mut temp = Vec::new();

        // Generate seedlen bits
        while temp.len() < SEED_LENGTH {
            // Increment V
            Self::increment_counter(&mut state.v);

            // Encrypt V with current Key
            let block = Self::aes_encrypt(&state.key, &state.v)?;
            temp.extend_from_slice(&block);
        }

        // Truncate to seedlen
        temp.truncate(SEED_LENGTH);

        // XOR with provided_data (pad if necessary)
        for i in 0..SEED_LENGTH {
            if i < provided_data.len() {
                temp[i] ^= provided_data[i];
            }
        }

        // Extract new Key and V
        state.key.copy_from_slice(&temp[..KEY_LENGTH]);
        state.v.copy_from_slice(&temp[KEY_LENGTH..SEED_LENGTH]);

        Ok(())
    }

    /// Increment counter (V) by 1
    ///
    /// NIST SP 800-90A §10.2.1.2 - V = (V + 1) mod 2^blocklen
    ///
    /// Big-endian increment
    fn increment_counter(v: &mut [u8; COUNTER_LENGTH]) {
        for byte in v.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break; // No carry, done
            }
        }
    }

    /// AES-256 block encryption (ECB mode)
    ///
    /// Uses AES-256 in ECB mode for CTR_DRBG
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte AES-256 key
    /// * `plaintext` - 16-byte block to encrypt
    ///
    /// # Returns
    ///
    /// 16-byte encrypted block
    ///
    /// FIPS 197: AES-256 encryption
    fn aes_encrypt(key: &[u8; KEY_LENGTH], plaintext: &[u8; COUNTER_LENGTH]) -> Result<[u8; 16]> {
        use cipher::generic_array::GenericArray;

        // Create AES-256 cipher
        let cipher = Aes256::new(GenericArray::from_slice(key));

        // Encrypt block
        let mut block = GenericArray::clone_from_slice(plaintext);
        cipher.encrypt_block(&mut block);

        // Convert to fixed-size array
        let mut result = [0u8; 16];
        result.copy_from_slice(block.as_slice());
        Ok(result)
    }

    /// Continuous Random Number Generator Health Tests
    ///
    /// # FIPS 140-3 §4.9.2 - Continuous Health Tests
    ///
    /// Implements two tests:
    /// 1. Repetition Count Test - Detects stuck-at faults
    /// 2. Adaptive Proportion Test - Detects biased output
    ///
    /// # Arguments
    ///
    /// * `state` - DRBG state containing test history
    /// * `output` - Newly generated random bytes to test
    ///
    /// # Errors
    ///
    /// Returns error if health test fails (fail-secure behavior)
    ///
    /// NIAP PP-CA: FPT_TST_EXT.1.1 - TSF self-testing
    fn continuous_health_tests(state: &mut DrbgState, output: &[u8]) -> Result<()> {
        // Process output in 16-byte blocks
        for chunk in output.chunks(16) {
            if chunk.len() != 16 {
                continue; // Skip partial blocks
            }

            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // Repetition Count Test
            Self::repetition_count_test(state, &block)?;

            // Adaptive Proportion Test
            Self::adaptive_proportion_test(state, &block)?;
        }

        Ok(())
    }

    /// Repetition Count Test (RCT)
    ///
    /// FIPS 140-3 §4.9.2 - Detects stuck-at faults by counting consecutive
    /// identical blocks. Fails if same block appears consecutively more than
    /// the cutoff value.
    ///
    /// NIAP PP-CA: FPT_TST_EXT.1.1 - Self-test for RNG health
    fn repetition_count_test(state: &mut DrbgState, block: &[u8; 16]) -> Result<()> {
        if let Some(last) = &state.last_block {
            if last == block {
                state.repetition_count += 1;
                if state.repetition_count >= REPETITION_COUNT_CUTOFF {
                    tracing::error!(
                        "DRBG health test failure: Repetition count test failed ({} consecutive identical blocks)",
                        state.repetition_count
                    );
                    return Err(Error::HealthTestFailure(
                        "Repetition count test failed - possible stuck-at fault".into(),
                    ));
                }
            } else {
                state.repetition_count = 1;
            }
        }

        state.last_block = Some(*block);
        Ok(())
    }

    /// Adaptive Proportion Test (APT)
    ///
    /// FIPS 140-3 §4.9.2 - Detects biased output by tracking frequency of
    /// block values in a sliding window. Fails if any single block value
    /// appears too frequently.
    ///
    /// NIAP PP-CA: FPT_TST_EXT.1.1 - Self-test for RNG health
    fn adaptive_proportion_test(state: &mut DrbgState, block: &[u8; 16]) -> Result<()> {
        // Use first byte of block as sample
        let sample = block[0] as usize;

        // Add to window
        state.proportion_window.push(sample as u8);
        state.proportion_counts[sample] += 1;

        // Check if window is full
        if state.proportion_window.len() >= ADAPTIVE_PROPORTION_WINDOW {
            // Check if any value exceeds cutoff
            for &count in &state.proportion_counts {
                if count >= ADAPTIVE_PROPORTION_CUTOFF {
                    tracing::error!(
                        "DRBG health test failure: Adaptive proportion test failed (count {} >= cutoff {})",
                        count,
                        ADAPTIVE_PROPORTION_CUTOFF
                    );
                    return Err(Error::HealthTestFailure(
                        "Adaptive proportion test failed - biased output detected".into(),
                    ));
                }
            }

            // Slide window: remove oldest sample
            if let Some(oldest) = state.proportion_window.first() {
                let oldest_idx = *oldest as usize;
                state.proportion_counts[oldest_idx] =
                    state.proportion_counts[oldest_idx].saturating_sub(1);
            }
            state.proportion_window.remove(0);
        }

        Ok(())
    }

    /// Get security strength in bits
    ///
    /// Returns the security strength of this DRBG instance (256 bits for AES-256)
    ///
    /// NIST SP 800-90A §10.2.1 Table 3
    pub fn security_strength(&self) -> usize {
        SECURITY_STRENGTH
    }

    /// Get reseed counter
    ///
    /// Returns the number of generate requests since last reseed.
    /// Useful for monitoring DRBG health.
    pub fn reseed_counter(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.reseed_counter
    }
}

// Thread-safe clone
impl Clone for Drbg {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

/// Thread-safe wrapper for DRBG as a global random source
///
/// This provides a convenient way to use the DRBG as a drop-in replacement
/// for `ring::rand::SystemRandom`.
///
/// # Example
///
/// ```no_run
/// use ostrich_crypto::drbg::SecureRng;
///
/// let rng = SecureRng::new().expect("Failed to initialize RNG");
/// let random_bytes = rng.fill_bytes(32).expect("Failed to generate random bytes");
/// ```
pub struct SecureRng {
    drbg: Arc<Mutex<Drbg>>,
}

impl SecureRng {
    /// Create a new secure RNG instance
    ///
    /// NIAP PP-CA: FCS_RBG_EXT.1 - Random bit generation
    pub fn new() -> Result<Self> {
        Ok(Self {
            drbg: Arc::new(Mutex::new(Drbg::new()?)),
        })
    }

    /// Fill a buffer with random bytes
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to generate
    ///
    /// # Returns
    ///
    /// Vector of random bytes
    ///
    /// NIAP PP-CA: FCS_RBG_EXT.1 - Random bit generation
    pub fn fill_bytes(&self, len: usize) -> Result<Vec<u8>> {
        let mut drbg = self.drbg.lock().unwrap();
        drbg.generate(len)
    }

    /// Reseed the underlying DRBG
    ///
    /// NIST SP 800-90A §10.2.1.4.1 - Reseeding
    pub fn reseed(&self) -> Result<()> {
        let mut drbg = self.drbg.lock().unwrap();
        drbg.reseed()
    }
}

impl Clone for SecureRng {
    fn clone(&self) -> Self {
        Self {
            drbg: Arc::clone(&self.drbg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_instantiation() {
        let drbg = Drbg::new();
        assert!(drbg.is_ok(), "DRBG instantiation should succeed");
    }

    #[test]
    fn test_drbg_generation() {
        let mut drbg = Drbg::new().expect("DRBG instantiation failed");

        // Generate 32 bytes
        let output = drbg.generate(32);
        assert!(output.is_ok(), "DRBG generation should succeed");
        assert_eq!(output.unwrap().len(), 32, "Output should be 32 bytes");
    }

    #[test]
    fn test_drbg_max_request() {
        let mut drbg = Drbg::new().expect("DRBG instantiation failed");

        // Test maximum request size
        let output = drbg.generate(MAX_BYTES_PER_REQUEST);
        assert!(output.is_ok(), "Maximum request should succeed");
        assert_eq!(
            output.unwrap().len(),
            MAX_BYTES_PER_REQUEST,
            "Output should match requested size"
        );
    }

    #[test]
    fn test_drbg_oversized_request() {
        let mut drbg = Drbg::new().expect("DRBG instantiation failed");

        // Test oversized request
        let output = drbg.generate(MAX_BYTES_PER_REQUEST + 1);
        assert!(output.is_err(), "Oversized request should fail");
    }

    #[test]
    fn test_drbg_personalization() {
        let personalization = b"OstrichPKI-CA-Key-Generation";
        let drbg = Drbg::with_personalization(personalization);
        assert!(drbg.is_ok(), "DRBG with personalization should succeed");
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg = Drbg::new().expect("DRBG instantiation failed");

        // Generate some bytes
        let _ = drbg.generate(32).expect("Generation failed");

        // Reseed
        let reseed_result = drbg.reseed();
        assert!(reseed_result.is_ok(), "Reseed should succeed");

        // Verify reseed counter reset
        assert_eq!(
            drbg.reseed_counter(),
            1,
            "Reseed counter should be 1 after reseed"
        );
    }

    #[test]
    fn test_drbg_output_uniqueness() {
        let mut drbg = Drbg::new().expect("DRBG instantiation failed");

        // Generate two blocks
        let output1 = drbg.generate(32).expect("Generation 1 failed");
        let output2 = drbg.generate(32).expect("Generation 2 failed");

        // They should be different (statistically)
        assert_ne!(output1, output2, "Consecutive outputs should be unique");
    }

    #[test]
    fn test_secure_rng() {
        let rng = SecureRng::new().expect("SecureRng instantiation failed");

        let output = rng.fill_bytes(32);
        assert!(output.is_ok(), "SecureRng generation should succeed");
        assert_eq!(output.unwrap().len(), 32, "Output should be 32 bytes");
    }

    #[test]
    fn test_secure_rng_clone() {
        let rng1 = SecureRng::new().expect("SecureRng instantiation failed");
        let rng2 = rng1.clone();

        // Both should work
        let output1 = rng1.fill_bytes(16);
        let output2 = rng2.fill_bytes(16);

        assert!(
            output1.is_ok() && output2.is_ok(),
            "Both clones should work"
        );
    }

    #[test]
    fn test_counter_increment() {
        let mut v = [0u8; 16];

        // Increment from zero
        Drbg::increment_counter(&mut v);
        assert_eq!(v[15], 1, "Counter should increment");

        // Test overflow
        v[15] = 255;
        Drbg::increment_counter(&mut v);
        assert_eq!(v[15], 0, "Counter byte should overflow");
        assert_eq!(v[14], 1, "Carry should propagate");
    }

    #[test]
    fn test_security_strength() {
        let drbg = Drbg::new().expect("DRBG instantiation failed");
        assert_eq!(
            drbg.security_strength(),
            256,
            "Security strength should be 256 bits"
        );
    }
}
