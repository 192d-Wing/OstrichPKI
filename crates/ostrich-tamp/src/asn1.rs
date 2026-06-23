//! ASN.1 data structures for the Trust Anchor Management Protocol.
//!
//! These types are a direct, bits-on-the-wire transcription of the normative
//! 1993-syntax module in **RFC 5934 Appendix A.1** (`TAMP-Protocol-v2`) and the
//! trust-anchor types it imports from **RFC 5914** (`TrustAnchorInfoModule`).
//!
//! ## Tagging
//!
//! The RFC 5934 / 5914 modules are declared `DEFINITIONS IMPLICIT TAGS`, so a
//! context-specific tag on an ordinary type is IMPLICIT. However, per X.680
//! §31.2.7, tagging a `CHOICE` type implicitly is promoted to EXPLICIT (a
//! CHOICE has no single tag to overwrite). This affects, e.g.,
//! `add [1] TrustAnchorChoice` and the `issuer`/`subject [n] Name` fields
//! (`Name` is a CHOICE in PKIX): those are encoded EXPLICIT here.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 Appendix A.1 - TAMP-Protocol-v2 ASN.1 module
//! - RFC 5914 - Trust Anchor Format (TrustAnchorChoice / TrustAnchorInfo)
//! - RFC 5280 - X.509 Certificate / TBSCertificate / Name / Extensions
//! - NIST 800-53: SI-10 (input validation) - strict DER decoding of all fields

use const_oid::ObjectIdentifier;
use der::asn1::{BitString, Ia5String, Null, OctetString};
use der::{Choice, Enumerated, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::name::OtherName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

// ---------------------------------------------------------------------------
// DEFAULT helpers
// ---------------------------------------------------------------------------

/// `TAMPVersion DEFAULT v2` — RFC 5934 Appendix A.1.
fn default_version() -> u8 {
    2
}

/// `terse TerseOrVerbose DEFAULT verbose` — RFC 5934 Appendix A.1.
fn default_verbose() -> TerseOrVerbose {
    TerseOrVerbose::Verbose
}

/// `usesApex BOOLEAN DEFAULT TRUE` — RFC 5934 Appendix A.1.
fn default_true() -> bool {
    true
}

/// `version TrustAnchorInfoVersion DEFAULT v1` — RFC 5914.
fn default_ta_version() -> u8 {
    1
}

// ---------------------------------------------------------------------------
// Primitive protocol types
// ---------------------------------------------------------------------------

/// `TAMPVersion ::= INTEGER { v1(1), v2(2) }`. Represented as the raw integer.
pub type TampVersion = u8;

/// `SeqNumber ::= INTEGER (0..9223372036854775807)`.
///
/// A 63-bit monotonic counter; `u64` losslessly holds the permitted range.
pub type SeqNumber = u64;

/// `KeyIdentifier ::= OCTET STRING` (RFC 5280) — a trust anchor's SKI.
pub type KeyIdentifier = OctetString;

/// `Community ::= OBJECT IDENTIFIER`.
pub type Community = ObjectIdentifier;

/// `CommunityIdentifierList ::= SEQUENCE SIZE (0..MAX) OF Community`.
pub type CommunityIdentifierList = Vec<Community>;

/// `KeyIdentifiers ::= SEQUENCE SIZE (1..MAX) OF KeyIdentifier`.
pub type KeyIdentifiers = Vec<KeyIdentifier>;

/// `TrustAnchorTitle ::= UTF8String (SIZE (1..64))`. Size is enforced by the
/// application layer, not the type.
pub type TrustAnchorTitle = String;

/// `TerseOrVerbose ::= ENUMERATED { terse(1), verbose(2) }`.
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq, Default)]
#[asn1(type = "ENUMERATED")]
#[repr(u8)]
pub enum TerseOrVerbose {
    /// Terse responses contain only key identifiers / status codes.
    Terse = 1,
    /// Verbose responses contain full trust-anchor information.
    #[default]
    Verbose = 2,
}

// ---------------------------------------------------------------------------
// RFC 5914 — Trust Anchor Format
// ---------------------------------------------------------------------------

/// `CertPolicyFlags ::= BIT STRING { inhibitPolicyMapping(0),
///   requireExplicitPolicy(1), inhibitAnyPolicy(2) }` (RFC 5914).
pub type CertPolicyFlags = BitString;

/// `CertPathControls ::= SEQUENCE { ... }` (RFC 5914).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertPathControls {
    /// `taName Name` — distinguished name to use when this TA appears in a path.
    pub ta_name: Name,

    /// `certificate [0] Certificate OPTIONAL`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificate: Option<Certificate>,

    /// `policySet [1] CertificatePolicies OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub policy_set: Option<x509_cert::ext::pkix::CertificatePolicies>,

    /// `policyFlags [2] CertPolicyFlags OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub policy_flags: Option<CertPolicyFlags>,

    /// `nameConstr [3] NameConstraints OPTIONAL`.
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub name_constr: Option<x509_cert::ext::pkix::NameConstraints>,

    /// `pathLenConstraint [4] INTEGER (0..MAX) OPTIONAL`.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub path_len_constraint: Option<u32>,
}

/// `TrustAnchorInfo ::= SEQUENCE { ... }` (RFC 5914) — the minimalist trust
/// anchor representation.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TrustAnchorInfo {
    /// `version TrustAnchorInfoVersion DEFAULT v1`.
    #[asn1(default = "default_ta_version")]
    pub version: u8,

    /// `pubKey SubjectPublicKeyInfo`.
    pub pub_key: SubjectPublicKeyInfoOwned,

    /// `keyId KeyIdentifier`.
    pub key_id: KeyIdentifier,

    /// `taTitle TrustAnchorTitle OPTIONAL`.
    #[asn1(optional = "true")]
    pub ta_title: Option<TrustAnchorTitle>,

    /// `certPath CertPathControls OPTIONAL`.
    #[asn1(optional = "true")]
    pub cert_path: Option<CertPathControls>,

    /// `exts [1] EXPLICIT Extensions OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub exts: Option<Extensions>,

    /// `taTitleLangTag [2] UTF8String OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub ta_title_lang_tag: Option<String>,
}

/// `TrustAnchorChoice ::= CHOICE { ... }` (RFC 5914).
///
/// Note: `tbsCert`/`taInfo` are explicitly EXPLICIT in the module.
// Protocol message variants intentionally embed full X.509 / TA structures;
// boxing would complicate the `der` Choice derive for no real benefit here.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TrustAnchorChoice {
    /// `certificate Certificate` — a full X.509 certificate (untagged).
    Certificate(Certificate),

    /// `tbsCert [1] EXPLICIT TBSCertificate`.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    TbsCert(TbsCertificate),

    /// `taInfo [2] EXPLICIT TrustAnchorInfo`.
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    TaInfo(TrustAnchorInfo),
}

/// `TrustAnchorChoiceList ::= SEQUENCE SIZE (1..MAX) OF TrustAnchorChoice`.
pub type TrustAnchorChoiceList = Vec<TrustAnchorChoice>;

// ---------------------------------------------------------------------------
// Targeting and replay reference (RFC 5934 §4.1)
// ---------------------------------------------------------------------------

/// `HardwareSerialEntry ::= CHOICE { all NULL, single OCTET STRING,
///   block SEQUENCE { low OCTET STRING, high OCTET STRING } }`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum HardwareSerialEntry {
    /// `all NULL` — every serial number of this hardware type.
    All(Null),
    /// `single OCTET STRING` — one specific serial number.
    Single(OctetString),
    /// `block SEQUENCE { low, high }` — an inclusive range of serial numbers.
    Block(HardwareSerialBlock),
}

/// `block SEQUENCE { low OCTET STRING, high OCTET STRING }` of
/// [`HardwareSerialEntry`].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HardwareSerialBlock {
    /// Inclusive low bound of the serial-number range.
    pub low: OctetString,
    /// Inclusive high bound of the serial-number range.
    pub high: OctetString,
}

/// `HardwareModules ::= SEQUENCE { hwType OBJECT IDENTIFIER,
///   hwSerialEntries SEQUENCE SIZE (1..MAX) OF HardwareSerialEntry }`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HardwareModules {
    /// `hwType OBJECT IDENTIFIER` — the hardware module type.
    pub hw_type: ObjectIdentifier,
    /// `hwSerialEntries` — the serial numbers / ranges in scope.
    pub hw_serial_entries: Vec<HardwareSerialEntry>,
}

/// `HardwareModuleIdentifierList ::= SEQUENCE SIZE (1..MAX) OF HardwareModules`.
pub type HardwareModuleIdentifierList = Vec<HardwareModules>;

/// `TargetIdentifier ::= CHOICE { ... }` — which module(s) a message targets.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TargetIdentifier {
    /// `hwModules [1] HardwareModuleIdentifierList`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    HwModules(HardwareModuleIdentifierList),

    /// `communities [2] CommunityIdentifierList`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Communities(CommunityIdentifierList),

    /// `allModules [3] NULL` — broadcast to every module.
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT")]
    AllModules(Null),

    /// `uri [4] IA5String`.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
    Uri(Ia5String),

    /// `otherName [5] INSTANCE OF OTHER-NAME`.
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", constructed = "true")]
    OtherName(OtherName),
}

/// `TAMPMsgRef ::= SEQUENCE { target TargetIdentifier, seqNum SeqNumber }`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampMsgRef {
    /// `target` — module(s) this message applies to.
    pub target: TargetIdentifier,
    /// `seqNum` — monotonic anti-replay sequence number (RFC 5934 §4.1).
    pub seq_num: SeqNumber,
}

/// `TAMPSequenceNumber ::= SEQUENCE { keyId KeyIdentifier, seqNumber SeqNumber }`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampSequenceNumber {
    /// `keyId` — the authorized signer this baseline applies to.
    pub key_id: KeyIdentifier,
    /// `seqNumber` — the last accepted sequence number for that signer.
    pub seq_number: SeqNumber,
}

/// `TAMPSequenceNumbers ::= SEQUENCE SIZE (1..MAX) OF TAMPSequenceNumber`.
pub type TampSequenceNumbers = Vec<TampSequenceNumber>;

// ---------------------------------------------------------------------------
// Status Query / Response (RFC 5934 §4.1 / §4.2)
// ---------------------------------------------------------------------------

/// `TAMPStatusQuery ::= SEQUENCE { ... }` (RFC 5934 §4.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampStatusQuery {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,

    /// `terse [1] TerseOrVerbose DEFAULT verbose`.
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "default_verbose"
    )]
    pub terse: TerseOrVerbose,

    /// `query TAMPMsgRef`.
    pub query: TampMsgRef,
}

/// `TerseStatusResponse ::= SEQUENCE { ... }` (RFC 5934 §4.2).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TerseStatusResponse {
    /// `taKeyIds KeyIdentifiers`.
    pub ta_key_ids: KeyIdentifiers,
    /// `communities CommunityIdentifierList OPTIONAL`.
    #[asn1(optional = "true")]
    pub communities: Option<CommunityIdentifierList>,
}

/// `VerboseStatusResponse ::= SEQUENCE { ... }` (RFC 5934 §4.2).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseStatusResponse {
    /// `taInfo TrustAnchorChoiceList`.
    pub ta_info: TrustAnchorChoiceList,

    /// `continPubKeyDecryptAlg [0] AlgorithmIdentifier OPTIONAL`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub contin_pub_key_decrypt_alg: Option<AlgorithmIdentifierOwned>,

    /// `communities [1] CommunityIdentifierList OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<CommunityIdentifierList>,

    /// `tampSeqNumbers [2] TAMPSequenceNumbers OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

/// `StatusResponse ::= CHOICE { terseResponse [0] ..., verboseResponse [1] ... }`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum StatusResponse {
    /// `terseResponse [0] TerseStatusResponse`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    Terse(TerseStatusResponse),
    /// `verboseResponse [1] VerboseStatusResponse`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseStatusResponse),
}

/// `TAMPStatusResponse ::= SEQUENCE { ... }` (RFC 5934 §4.2).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampStatusResponse {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `query TAMPMsgRef`.
    pub query: TampMsgRef,
    /// `response StatusResponse`.
    pub response: StatusResponse,
    /// `usesApex BOOLEAN DEFAULT TRUE`.
    #[asn1(default = "default_true")]
    pub uses_apex: bool,
}

// ---------------------------------------------------------------------------
// Trust Anchor Update / Confirm (RFC 5934 §4.3 / §4.4)
// ---------------------------------------------------------------------------

/// `TBSCertificateChangeInfo ::= SEQUENCE { ... }` (RFC 5934 §4.3).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertificateChangeInfo {
    /// `serialNumber CertificateSerialNumber OPTIONAL`.
    #[asn1(optional = "true")]
    pub serial_number: Option<SerialNumber>,

    /// `signature [0] AlgorithmIdentifier OPTIONAL`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signature: Option<AlgorithmIdentifierOwned>,

    /// `issuer [1] Name OPTIONAL` (Name is a CHOICE → EXPLICIT).
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub issuer: Option<Name>,

    /// `validity [2] Validity OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub validity: Option<Validity>,

    /// `subject [3] Name OPTIONAL` (Name is a CHOICE → EXPLICIT).
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub subject: Option<Name>,

    /// `subjectPublicKeyInfo [4] SubjectPublicKeyInfo`.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
    pub subject_public_key_info: SubjectPublicKeyInfoOwned,

    /// `exts [5] EXPLICIT Extensions OPTIONAL`.
    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// `TrustAnchorChangeInfo ::= SEQUENCE { ... }` (RFC 5934 §4.3).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TrustAnchorChangeInfo {
    /// `pubKey SubjectPublicKeyInfo` — identifies the TA being changed.
    pub pub_key: SubjectPublicKeyInfoOwned,

    /// `keyId KeyIdentifier OPTIONAL`.
    #[asn1(optional = "true")]
    pub key_id: Option<KeyIdentifier>,

    /// `taTitle TrustAnchorTitle OPTIONAL`.
    #[asn1(optional = "true")]
    pub ta_title: Option<TrustAnchorTitle>,

    /// `certPath CertPathControls OPTIONAL`.
    #[asn1(optional = "true")]
    pub cert_path: Option<CertPathControls>,

    /// `exts [1] Extensions OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// `TrustAnchorChangeInfoChoice ::= CHOICE { tbsCertChange [0] ...,
///   taChange [1] ... }` (RFC 5934 §4.3).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TrustAnchorChangeInfoChoice {
    /// `tbsCertChange [0] TBSCertificateChangeInfo`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    TbsCertChange(TbsCertificateChangeInfo),
    /// `taChange [1] TrustAnchorChangeInfo`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    TaChange(TrustAnchorChangeInfo),
}

/// `TrustAnchorUpdate ::= CHOICE { add [1] ..., remove [2] ..., change [3] ... }`.
///
/// `add` wraps a CHOICE (`TrustAnchorChoice`), so its IMPLICIT tag is promoted
/// to EXPLICIT; `change` is explicitly EXPLICIT in the module.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TrustAnchorUpdate {
    /// `add [1] TrustAnchorChoice`.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    Add(TrustAnchorChoice),
    /// `remove [2] SubjectPublicKeyInfo`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Remove(SubjectPublicKeyInfoOwned),
    /// `change [3] EXPLICIT TrustAnchorChangeInfoChoice`.
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Change(TrustAnchorChangeInfoChoice),
}

/// `TAMPUpdate ::= SEQUENCE { ... }` (RFC 5934 §4.3).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampUpdate {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `terse [1] TerseOrVerbose DEFAULT verbose`.
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "default_verbose"
    )]
    pub terse: TerseOrVerbose,
    /// `msgRef TAMPMsgRef`.
    pub msg_ref: TampMsgRef,
    /// `updates SEQUENCE SIZE (1..MAX) OF TrustAnchorUpdate`.
    pub updates: Vec<TrustAnchorUpdate>,
    /// `tampSeqNumbers [2] TAMPSequenceNumbers OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

/// `StatusCodeList ::= SEQUENCE SIZE (1..MAX) OF StatusCode`.
pub type StatusCodeList = Vec<crate::statuscode::StatusCode>;

/// `VerboseUpdateConfirm ::= SEQUENCE { ... }` (RFC 5934 §4.4).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseUpdateConfirm {
    /// `status StatusCodeList`.
    pub status: StatusCodeList,
    /// `taInfo TrustAnchorChoiceList`.
    pub ta_info: TrustAnchorChoiceList,
    /// `tampSeqNumbers TAMPSequenceNumbers OPTIONAL`.
    #[asn1(optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
    /// `usesApex BOOLEAN DEFAULT TRUE`.
    #[asn1(default = "default_true")]
    pub uses_apex: bool,
}

/// `UpdateConfirm ::= CHOICE { terseConfirm [0] ..., verboseConfirm [1] ... }`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum UpdateConfirm {
    /// `terseConfirm [0] TerseUpdateConfirm` (= `StatusCodeList`).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    Terse(StatusCodeList),
    /// `verboseConfirm [1] VerboseUpdateConfirm`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseUpdateConfirm),
}

/// `TAMPUpdateConfirm ::= SEQUENCE { ... }` (RFC 5934 §4.4).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampUpdateConfirm {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `update TAMPMsgRef`.
    pub update: TampMsgRef,
    /// `confirm UpdateConfirm`.
    pub confirm: UpdateConfirm,
}

// ---------------------------------------------------------------------------
// Apex Trust Anchor Update / Confirm (RFC 5934 §4.5 / §4.6)
// ---------------------------------------------------------------------------

/// `TAMPApexUpdate ::= SEQUENCE { ... }` (RFC 5934 §4.5).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampApexUpdate {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `terse [1] TerseOrVerbose DEFAULT verbose`.
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "default_verbose"
    )]
    pub terse: TerseOrVerbose,
    /// `msgRef TAMPMsgRef`.
    pub msg_ref: TampMsgRef,
    /// `clearTrustAnchors BOOLEAN`.
    pub clear_trust_anchors: bool,
    /// `clearCommunities BOOLEAN`.
    pub clear_communities: bool,
    /// `seqNumber SeqNumber OPTIONAL`.
    #[asn1(optional = "true")]
    pub seq_number: Option<SeqNumber>,
    /// `apexTA TrustAnchorChoice`.
    pub apex_ta: TrustAnchorChoice,
}

/// `VerboseApexUpdateConfirm ::= SEQUENCE { ... }` (RFC 5934 §4.6).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseApexUpdateConfirm {
    /// `status StatusCode`.
    pub status: crate::statuscode::StatusCode,
    /// `taInfo TrustAnchorChoiceList`.
    pub ta_info: TrustAnchorChoiceList,
    /// `communities [0] CommunityIdentifierList OPTIONAL`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<CommunityIdentifierList>,
    /// `tampSeqNumbers [1] TAMPSequenceNumbers OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

/// `ApexUpdateConfirm ::= CHOICE { terseApexConfirm [0] StatusCode,
///   verboseApexConfirm [1] VerboseApexUpdateConfirm }`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ApexUpdateConfirm {
    /// `terseApexConfirm [0] StatusCode`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Terse(crate::statuscode::StatusCode),
    /// `verboseApexConfirm [1] VerboseApexUpdateConfirm`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseApexUpdateConfirm),
}

/// `TAMPApexUpdateConfirm ::= SEQUENCE { ... }` (RFC 5934 §4.6).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampApexUpdateConfirm {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `apexReplace TAMPMsgRef`.
    pub apex_replace: TampMsgRef,
    /// `apexConfirm ApexUpdateConfirm`.
    pub apex_confirm: ApexUpdateConfirm,
}

// ---------------------------------------------------------------------------
// Community Update / Confirm (RFC 5934 §4.7 / §4.8)
// ---------------------------------------------------------------------------

/// `CommunityUpdates ::= SEQUENCE { remove [1] ... OPTIONAL,
///   add [2] ... OPTIONAL }` — at least one must be present (RFC 5934 §4.7).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CommunityUpdates {
    /// `remove [1] CommunityIdentifierList OPTIONAL`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub remove: Option<CommunityIdentifierList>,
    /// `add [2] CommunityIdentifierList OPTIONAL`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub add: Option<CommunityIdentifierList>,
}

/// `TAMPCommunityUpdate ::= SEQUENCE { ... }` (RFC 5934 §4.7).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampCommunityUpdate {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `terse [1] TerseOrVerbose DEFAULT verbose`.
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "default_verbose"
    )]
    pub terse: TerseOrVerbose,
    /// `msgRef TAMPMsgRef`.
    pub msg_ref: TampMsgRef,
    /// `updates CommunityUpdates`.
    pub updates: CommunityUpdates,
}

/// `VerboseCommunityConfirm ::= SEQUENCE { status StatusCode,
///   communities CommunityIdentifierList OPTIONAL }` (RFC 5934 §4.8).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseCommunityConfirm {
    /// `status StatusCode`.
    pub status: crate::statuscode::StatusCode,
    /// `communities CommunityIdentifierList OPTIONAL`.
    #[asn1(optional = "true")]
    pub communities: Option<CommunityIdentifierList>,
}

/// `CommunityConfirm ::= CHOICE { terseCommConfirm [0] StatusCode,
///   verboseCommConfirm [1] VerboseCommunityConfirm }`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CommunityConfirm {
    /// `terseCommConfirm [0] StatusCode`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Terse(crate::statuscode::StatusCode),
    /// `verboseCommConfirm [1] VerboseCommunityConfirm`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseCommunityConfirm),
}

/// `TAMPCommunityUpdateConfirm ::= SEQUENCE { ... }` (RFC 5934 §4.8).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampCommunityUpdateConfirm {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `update TAMPMsgRef`.
    pub update: TampMsgRef,
    /// `commConfirm CommunityConfirm`.
    pub comm_confirm: CommunityConfirm,
}

// ---------------------------------------------------------------------------
// Sequence Number Adjust / Confirm (RFC 5934 §4.9 / §4.10)
// ---------------------------------------------------------------------------

/// `SequenceNumberAdjust ::= SEQUENCE { version [0] ..., msgRef TAMPMsgRef }`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SequenceNumberAdjust {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `msgRef TAMPMsgRef`.
    pub msg_ref: TampMsgRef,
}

/// `SequenceNumberAdjustConfirm ::= SEQUENCE { version [0] ...,
///   adjust TAMPMsgRef, status StatusCode }`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SequenceNumberAdjustConfirm {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `adjust TAMPMsgRef`.
    pub adjust: TampMsgRef,
    /// `status StatusCode`.
    pub status: crate::statuscode::StatusCode,
}

// ---------------------------------------------------------------------------
// TAMP Error (RFC 5934 §4.11)
// ---------------------------------------------------------------------------

/// `TAMPError ::= SEQUENCE { ... }` (RFC 5934 §4.11).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampError {
    /// `version [0] TAMPVersion DEFAULT v2`.
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "default_version"
    )]
    pub version: TampVersion,
    /// `msgType OBJECT IDENTIFIER` — content type of the offending message.
    pub msg_type: ObjectIdentifier,
    /// `status StatusCode`.
    pub status: crate::statuscode::StatusCode,
    /// `msgRef TAMPMsgRef OPTIONAL`.
    #[asn1(optional = "true")]
    pub msg_ref: Option<TampMsgRef>,
}

// ---------------------------------------------------------------------------
// Apex contingency key material (RFC 5934 §2.2.4.1 / Appendix A.1)
// ---------------------------------------------------------------------------

/// `PlaintextSymmetricKey ::= OCTET STRING` — value of the
/// `id-aa-TAMP-contingencyPublicKeyDecryptKey` unsigned attribute.
pub type PlaintextSymmetricKey = OctetString;

/// `ApexContingencyKey ::= SEQUENCE { wrapAlgorithm AlgorithmIdentifier,
///   wrappedContinPubKey OCTET STRING }` (RFC 5934 Appendix A.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ApexContingencyKey {
    /// `wrapAlgorithm` — the key-wrap algorithm protecting the contingency key.
    pub wrap_algorithm: AlgorithmIdentifierOwned,
    /// `wrappedContinPubKey` — the wrapped (encrypted) contingency public key.
    pub wrapped_contin_pub_key: OctetString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    fn sample_msg_ref() -> TampMsgRef {
        TampMsgRef {
            target: TargetIdentifier::AllModules(Null),
            seq_num: 42,
        }
    }

    #[test]
    fn status_query_round_trip_with_defaults() {
        // Defaults (version=v2, terse=verbose) must be omitted on the wire and
        // restored on decode (RFC 5934 Appendix A.1 DEFAULT semantics).
        let q = TampStatusQuery {
            version: 2,
            terse: TerseOrVerbose::Verbose,
            query: sample_msg_ref(),
        };
        let der = q.to_der().unwrap();
        let decoded = TampStatusQuery::from_der(&der).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn status_query_non_default_terse_round_trip() {
        let q = TampStatusQuery {
            version: 2,
            terse: TerseOrVerbose::Terse,
            query: sample_msg_ref(),
        };
        let der = q.to_der().unwrap();
        let decoded = TampStatusQuery::from_der(&der).unwrap();
        assert_eq!(decoded.terse, TerseOrVerbose::Terse);
    }

    #[test]
    fn target_identifier_uri_round_trip() {
        let t = TargetIdentifier::Uri(Ia5String::new("https://m.example/1").unwrap());
        let der = t.to_der().unwrap();
        let decoded = TargetIdentifier::from_der(&der).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn target_identifier_communities_round_trip() {
        let t = TargetIdentifier::Communities(vec![
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.1"),
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.2"),
        ]);
        let der = t.to_der().unwrap();
        let decoded = TargetIdentifier::from_der(&der).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn tamp_error_round_trip() {
        let e = TampError {
            version: 2,
            msg_type: crate::oids::ID_CT_TAMP_UPDATE,
            status: crate::statuscode::StatusCode::SeqNumFailure,
            msg_ref: Some(sample_msg_ref()),
        };
        let der = e.to_der().unwrap();
        let decoded = TampError::from_der(&der).unwrap();
        assert_eq!(e, decoded);
    }

    #[test]
    fn community_update_round_trip() {
        let u = TampCommunityUpdate {
            version: 2,
            terse: TerseOrVerbose::Verbose,
            msg_ref: sample_msg_ref(),
            updates: CommunityUpdates {
                remove: None,
                add: Some(vec![ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.7")]),
            },
        };
        let der = u.to_der().unwrap();
        let decoded = TampCommunityUpdate::from_der(&der).unwrap();
        assert_eq!(u, decoded);
    }

    #[test]
    fn seq_num_adjust_round_trip() {
        let a = SequenceNumberAdjust {
            version: 2,
            msg_ref: sample_msg_ref(),
        };
        let der = a.to_der().unwrap();
        let decoded = SequenceNumberAdjust::from_der(&der).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn target_identifier_hw_modules_round_trip() {
        // Exercises a constructed (SEQUENCE OF) IMPLICIT-tagged CHOICE variant.
        let t = TargetIdentifier::HwModules(vec![HardwareModules {
            hw_type: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.42"),
            hw_serial_entries: vec![
                HardwareSerialEntry::Single(OctetString::new(vec![1, 2, 3]).unwrap()),
                HardwareSerialEntry::All(Null),
            ],
        }]);
        let der = t.to_der().unwrap();
        let decoded = TargetIdentifier::from_der(&der).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn terse_status_response_round_trip() {
        // Exercises StatusResponse::Terse (constructed IMPLICIT CHOICE variant)
        // and the usesApex BOOLEAN DEFAULT TRUE handling.
        let r = TampStatusResponse {
            version: 2,
            query: sample_msg_ref(),
            response: StatusResponse::Terse(TerseStatusResponse {
                ta_key_ids: vec![OctetString::new(vec![0xaa; 20]).unwrap()],
                communities: Some(vec![ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.1")]),
            }),
            uses_apex: true,
        };
        let der = r.to_der().unwrap();
        let decoded = TampStatusResponse::from_der(&der).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn terse_update_confirm_round_trip() {
        // Exercises UpdateConfirm::Terse = [0] SEQUENCE OF StatusCode.
        use crate::statuscode::StatusCode;
        let c = TampUpdateConfirm {
            version: 2,
            update: sample_msg_ref(),
            confirm: UpdateConfirm::Terse(vec![
                StatusCode::Success,
                StatusCode::TrustAnchorNotFound,
            ]),
        };
        let der = c.to_der().unwrap();
        let decoded = TampUpdateConfirm::from_der(&der).unwrap();
        assert_eq!(c, decoded);
    }
}
