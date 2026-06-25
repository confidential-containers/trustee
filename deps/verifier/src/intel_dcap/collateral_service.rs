use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use strum::Display;

/// Fixed-length byte array that serializes as uppercase hex and deserializes
/// from hex (case-insensitive).
#[derive(Clone, Copy)]
pub struct HexBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for HexBytes<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Deref for HexBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for HexBytes<N> {
    fn from(v: [u8; N]) -> Self {
        Self(v)
    }
}

impl<const N: usize> Serialize for HexBytes<N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex::serialize_upper(self.0, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexBytes<N>
where
    [u8; N]: hex::FromHex,
    <[u8; N] as hex::FromHex>::Error: std::fmt::Display,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex::deserialize(deserializer).map(HexBytes)
    }
}

const NUM_TCB_COMPONENTS: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoJson {
    pub tcb_info: TcbInfo,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u8,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub fmspc: HexBytes<6>,
    pub pce_id: HexBytes<2>,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub mrsigner: Vec<u8>,
    pub attributes: HexBytes<8>,
    pub attributes_mask: HexBytes<8>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub mrsigner: Vec<u8>,
    pub attributes: HexBytes<8>,
    pub attributes_mask: HexBytes<8>,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Serialize, Deserialize, Display)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(
        rename = "advisoryIDs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub advisory_ids: Option<Vec<String>>,
}

/// TCB SVN components for a single TCB level.
#[derive(Serialize, Deserialize)]
pub struct Tcb {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sgxtcbcomponents: Option<TcbComponentList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcesvn: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<TcbComponentList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isvsvn: Option<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct TcbComponentList(pub [TcbComponent; NUM_TCB_COMPONENTS]);

impl Deref for TcbComponentList {
    type Target = [TcbComponent; NUM_TCB_COMPONENTS];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct TcbComponent {
    pub svn: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    pub enclave_identity: EnclaveIdentity,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u8,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: HexBytes<4>,
    pub miscselect_mask: HexBytes<4>,
    pub attributes: HexBytes<16>,
    pub attributes_mask: HexBytes<16>,
    pub mrsigner: HexBytes<32>,
    pub isvprodid: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Deserialize)]
pub struct PlatformCollaterals {
    pub collaterals: PcsCollaterals,
}

#[derive(Deserialize)]
pub struct PcsCollaterals {
    pub tcbinfos: Vec<TcbInfoEntry>,
    pub pckcacrl: PckCaCrl,

    /// QE enclave identity.
    #[serde(default)]
    pub qeidentity: Option<QeIdentity>,
    #[serde(default)]
    pub qeidentity_early: Option<QeIdentity>,

    /// TD QE enclave identity.
    #[serde(default)]
    pub tdqeidentity: Option<QeIdentity>,
    #[serde(default)]
    pub tdqeidentity_early: Option<QeIdentity>,

    pub certificates: PcsCollateralCertificates,

    /// Root CA CRL (hex-encoded DER).
    pub rootcacrl: String,
    #[serde(default)]
    pub rootcacrl_cdp: Option<String>,
}

/// One FMSPC entry in `collaterals.tcbinfos`.
///
/// TDX TCB info is optional and only present when the FMSPC corresponds to a TDX-capable platform.
/// The `_early` variants are present only when the tool was run with `tcb_update_type = all`.
#[derive(Deserialize)]
pub struct TcbInfoEntry {
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],

    #[serde(default)]
    pub sgx_tcbinfo: Option<TcbInfoJson>,
    #[serde(default)]
    pub sgx_tcbinfo_early: Option<TcbInfoJson>,

    #[serde(default)]
    pub tdx_tcbinfo: Option<TcbInfoJson>,
    #[serde(default)]
    pub tdx_tcbinfo_early: Option<TcbInfoJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PckCaCrl {
    pub processor_crl: String,
    pub platform_crl: String,
}

impl std::ops::Index<&PckCaType> for PckCaCrl {
    type Output = str;

    fn index(&self, ca: &PckCaType) -> &str {
        match ca {
            PckCaType::Processor => &self.processor_crl,
            PckCaType::Platform => &self.platform_crl,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct PckCrlIssuerChains {
    pub processor: String,
    pub platform: String,
}

impl std::ops::Index<&PckCaType> for PckCrlIssuerChains {
    type Output = str;

    fn index(&self, ca: &PckCaType) -> &str {
        match ca {
            PckCaType::Processor => &self.processor,
            PckCaType::Platform => &self.platform,
        }
    }
}

#[derive(Deserialize)]
pub struct PcsCollateralCertificates {
    #[serde(rename = "TCB-Info-Issuer-Chain")]
    pub tcb_info_issuer_chain: String,
    #[serde(rename = "SGX-Enclave-Identity-Issuer-Chain")]
    pub enclave_identity_issuer_chain: String,
    #[serde(rename = "SGX-PCK-Certificate-Issuer-Chain", default)]
    pub pck_crl_issuer_chains: Option<PckCrlIssuerChains>,
}

/// CA type used to select a PCK CRL issuer chain.
#[derive(Display)]
#[strum(serialize_all = "lowercase")]
pub enum PckCaType {
    Platform,
    Processor,
}

/// The collateral fetched from a `CollateralService`: the response body and an optional
/// PEM-encoded certificate chain extracted from the response headers.
pub struct CollateralData {
    pub body: Vec<u8>,
    pub cert_chain: Option<Vec<u8>>,
}

pub enum CollateralType<'a> {
    TcbInfo(&'a IntelTee, [u8; 6]),
    QeIdentity(&'a IntelTee),
    /// CA type; the CRL is always returned as raw DER bytes.
    PckCrl(PckCaType),
    RootCaCrl(Option<&'a str>),
}

/// Intel TEE type used to select the correct PCS endpoint path segment.
#[derive(Debug, Display)]
#[strum(serialize_all = "lowercase")]
pub enum IntelTee {
    Sgx,
    Tdx,
}

pub trait CollateralService: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn get(&self, ct: CollateralType<'_>) -> Result<CollateralData, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::{QeIdentity, TcbInfoJson};
    use assert_json_diff::assert_json_eq;

    #[test]
    fn deserialize_tcb_info() {
        let text = std::fs::read_to_string("./test_data/tcbInfo.json").expect("read tcbInfo.json");
        let d: TcbInfoJson = serde_json::from_str(&text).expect("deserialize TcbInfoJson");

        let ti = &d.tcb_info;
        assert_eq!(ti.id, "TDX");
        assert_eq!(ti.version, 3);
        assert_eq!(*ti.fmspc, [0x00, 0xA0, 0x6D, 0x08, 0x00, 0x00]);
        assert_eq!(*ti.pce_id, [0x00, 0x00]);

        let tdx_mod = ti.tdx_module.as_ref().expect("tdxModule present");
        assert_eq!(*tdx_mod.attributes_mask, [0xFF; 8]);

        assert!(!d.signature.is_empty());

        // Round-trip: serialized JSON must match the original.
        let serialized = serde_json::to_value(&d).expect("serialize TcbInfoJson");
        let original: serde_json::Value =
            serde_json::from_str(&text).expect("re-parse tcbInfo.json");
        assert_json_eq!(original, serialized);
    }

    #[test]
    fn deserialize_enclave_identity() {
        let text = std::fs::read_to_string("./test_data/enclaveIdentity.json")
            .expect("read enclaveIdentity.json");
        let d: QeIdentity = serde_json::from_str(&text).expect("deserialize QeIdentity");

        let ei = &d.enclave_identity;
        assert_eq!(ei.id, "TD_QE");
        assert_eq!(ei.version, 2);
        assert_eq!(*ei.miscselect, [0x00; 4]);
        assert_eq!(*ei.miscselect_mask, [0xFF; 4]);

        assert!(!d.signature.is_empty());

        // Round-trip.
        let serialized = serde_json::to_value(&d).expect("serialize QeIdentity");
        let original: serde_json::Value =
            serde_json::from_str(&text).expect("re-parse enclaveIdentity.json");
        assert_json_eq!(original, serialized);
    }
}
