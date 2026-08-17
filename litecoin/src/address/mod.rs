// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for ordinary base58 Bitcoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use litecoin::{Address, PublicKey, Network};
//! use litecoin::secp256k1::{rand, Secp256k1};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! bitcoin = { version = "...", features = ["rand-std"] }
//! ```

pub mod error;

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::hrp::Hrp;
use hashes::{sha256, Hash, HashEngine};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::witness_program::WitnessProgram;
use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{self, Script, ScriptBuf, ScriptHash};
use crate::consensus::Params;
use crate::crypto::key::{
    CompressedPublicKey, PubkeyHash, PublicKey, TweakedPublicKey, UntweakedPublicKey,
};
use crate::network::{Network, NetworkKind};
use crate::prelude::*;
use crate::taproot::TapNodeHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    error::{
        FromScriptError, InvalidBase58PayloadLengthError, InvalidLegacyPrefixError, LegacyAddressTooLongError,
        NetworkValidationError, ParseError, P2shError, UnknownAddressTypeError, UnknownHrpError
    },
};

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to taproot.
    P2tr,
    /// Pay to anchor.
    P2a,
    /// Litecoin MimbleWimble stealth address (`ltcmweb1…` / `tmweb1…` / `rmweb1…`).
    Mweb,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
            AddressType::P2tr => "p2tr",
            AddressType::P2a => "p2a",
            AddressType::Mweb => "mweb",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            "p2tr" => Ok(AddressType::P2tr),
            "p2a" => Ok(AddressType::P2a),
            "mweb" => Ok(AddressType::Mweb),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation: sealed::NetworkValidation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// The inner representation of an address, without the network validation tag.
///
/// This struct represents the inner representation of an address without the network validation
/// tag, which is used to ensure that addresses are used only on the appropriate network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: PubkeyHash, network: NetworkKind },
    P2sh { hash: ScriptHash, network: NetworkKind },
    Segwit { program: WitnessProgram, hrp: KnownHrp },
    /// Litecoin MWEB stealth address: 33-byte scan key followed by 33-byte spend key,
    /// bech32-encoded under the per-network MWEB HRP.
    Mweb { scan: [u8; 33], spend: [u8; 33], hrp: MwebHrp },
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => PUBKEY_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => PUBKEY_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => SCRIPT_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => SCRIPT_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = program.version();
                let program = program.program().as_ref();

                if fmt.alternate() {
                    litecoin_segwit_encode_upper(fmt, hrp, version, program)
                } else {
                    litecoin_segwit_encode_lower(fmt, hrp, version, program)
                }
            }
            Mweb { scan, spend, hrp } => {
                // ltcsuite (`ltcd/ltcutil/address.go:EncodeAddress`) prepends a version fe (0)
                // to the bech32 data: `bech32.Encode(hrp, append([]byte{0}, converted...))`.
                // We mirror that by chaining a leading `Fe32::Q` (value 0) into the bech32
                // encoder via `with_witness_version`, which is exactly what the segwit helper
                // does for v0/v1+ addresses.
                use bech32::{Bech32, ByteIterExt, Fe32, Fe32IterExt};
                use core::fmt::Write;
                let mut payload = [0u8; 66];
                payload[..33].copy_from_slice(scan);
                payload[33..].copy_from_slice(spend);
                let hrp = hrp.to_hrp();
                let iter = payload.iter().copied().bytes_to_fes();
                let bytes = iter
                    .with_checksum::<Bech32>(&hrp)
                    .with_witness_version(Fe32::Q)
                    .bytes();
                if fmt.alternate() {
                    for b in bytes {
                        Write::write_char(fmt, (b as char).to_ascii_uppercase())?;
                    }
                } else {
                    for b in bytes {
                        Write::write_char(fmt, b as char)?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// Litecoin witness-version → bech32 variant rule.
///
/// Bitcoin (BIP-350) uses bech32 only for witness V0 and bech32m for V1+. Litecoin's HogEx
/// uses witness version 8 and MWEB peg-in scripts use version 9; both use the original bech32
/// checksum, *not* bech32m. See <https://github.com/rust-litecoin/rust-litecoin/issues/4>.
fn litecoin_uses_bech32(version: WitnessVersion) -> bool {
    matches!(version, WitnessVersion::V0 | WitnessVersion::V8 | WitnessVersion::V9)
}

/// Lower-case segwit encoder using Litecoin's V0/V8/V9-bech32 / V1+(except 8,9)-bech32m rule.
fn litecoin_segwit_encode_lower<W: fmt::Write>(
    fmt: &mut W,
    hrp: Hrp,
    version: WitnessVersion,
    program: &[u8],
) -> fmt::Result {
    use bech32::{Bech32, Bech32m, ByteIterExt, Fe32IterExt};
    let iter = program.iter().copied().bytes_to_fes();
    if litecoin_uses_bech32(version) {
        let bytes = iter
            .with_checksum::<Bech32>(&hrp)
            .with_witness_version(version.to_fe())
            .bytes();
        for b in bytes {
            fmt.write_char(b as char)?;
        }
    } else {
        let bytes = iter
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version.to_fe())
            .bytes();
        for b in bytes {
            fmt.write_char(b as char)?;
        }
    }
    Ok(())
}

/// Upper-case segwit encoder (BIP-173 QR-friendly form).
fn litecoin_segwit_encode_upper<W: fmt::Write>(
    fmt: &mut W,
    hrp: Hrp,
    version: WitnessVersion,
    program: &[u8],
) -> fmt::Result {
    use bech32::{Bech32, Bech32m, ByteIterExt, Fe32IterExt};
    let iter = program.iter().copied().bytes_to_fes();
    if litecoin_uses_bech32(version) {
        let bytes = iter
            .with_checksum::<Bech32>(&hrp)
            .with_witness_version(version.to_fe())
            .bytes();
        for b in bytes {
            fmt.write_char((b as char).to_ascii_uppercase())?;
        }
    } else {
        let bytes = iter
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version.to_fe())
            .bytes();
        for b in bytes {
            fmt.write_char((b as char).to_ascii_uppercase())?;
        }
    }
    Ok(())
}

/// Decode a Litecoin MWEB stealth address (`ltcmweb1…` / `tmweb1…` / `rmweb1…`).
///
/// Returns `(scan, spend, hrp)` on success. Wire format (per ltcsuite
/// `ltcd/ltcutil/address.go:EncodeAddress` and Litecoin Core `mw::StealthAddress::Encode`):
///   * bech32 (NOT bech32m) checksum over the per-network MWEB HRP
///   * 1-fe5 leading version field (always `0` today)
///   * 66 bytes of payload encoded as 5-bit groups: 33-byte scan pubkey || 33-byte spend pubkey
///   * 6-fe5 checksum
///
/// Both halves are validated as compressed secp256k1 public keys.
fn litecoin_mweb_decode(s: &str) -> Option<([u8; 33], [u8; 33], MwebHrp)> {
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Bech32, Fe32IterExt};

    let unchecked = UncheckedHrpstring::new(s).ok()?;
    let hrp = unchecked.hrp();
    let hrp = if hrp == HRP_LTCMWEB {
        MwebHrp::Mainnet
    } else if hrp == HRP_TMWEB {
        MwebHrp::Testnets
    } else if hrp == HRP_RMWEB {
        MwebHrp::Regtest
    } else {
        return None;
    };

    if !unchecked.has_valid_checksum::<Bech32>() {
        return None;
    }
    let checked = UncheckedHrpstring::new(s).ok()?.remove_checksum::<Bech32>();
    let mut fe_iter = checked.fe32_iter::<core::iter::Empty<u8>>();
    // First fe is the version byte (must be 0 today, matching ltcsuite/LTC Core).
    let version = fe_iter.next()?;
    if version.to_u8() != 0 {
        return None;
    }
    let bytes: Vec<u8> = fe_iter.fes_to_bytes().collect();
    if bytes.len() != 66 {
        return None;
    }
    let mut scan = [0u8; 33];
    let mut spend = [0u8; 33];
    scan.copy_from_slice(&bytes[..33]);
    spend.copy_from_slice(&bytes[33..]);
    // Reject addresses whose halves don't parse as compressed secp256k1 pubkeys — matches
    // ltcsuite's `secp256k1.ParsePubKey` calls in `decodeAddressMweb`.
    secp256k1::PublicKey::from_slice(&scan).ok()?;
    secp256k1::PublicKey::from_slice(&spend).ok()?;
    Some((scan, spend, hrp))
}

/// Try-both-checksum segwit decoder. We can't use `bech32::segwit::decode` because it always
/// expects bech32m for V1+, but LTC mandates bech32 for V8/V9. Validate against each checksum
/// type and apply the Litecoin variant rule explicitly.
fn litecoin_segwit_decode(s: &str) -> Option<(Hrp, WitnessVersion, Vec<u8>)> {
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Bech32, Bech32m};

    // Determine which checksum the string passes (if any) and extract bytes.
    let unchecked = UncheckedHrpstring::new(s).ok()?;
    let hrp = unchecked.hrp();
    let valid_bech32 = unchecked.has_valid_checksum::<Bech32>();
    let valid_bech32m = unchecked.has_valid_checksum::<Bech32m>();
    if !valid_bech32 && !valid_bech32m {
        return None;
    }

    // Strip the appropriate checksum and walk the fe32 stream: first symbol is the witness
    // version, the rest convert back to bytes.
    let checked = if valid_bech32 {
        UncheckedHrpstring::new(s).ok()?.remove_checksum::<Bech32>()
    } else {
        UncheckedHrpstring::new(s).ok()?.remove_checksum::<Bech32m>()
    };
    let mut fe_iter = checked.fe32_iter::<core::iter::Empty<u8>>();
    let version_fe = fe_iter.next()?;
    let program: Vec<u8> = {
        use bech32::Fe32IterExt;
        fe_iter.fes_to_bytes().collect()
    };

    let version = WitnessVersion::try_from(version_fe).ok()?;
    // Enforce Litecoin's version → checksum-variant invariant.
    let expected_bech32 = litecoin_uses_bech32(version);
    if expected_bech32 && !valid_bech32 {
        return None;
    }
    if !expected_bech32 && !valid_bech32m {
        return None;
    }
    Some((hrp, version, program))
}

/// Known bech32 human-readable parts.
///
/// This is the human-readable part before the separator (`1`) in a bech32 encoded address e.g.,
/// the "bc" in "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5".
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KnownHrp {
    /// The main Bitcoin network.
    Mainnet,
    /// The test networks, testnet (testnet3), testnet4, and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

/// Litecoin segwit HRP: mainnet (`ltc`).
const HRP_LTC: Hrp = Hrp::parse_unchecked("ltc");
/// Litecoin segwit HRP: testnet4 / signet (`tltc`).
const HRP_TLTC: Hrp = Hrp::parse_unchecked("tltc");
/// Litecoin segwit HRP: regtest (`rltc`).
const HRP_RLTC: Hrp = Hrp::parse_unchecked("rltc");

/// Litecoin MWEB stealth-address HRP: mainnet (`ltcmweb`).
const HRP_LTCMWEB: Hrp = Hrp::parse_unchecked("ltcmweb");
/// Litecoin MWEB stealth-address HRP: testnet4 / signet (`tmweb`).
const HRP_TMWEB: Hrp = Hrp::parse_unchecked("tmweb");
/// Litecoin MWEB stealth-address HRP: regtest (`rmweb`). Core v24+; 0.21 used `tmweb`.
const HRP_RMWEB: Hrp = Hrp::parse_unchecked("rmweb");

/// Known MWEB stealth-address human-readable parts.
///
/// Parallel to [`KnownHrp`] for segwit. Core v24 split regtest (`rmweb`) from
/// testnet4/signet (`tmweb`). [`NetworkKind::Test`] still maps to [`Self::Testnets`]
/// (`tmweb`) so existing testnet vectors stay stable; pass [`Network::Regtest`]
/// to encode `rmweb`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MwebHrp {
    /// Mainnet (`ltcmweb`).
    Mainnet,
    /// Testnet4 and signet (`tmweb`).
    Testnets,
    /// Regtest (`rmweb`).
    Regtest,
}

impl MwebHrp {
    /// Creates a `MwebHrp` from `network`.
    fn from_network(network: Network) -> Self {
        use Network::*;

        match network {
            Bitcoin => Self::Mainnet,
            Testnet4 | Signet => Self::Testnets,
            Regtest => Self::Regtest,
        }
    }

    /// Converts, infallibly, a known MWEB HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => HRP_LTCMWEB,
            Self::Testnets => HRP_TMWEB,
            Self::Regtest => HRP_RMWEB,
        }
    }
}

impl From<Network> for MwebHrp {
    fn from(n: Network) -> Self { Self::from_network(n) }
}

impl From<NetworkKind> for MwebHrp {
    fn from(k: NetworkKind) -> Self {
        match k {
            NetworkKind::Main => Self::Mainnet,
            // Test-kind without a specific [`Network`] is testnet, not v24 regtest.
            NetworkKind::Test => Self::Testnets,
        }
    }
}

impl KnownHrp {
    /// Creates a `KnownHrp` from `network`.
    fn from_network(network: Network) -> Self {
        use Network::*;

        match network {
            Bitcoin => Self::Mainnet,
            Testnet4 | Signet => Self::Testnets,
            Regtest => Self::Regtest,
        }
    }

    /// Creates a `KnownHrp` from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == HRP_LTC {
            Ok(Self::Mainnet)
        } else if hrp == HRP_TLTC {
            Ok(Self::Testnets)
        } else if hrp == HRP_RLTC {
            Ok(Self::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a known HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => HRP_LTC,
            Self::Testnets => HRP_TLTC,
            Self::Regtest => HRP_RLTC,
        }
    }
}

impl From<Network> for KnownHrp {
    fn from(n: Network) -> Self { Self::from_network(n) }
}

/// The data encoded by an `Address`.
///
/// This is the data used to encumber an output that pays to this address i.e., it is the address
/// excluding the network information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressData {
    /// Data encoded by a P2PKH address.
    P2pkh {
        /// The pubkey hash used to encumber outputs to this address.
        pubkey_hash: PubkeyHash,
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The script hash used to encumber outputs to this address.
        script_hash: ScriptHash,
    },
    /// Data encoded by a Segwit address.
    Segwit {
        /// The witness program used to encumber outputs to this address.
        witness_program: WitnessProgram,
    },
    /// Data encoded by a Litecoin MWEB stealth address. Unlike the other variants this does
    /// not produce a regular on-chain script_pubkey; the destination lives in the MWEB
    /// extension block.
    Mweb {
        /// 33-byte compressed scan public key (`A_i` in the MWEB design).
        scan: [u8; 33],
        /// 33-byte compressed spend public key (`B_i` in the MWEB design).
        spend: [u8; 33],
    },
}

/// A Bitcoin address.
///
/// ### Parsing addresses
///
/// When parsing string as an address, one has to pay attention to the network, on which the parsed
/// address is supposed to be valid. For the purpose of this validation, `Address` has
/// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
/// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
/// address has been checked. This marker type will prevent from calling certain functions unless the network
/// verification has been successfully completed.
///
/// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
/// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
/// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
/// `Address<NetworkChecked>` is returned.
///
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use litecoin::{Address, Network};
/// use litecoin::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9").unwrap()
///                .require_network(Network::Bitcoin).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9".parse::<Address<_>>()
///                .unwrap().require_network(Network::Bitcoin).unwrap();
/// ```
///
/// ### Formatting addresses
///
/// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
/// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
///
/// 1. `Display` is implemented only for `Address<NetworkChecked>`:
///
/// ```
/// # use std::str::FromStr;
/// # use litecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use litecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
///    an indicator that its network has not been checked. This is to encourage programmer to properly
///    check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use litecoin::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use litecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1");
/// ```
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
/// * [BIP141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
/// * [BIP142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
/// * [BIP341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
/// * [BIP350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// The `#[repr(transparent)]` attribute is used to guarantee the layout of the `Address` struct. It
// is an implementation detail and users should not rely on it in their code.
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0 .0, fmt) }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Bitcoin address");

#[cfg(feature = "serde")]
impl<N: NetworkValidation> serde::Serialize for Address<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }

    /// Marks the network of this address as unchecked.
    pub fn into_unchecked(self) -> Address<NetworkUnchecked> { Address(self.0, PhantomData) }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl Into<NetworkKind>) -> Address {
        let hash = pk.into();
        Self(AddressInner::P2pkh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: impl Into<NetworkKind>) -> Result<Address, P2shError> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(P2shError::ExcessiveScriptSize);
        }
        let hash = script.script_hash();
        Ok(Address::p2sh_from_hash(hash, network))
    }

    /// Creates a pay to script hash P2SH address from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Address {
        Self(AddressInner::P2sh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    pub fn p2wpkh(pk: &CompressedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh(pk);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwpkh(pk: &CompressedPublicKey, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(pk.wpubkey_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &Script, hrp: impl Into<KnownHrp>) -> Address {
        let program = WitnessProgram::p2wsh(script);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &Script, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(script.wscript_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        hrp: impl Into<KnownHrp>,
    ) -> Address {
        let program = WitnessProgram::p2tr(secp, internal_key, merkle_root);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, hrp: impl Into<KnownHrp>) -> Address {
        let program = WitnessProgram::p2tr_tweaked(output_key);
        Address::from_witness_program(program, hrp)
    }

    /// Creates an address from an arbitrary witness program.
    ///
    /// This only exists to support future witness versions. If you are doing normal mainnet things
    /// then you likely do not need this constructor.
    pub fn from_witness_program(program: WitnessProgram, hrp: impl Into<KnownHrp>) -> Address {
        let inner = AddressInner::Segwit { program, hrp: hrp.into() };
        Address(inner, PhantomData)
    }

    /// Creates a Litecoin MWEB stealth address from the scan / spend public keys.
    ///
    /// Accepting [`secp256k1::PublicKey`] forces both halves to be on-curve compressed points,
    /// matching ltcsuite's `secp256k1.ParsePubKey` validation in `NewAddressMweb`.
    ///
    /// Pass [`Network::Regtest`] (or [`MwebHrp::Regtest`]) for Core v24+ `rmweb`.
    /// [`NetworkKind::Test`] still encodes `tmweb`.
    pub fn mweb(
        scan: secp256k1::PublicKey,
        spend: secp256k1::PublicKey,
        hrp: impl Into<MwebHrp>,
    ) -> Address {
        Address(
            AddressInner::Mweb {
                scan: scan.serialize(),
                spend: spend.serialize(),
                hrp: hrp.into(),
            },
            PhantomData,
        )
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match self.0 {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, hrp: _ } =>
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2tr() {
                    Some(AddressType::P2tr)
                } else if program.is_p2a() {
                    Some(AddressType::P2a)
                } else {
                    None
                },
            AddressInner::Mweb { .. } => Some(AddressType::Mweb),
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(&self) -> AddressData {
        use AddressData::*;

        match self.0 {
            AddressInner::P2pkh { hash, network: _ } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, network: _ } => P2sh { script_hash: hash },
            AddressInner::Segwit { program, hrp: _ } => Segwit { witness_program: program },
            AddressInner::Mweb { scan, spend, hrp: _ } => Mweb { scan, spend },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match self.0 {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match self.0 {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the witness program for this address if this is a segwit address.
    pub fn witness_program(&self) -> Option<WitnessProgram> {
        use AddressInner::*;

        match self.0 {
            Segwit { ref program, hrp: _ } => Some(*program),
            _ => None,
        }
    }

    /// Checks whether or not the address is following Bitcoin standardness rules when
    /// *spending* from this address. *NOT* to be called by senders.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool { self.address_type().is_some() }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(
        script: &Script,
        params: impl AsRef<Params>,
    ) -> Result<Address, FromScriptError> {
        let network = params.as_ref().network;
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Address::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Address::p2sh_from_hash(hash, network))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode)?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..])?;
            Ok(Address::from_witness_program(program, network))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    ///
    /// **MWEB stealth addresses have no on-chain `script_pubkey`** — the destination lives in
    /// the MWEB extension block. This method returns an empty script for `AddressType::Mweb`;
    /// callers should detect `Mweb` via [`Address::address_type`] before constructing TxOuts.
    pub fn script_pubkey(&self) -> ScriptBuf {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } => ScriptBuf::new_p2pkh(hash),
            P2sh { ref hash, network: _ } => ScriptBuf::new_p2sh(hash),
            Segwit { ref program, hrp: _ } => {
                let prog = program.program();
                let version = program.version();
                ScriptBuf::new_witness_program_unchecked(version, prog)
            }
            Mweb { .. } => ScriptBuf::new(),
        }
    }

    /// Creates a URI string *litecoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP21 explicitly stating that the `litecoin:` prefix should be
    /// parsed as case-insensitive many wallets got this wrong and don't parse correctly.
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```
    /// # use core::fmt::Write;
    /// # const ADDRESS: &str = "LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9";
    /// # let address = ADDRESS.parse::<litecoin::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> Result<(), core::fmt::Error> {
    ///
    /// write!(writer, "{:#}", address)?;
    ///
    /// # Ok(())
    /// # })().unwrap();
    /// # assert_eq!(writer, ADDRESS);
    /// ```
    pub fn to_qr_uri(&self) -> String { format!("litecoin:{:#}", self) }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(&pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: &XOnlyPublicKey) -> bool {
        xonly_pubkey.serialize() == *self.payload_as_bytes()
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } if script.is_p2pkh() =>
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash),
            P2sh { ref hash, network: _ } if script.is_p2sh() =>
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash),
            Segwit { ref program, hrp: _ } if script.is_witness_program() =>
                &script.as_bytes()[2..] == program.program().as_bytes(),
            P2pkh { .. } | P2sh { .. } | Segwit { .. } => false,
            // MWEB stealth addresses don't have an on-chain script_pubkey.
            Mweb { .. } => false,
        }
    }

    /// Returns the "payload" for this address.
    ///
    /// The "payload" is the useful stuff excluding serialization prefix, the exact payload is
    /// dependent on the inner address:
    ///
    /// - For p2sh, the payload is the script hash.
    /// - For p2pkh, the payload is the pubkey hash.
    /// - For segwit addresses, the payload is the witness program.
    fn payload_as_bytes(&self) -> &[u8] {
        use AddressInner::*;
        match self.0 {
            P2sh { ref hash, network: _ } => hash.as_ref(),
            P2pkh { ref hash, network: _ } => hash.as_ref(),
            Segwit { ref program, hrp: _ } => program.program().as_bytes(),
            // For MWEB the "payload" is the concatenated scan||spend keys. Callers that need
            // the components separately should match on `AddressInner::Mweb` directly.
            Mweb { ref scan, .. } => scan,
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    ///
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }

    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresse use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use litecoin::{Address, Network};
    /// use litecoin::address::NetworkUnchecked;
    ///
    /// // Testnet P2SH address (prefix 0x3a → starts with Q).
    /// let address: Address<NetworkUnchecked> = "Qec8RUd8PgAMi6dKDKdHQ7zu71kyQNeU5m".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet4));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address<NetworkUnchecked> = "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet4), false);
    /// ```
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { hash: _, ref network } => *network == NetworkKind::from(n),
            P2sh { hash: _, ref network } => *network == NetworkKind::from(n),
            Segwit { program: _, ref hrp } => *hrp == KnownHrp::from_network(n),
            Mweb { scan: _, spend: _, ref hrp } => *hrp == MwebHrp::from_network(n),
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    ///
    /// # Errors
    ///
    /// This function only ever returns the [`ParseError::NetworkValidation`] variant of
    /// `ParseError`. This is not how we normally implement errors in this library but
    /// `require_network` is not a typical function, it is conceptually part of string parsing.
    ///
    ///  # Examples
    ///
    /// ```
    /// use litecoin::address::{NetworkChecked, NetworkUnchecked, ParseError};
    /// use litecoin::{Address, Network};
    ///
    /// const ADDR: &str = "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9";
    ///
    /// fn parse_and_validate_address(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()?
    ///                       .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_combinator(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()
    ///                       .and_then(|a| a.require_network(network))?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_show_types(network: Network) -> Result<Address, ParseError> {
    ///     let address: Address<NetworkChecked> = ADDR.parse::<Address<NetworkUnchecked>>()?
    ///                                                .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// let network = Network::Bitcoin;  // Don't hard code network in applications.
    /// let _ = parse_and_validate_address(network).unwrap();
    /// let _ = parse_and_validate_address_combinator(network).unwrap();
    /// let _ = parse_and_validate_address_show_types(network).unwrap();
    /// ```
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkValidationError { required, address: self }.into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address { Address(self.0, PhantomData) }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self { a.script_pubkey() }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.0, f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.0, f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Address<NetworkUnchecked>, ParseError> {
        // Litecoin MWEB stealth addresses (`ltcmweb1…` / `tmweb1…` / `rmweb1…`) use a bech32
        // payload of 66 bytes (scan ∥ spend pubkeys). They share the bech32 family but are
        // distinct from BIP-141 witness addresses, so check for the MWEB HRPs first.
        if let Some((scan, spend, hrp)) = litecoin_mweb_decode(s) {
            let inner = AddressInner::Mweb { scan, spend, hrp };
            return Ok(Address(inner, PhantomData));
        }

        if let Some((hrp, version, data)) = litecoin_segwit_decode(s) {
            // Reject programs with invalid lengths (BIP-141 length constraints) instead of
            // panicking — a valid-checksum string with a bad length is a parse error.
            let program = WitnessProgram::new(version, &data)?;

            let hrp = KnownHrp::from_hrp(hrp)?;
            let inner = AddressInner::Segwit { program, hrp };
            return Ok(Address(inner, PhantomData));
        }

        // If segwit decoding fails, assume its a legacy address.

        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(InvalidBase58PayloadLengthError { length: s.len() }.into());
        }

        let (prefix, data) = data.split_first().expect("length checked above");
        let data: [u8; 20] = data.try_into().expect("length checked above");

        let inner = match *prefix {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Main }
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Test }
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Main }
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Test }
            }
            // Litecoin Core defines a legacy P2SH prefix to keep old `3`-prefixed mainnet
            // addresses spendable. New addresses use 0x32 (`M`), but we accept 0x05 (`3`) on
            // parse so existing addresses still decode. See `chainparams.cpp` `SCRIPT_ADDRESS2`.
            0x05 => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Main }
            }
            // Litecoin testnet legacy P2SH prefix (`2`-prefixed addresses).
            0xc4 => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Test }
            }
            invalid => return Err(InvalidLegacyPrefixError { invalid }.into()),
        };

        Ok(Address(inner, PhantomData))
    }
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
fn segwit_redeem_hash(pubkey_hash: &PubkeyHash) -> crate::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_ref());
    crate::hashes::hash160::Hash::from_engine(sha_engine)
}

#[cfg(test)]
mod tests {
    use hex_lit::hex;

    use super::*;
    use crate::consensus::params;
    use crate::network::Network::{Bitcoin, Testnet4};

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), network)
                .expect("failed to create inner address from script_pubkey"),
            *addr,
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    #[test]
    fn test_p2pkh_address_58() {
        let hash = "13c60d8e68d7349f5b4ca362c3954b15045061b1".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a91413c60d8e68d7349f5b4ca362c3954b15045061b188ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "LLqYfYm5SBfqhoT3Rtu6Y4i41a1XzQ5YsL");

        let key = "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Test);
        assert_eq!(&addr.to_string(), "mhiDPVP2nJunaAgTjzWSHCYfAqxxrxzjmo");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Testnet4);
    }

    #[test]
    fn test_p2sh_address_58() {
        let hash = "ee34ac676bdaf6e370c8c820b948edfad3a873d8".parse::<ScriptHash>().unwrap();
        let addr = Address::p2sh_from_hash(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914ee34ac676bdaf6e370c8c820b948edfad3a873d887").unwrap(),
        );
        assert_eq!(&addr.to_string(), "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, NetworkKind::Test).unwrap();
        assert_eq!(&addr.to_string(), "QXMHrcosUiSxSujBVaMALPwjrDr2obVLNi");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Testnet4);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, NetworkKind::Test), Err(P2shError::ExcessiveScriptSize));
    }

    #[test]
    fn test_p2wpkh() {
        let key = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2wpkh(&key, KnownHrp::Mainnet);
        assert_eq!(&addr.to_string(), "ltc1qvzvkjn4q3nszqxrv3nraga2r822xjty3q2kjy7");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2wsh() {
        let script = ScriptBuf::from_hex("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae").unwrap();
        let addr = Address::p2wsh(&script, KnownHrp::Mainnet);
        assert_eq!(
            &addr.to_string(),
            "ltc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxsdgzjrh"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwpkh() {
        let key = "026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2shwpkh(&key, NetworkKind::Main);
        // P2SH wrapping P2WPKH still uses the M-prefix mainnet P2SH (0x32).
        assert_eq!(&addr.to_string(), "MWPa5PnonJ8CSevkDYM66V8yDWf8nSur8v");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwsh() {
        let script = ScriptBuf::from_hex("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
        let addr = Address::p2shwsh(&script, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "MCSyzGCqTczVFMvTn4VwpocbReQhXNC1kw");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let program = WitnessProgram::new(WitnessVersion::V13, &program).expect("valid program");

        let addr = Address::from_witness_program(program, KnownHrp::Mainnet);
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_hogex_addr_encoding() {
        // HogEx output script: witness version 8, 32-byte program.
        // Address must use bech32 (not bech32m). Regression test for the original
        // rust-litecoin issue #4. The tx is a real Litecoin mainnet HogEx coinbase output.
        let tx_bytes = hex!(
            "020000000008014c6760f58df93356b4f23ab8be1f33b44be814bdfafb77c9758682d39d492eb50000\
             000000ffffffff012c8a768b1c030000225820638c6c06eef97d9155e56990ad0cf3358ce00b47609\
             f132750cbd05364db58da0000000000"
        );
        let tx: crate::Transaction = crate::consensus::deserialize(&tx_bytes).unwrap();
        let addr = Address::from_script(&tx.output[0].script_pubkey, Network::Bitcoin).unwrap();
        // V8 witness program — must use bech32 checksum, not bech32m.
        assert_eq!(
            addr.to_string(),
            "ltc1gvwxxcphwl97ez409dxg26r8nxkxwqz68vz03xf6se0g9xexmtrdqu4hale"
        );
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_mweb_stealth_address_roundtrip() {
        // Construct an MWEB address from two real compressed secp256k1 pubkeys, then verify
        // the bech32 encoding round-trips and stays string-stable. The constructor demands
        // typed `secp256k1::PublicKey`s, so off-curve garbage cannot be stored.
        use crate::hex::FromHex;
        let scan_bytes: [u8; 33] = <[u8; 33]>::from_hex(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
        )
        .expect("scan hex");
        let spend_bytes: [u8; 33] = <[u8; 33]>::from_hex(
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
        )
        .expect("spend hex");
        let scan = secp256k1::PublicKey::from_slice(&scan_bytes).expect("scan on-curve");
        let spend = secp256k1::PublicKey::from_slice(&spend_bytes).expect("spend on-curve");

        let addr = Address::mweb(scan, spend, NetworkKind::Main);
        assert_eq!(addr.address_type(), Some(AddressType::Mweb));
        // Encoded form must start with the canonical `ltcmweb1qq…` prefix (HRP + separator +
        // leading version `q` (0) + the q-prefix of the scan pubkey).
        let encoded = addr.to_string();
        assert!(
            encoded.starts_with("ltcmweb1"),
            "expected ltcmweb HRP, got {}",
            encoded
        );

        // Round-trip via FromStr: parsed checked address must equal the original.
        let parsed: Address<NetworkUnchecked> = encoded.parse().expect("parse mweb addr");
        let checked = parsed.require_network(Network::Bitcoin).expect("mainnet mweb");
        assert_eq!(checked, addr);
        assert_eq!(checked.to_string(), encoded);

        // `script_pubkey` for MWEB returns an empty script — destination lives in the MWEB
        // extension block, not on the regular UTXO set.
        assert!(checked.script_pubkey().is_empty());

        // Network checks.
        let mweb_unchecked: Address<NetworkUnchecked> = encoded.parse().unwrap();
        assert!(mweb_unchecked.is_valid_for_network(Network::Bitcoin));
        assert!(!mweb_unchecked.is_valid_for_network(Network::Testnet4));

        // A real-mainnet MWEB address must NOT decode under a testnet HRP.
        let testnet_encoded = encoded.replace("ltcmweb1", "tmweb1");
        assert!(
            testnet_encoded.parse::<Address<NetworkUnchecked>>().is_err(),
            "checksum-busted HRP swap must not parse"
        );
    }

    #[test]
    fn test_mweb_regtest_hrp_is_rmweb() {
        use crate::hex::FromHex;
        let scan_bytes: [u8; 33] = <[u8; 33]>::from_hex(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
        )
        .expect("scan hex");
        let spend_bytes: [u8; 33] = <[u8; 33]>::from_hex(
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
        )
        .expect("spend hex");
        let scan = secp256k1::PublicKey::from_slice(&scan_bytes).expect("scan on-curve");
        let spend = secp256k1::PublicKey::from_slice(&spend_bytes).expect("spend on-curve");

        let regtest = Address::mweb(scan, spend, Network::Regtest);
        let encoded = regtest.to_string();
        assert!(
            encoded.starts_with("rmweb1"),
            "expected rmweb HRP for Network::Regtest, got {}",
            encoded
        );
        let parsed: Address<NetworkUnchecked> = encoded.parse().expect("parse rmweb");
        assert!(parsed.is_valid_for_network(Network::Regtest));
        assert!(!parsed.is_valid_for_network(Network::Testnet4));
        assert!(!parsed.is_valid_for_network(Network::Bitcoin));
        assert_eq!(parsed.require_network(Network::Regtest).unwrap(), regtest);

        // NetworkKind::Test stays on the testnet HRP (tmweb), not v24 regtest.
        let testnet = Address::mweb(scan, spend, NetworkKind::Test);
        let tmweb = testnet.to_string();
        assert!(
            tmweb.starts_with("tmweb1"),
            "expected tmweb HRP for NetworkKind::Test, got {}",
            tmweb
        );
        let tmweb_parsed: Address<NetworkUnchecked> = tmweb.parse().expect("parse tmweb");
        assert!(tmweb_parsed.is_valid_for_network(Network::Testnet4));
        assert!(tmweb_parsed.is_valid_for_network(Network::Signet));
        assert!(!tmweb_parsed.is_valid_for_network(Network::Regtest));
    }

    #[test]
    fn test_mweb_stealth_address_invalid_pubkey_rejected() {
        // 66 zero bytes do NOT form valid compressed pubkeys (compressed pubkeys start with
        // 0x02 or 0x03). Even with a valid bech32 checksum the parser must reject these,
        // matching ltcsuite's `secp256k1.ParsePubKey` check.
        use bech32::{Bech32, ByteIterExt, Fe32, Fe32IterExt};
        let mut buf = String::new();
        let payload = [0u8; 66];
        let iter = payload.iter().copied().bytes_to_fes();
        let bytes = iter
            .with_checksum::<Bech32>(&HRP_LTCMWEB)
            .with_witness_version(Fe32::Q)
            .bytes();
        for b in bytes {
            buf.push(b as char);
        }
        assert!(buf.parse::<Address<NetworkUnchecked>>().is_err());
    }

    #[test]
    fn test_mweb_pegin_v9_addr_encoding() {
        // Witness version 9 (MWEB peg-in) similarly uses bech32 (not bech32m).
        let program = hex!(
            "660306b11402a8a3c2f13ff9bd1a6f7e1aaa3f811fb72d498bf8e0b11f9eb80e"
        );
        let program = WitnessProgram::new(WitnessVersion::V9, &program).expect("v9 program");
        let addr = Address::from_witness_program(program, KnownHrp::Mainnet);
        // Round-trip via Display + FromStr verifies the bech32 (not bech32m) checksum path.
        let parsed: Address<NetworkUnchecked> = addr.to_string().parse().expect("parse");
        assert_eq!(parsed.assume_checked(), addr);
    }

    #[test]
    fn test_address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9";
        let unchecked = Address::from_str(addr_str).unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked.clone() }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn test_address_type() {
        let addresses = [
            ("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1", Some(AddressType::P2pkh)),
            ("MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9", Some(AddressType::P2sh)),
            ("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", Some(AddressType::P2wpkh)),
            (
                "ltc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxsdgzjrh",
                Some(AddressType::P2wsh),
            ),
            (
                "ltc1paardr2nczq0rx5rqpfwnvpzm497zvux64y0f7wjgcs7xuuuh2nnqd8yawa",
                Some(AddressType::P2tr),
            ),
        ];
        for (address, expected_type) in &addresses {
            let addr = Address::from_str(address)
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr =
            Address::from_str("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("76a91413c60d8e68d7349f5b4ca362c3954b15045061b188ac").unwrap()
        );

        let addr =
            Address::from_str("MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("a914ee34ac676bdaf6e370c8c820b948edfad3a873d887").unwrap()
        );

        // Testnet P2WSH: derive the LTC address from the witness program directly.
        let tltc_p2wsh_spk = ScriptBuf::from_hex(
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        )
        .unwrap();
        let addr = Address::from_script(&tltc_p2wsh_spk, Network::Testnet4).unwrap();
        let tltc_p2wsh = addr.to_string();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(json, serde_json::Value::String(tltc_p2wsh.clone()));
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(into.script_pubkey(), tltc_p2wsh_spk);

        // Regtest P2WPKH: same approach.
        let rltc_p2wpkh_spk =
            ScriptBuf::from_hex("001454d26dddb59c7073c6a197946ea1841951fa7a74").unwrap();
        let addr = Address::from_script(&rltc_p2wpkh_spk, Network::Regtest).unwrap();
        let rltc_p2wpkh = addr.to_string();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(json, serde_json::Value::String(rltc_p2wpkh));
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(into.script_pubkey(), rltc_p2wpkh_spk);
    }

    #[test]
    fn test_qr_string() {
        // Base58 LTC mainnet P2PKH and P2SH: lowercase scheme, mixed-case address.
        for el in
            ["LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1", "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9"].iter()
        {
            let addr =
                Address::from_str(el).unwrap().require_network(Network::Bitcoin).expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("litecoin:{}", el));
        }

        // Bech32 segwit: uppercase scheme + uppercase address per BIP173.
        for el in
            ["ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"].iter()
        {
            let addr = Address::from_str(el).unwrap().assume_checked();
            assert_eq!(addr.to_qr_uri(), format!("litecoin:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn p2tr_from_untweaked() {
        // Same internal key as BIP-086 example; HRP swapped to `ltc`.
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let secp = Secp256k1::verification_only();
        let address = Address::p2tr(&secp, internal_key, None, KnownHrp::Mainnet);
        assert_eq!(
            address.to_string(),
            "ltc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxq4arnzx"
        );
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
        roundtrips(&address, Bitcoin);
    }

    #[test]
    fn test_is_related_to_pubkey_p2wpkh() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let compressed: CompressedPublicKey = pubkey.try_into().expect("compressed");
        let address = Address::p2wpkh(&compressed, KnownHrp::Mainnet);

        assert!(address.is_related_to_pubkey(&pubkey));

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2shwpkh() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let compressed: CompressedPublicKey = pubkey.try_into().expect("compressed");
        let address = Address::p2shwpkh(&compressed, NetworkKind::Main);

        assert!(address.is_related_to_pubkey(&pubkey));

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let address = Address::p2pkh(pubkey, NetworkKind::Main);

        assert!(address.is_related_to_pubkey(&pubkey));

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Testnet4)
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert!(address.is_related_to_pubkey(&pubkey));

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey));
    }

    #[test]
    fn test_is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert!(address.is_related_to_xonly_pubkey(&xonly_pubkey));
    }

    #[test]
    fn test_fail_address_from_script() {
        use crate::witness_program;

        let bad_p2wpkh = ScriptBuf::from_hex("0014dbc5b0a8f9d4353b4b54c3db48846bb15abfec").unwrap();
        let bad_p2wsh = ScriptBuf::from_hex(
            "00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623",
        )
        .unwrap();
        let invalid_segwitv0_script =
            ScriptBuf::from_hex("001161458e330389cd0437ee9fe3641d70cc18").unwrap();
        let expected = Err(FromScriptError::UnrecognizedScript);

        assert_eq!(Address::from_script(&bad_p2wpkh, Network::Bitcoin), expected);
        assert_eq!(Address::from_script(&bad_p2wsh, Network::Bitcoin), expected);
        assert_eq!(
            Address::from_script(&invalid_segwitv0_script, &params::MAINNET),
            Err(FromScriptError::WitnessProgram(witness_program::Error::InvalidSegwitV0Length(17)))
        );
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = AddressType::from_str("p2tr").expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = AddressType::from_str("invalid");
        let want = Err(UnknownAddressTypeError("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    fn test_matches_script_pubkey() {
        let addresses = [
            "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",
            "LLqYfYm5SBfqhoT3Rtu6Y4i41a1XzQ5YsL",
            "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9",
            "MWPa5PnonJ8CSevkDYM66V8yDWf8nSur8v",
            "ltc1qvzvkjn4q3nszqxrv3nraga2r822xjty3q2kjy7",
            "ltc1paardr2nczq0rx5rqpfwnvpzm497zvux64y0f7wjgcs7xuuuh2nnqd8yawa",
        ];
        for addr in &addresses {
            let addr = Address::from_str(addr).unwrap().require_network(Network::Bitcoin).unwrap();
            for another in &addresses {
                let another =
                    Address::from_str(another).unwrap().require_network(Network::Bitcoin).unwrap();
                assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
            }
        }
    }

    #[test]
    fn pay_to_anchor_address_regtest() {
        // P2A on Litecoin regtest: same witness program (v1, 0x4e73) but with the rltc HRP
        // so the bech32m checksum differs.
        let script = ScriptBuf::new_p2a();
        let address = Address::from_script(&script, Network::Regtest).unwrap();
        let address_str = address.to_string();

        assert!(address_str.starts_with("rltc1p"), "got {}", address_str);
        // Round-trip parses back to the same address.
        let parsed: Address<NetworkUnchecked> = address_str.parse().unwrap();
        assert_eq!(address.as_unchecked(), &parsed);

        // Verify that the address is considered standard and that the output type is P2a.
        assert!(address.is_spend_standard());
        assert_eq!(address.address_type(), Some(AddressType::P2a));
    }
}
