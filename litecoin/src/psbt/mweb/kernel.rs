// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;
use crate::psbt::mweb::types::*;

/// One MWEB kernel PSBT map (ltcd `PKernel`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MwebKernel {
    /// Excess commitment.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n33")
    )]
    pub excess_commit: Option<[u8; 33]>,
    /// Stealth excess (33-byte compressed pubkey).
    pub stealth_commit: Option<Vec<u8>>,
    /// Fee (litoshis).
    pub fee: Option<u64>,
    /// Peg-in amount.
    pub pegin_amount: Option<u64>,
    /// Peg-out serialization.
    pub pegout: Option<Vec<u8>>,
    /// Lock height.
    pub lock_height: Option<u32>,
    /// Features.
    pub features: Option<u8>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
    /// Signature (64 bytes).
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n64")
    )]
    pub signature: Option<[u8; 64]>,
}

impl MwebKernel {
    /// Encode kernel map as typed `(field_ty, value)` pairs.
    pub fn to_pairs(&self) -> Vec<(u8, Vec<u8>)> {
        let mut pairs = Vec::new();
        if let Some(c) = self.excess_commit {
            pairs.push((MWEB_KERNEL_EXCESS_COMMIT_TYPE, c.to_vec()));
        }
        if let Some(ref c) = self.stealth_commit {
            pairs.push((MWEB_KERNEL_STEALTH_COMMIT_TYPE, c.clone()));
        }
        if let Some(f) = self.fee {
            pairs.push((MWEB_KERNEL_FEE_TYPE, f.to_le_bytes().to_vec()));
        }
        if let Some(a) = self.pegin_amount {
            pairs.push((MWEB_KERNEL_PEGIN_AMOUNT_TYPE, a.to_le_bytes().to_vec()));
        }
        if let Some(ref p) = self.pegout {
            pairs.push((MWEB_KERNEL_PEGOUT_TYPE, p.clone()));
        }
        if let Some(h) = self.lock_height {
            pairs.push((MWEB_KERNEL_LOCK_HEIGHT_TYPE, h.to_le_bytes().to_vec()));
        }
        if let Some(f) = self.features {
            pairs.push((MWEB_KERNEL_FEATURES_TYPE, vec![f]));
        }
        if let Some(ref e) = self.extra_data {
            pairs.push((MWEB_KERNEL_EXTRA_DATA_TYPE, e.clone()));
        }
        if let Some(s) = self.signature {
            pairs.push((MWEB_KERNEL_SIGNATURE_TYPE, s.to_vec()));
        }
        pairs
    }

    /// Apply one kernel field from wire `(field_ty, value)`.
    pub fn apply_field(&mut self, field_ty: u8, value: &[u8]) {
        match field_ty {
            MWEB_KERNEL_EXCESS_COMMIT_TYPE if value.len() == 33 => {
                let mut c = [0u8; 33];
                c.copy_from_slice(value);
                self.excess_commit = Some(c);
            }
            MWEB_KERNEL_STEALTH_COMMIT_TYPE => self.stealth_commit = Some(value.to_vec()),
            MWEB_KERNEL_FEE_TYPE if value.len() == 8 => {
                self.fee = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
            }
            MWEB_KERNEL_PEGIN_AMOUNT_TYPE if value.len() == 8 => {
                self.pegin_amount = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
            }
            MWEB_KERNEL_PEGOUT_TYPE => self.pegout = Some(value.to_vec()),
            MWEB_KERNEL_LOCK_HEIGHT_TYPE if value.len() == 4 => {
                self.lock_height = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
            }
            MWEB_KERNEL_FEATURES_TYPE if !value.is_empty() => self.features = Some(value[0]),
            MWEB_KERNEL_EXTRA_DATA_TYPE => self.extra_data = Some(value.to_vec()),
            MWEB_KERNEL_SIGNATURE_TYPE if value.len() == 64 => {
                let mut s = [0u8; 64];
                s.copy_from_slice(value);
                self.signature = Some(s);
            }
            _ => {}
        }
    }

    /// Build from an iterator of `(field_ty, value)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Self {
        let mut out = Self::default();
        for (ty, val) in pairs {
            out.apply_field(ty, &val);
        }
        out
    }

    /// Merge `other` into `self`, keeping existing values when set.
    pub fn combine(&mut self, other: Self) {
        if self.excess_commit.is_none() {
            self.excess_commit = other.excess_commit;
        }
        if self.stealth_commit.is_none() {
            self.stealth_commit = other.stealth_commit;
        }
        if self.fee.is_none() {
            self.fee = other.fee;
        }
        if self.pegin_amount.is_none() {
            self.pegin_amount = other.pegin_amount;
        }
        if self.pegout.is_none() {
            self.pegout = other.pegout;
        }
        if self.lock_height.is_none() {
            self.lock_height = other.lock_height;
        }
        if self.features.is_none() {
            self.features = other.features;
        }
        if self.extra_data.is_none() {
            self.extra_data = other.extra_data;
        }
        if self.signature.is_none() {
            self.signature = other.signature;
        }
    }
}
