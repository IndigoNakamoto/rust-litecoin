// SPDX-License-Identifier: CC0-1.0

//! BIP-370 + LIP-0007 PSBTv2 wire (MWEB kernel section).

use io::{Read, Write};

use crate::blockdata::transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Version};
use crate::consensus::encode::serialize;
use crate::consensus::encode::VarInt;
use crate::hashes::Hash;
use crate::io;
use crate::prelude::*;
use crate::psbt::map::{Input, Map, Output};
use crate::psbt::mweb::{self, MwebKernel};
use crate::psbt::raw;
use crate::psbt::serialize::Serialize;
use crate::psbt::{Error, Psbt};
use crate::{absolute, Amount, ScriptBuf};

/// BIP-370 `PSBT_GLOBAL_TX_VERSION`.
pub const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
/// BIP-370 `PSBT_GLOBAL_FALLBACK_LOCKTIME`.
pub const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// BIP-370 `PSBT_GLOBAL_INPUT_COUNT`.
pub const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// BIP-370 `PSBT_GLOBAL_OUTPUT_COUNT`.
pub const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// BIP-370 `PSBT_IN_PREVIOUS_TXID`.
pub const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
/// BIP-370 `PSBT_IN_OUTPUT_INDEX`.
pub const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
/// BIP-370 `PSBT_OUT_AMOUNT`.
pub const PSBT_OUT_AMOUNT: u8 = 0x03;
/// BIP-370 `PSBT_OUT_SCRIPT`.
pub const PSBT_OUT_SCRIPT: u8 = 0x04;

impl Psbt {
    /// True when this packet carries any typed MWEB map.
    pub fn has_mweb_components(&self) -> bool {
        self.mweb_tx_offset.is_some()
            || self.mweb_stealth_offset.is_some()
            || !self.mweb_kernels.is_empty()
            || !self.mweb_inputs.is_empty()
            || !self.mweb_outputs.is_empty()
            || self.inputs.iter().any(|i| i.mweb.output_id.is_some())
            || self.outputs.iter().any(|o| {
                o.mweb.stealth_address.is_some() || o.mweb.commit.is_some()
            })
    }

    /// LIP-0007: MWEB packets serialize as PSBTv2 (kernel section, no `unsigned_tx`).
    pub fn should_serialize_v2(&self) -> bool { self.version == 2 || self.has_mweb_components() }

    pub(crate) fn serialize_v2_to_writer(&self, w: &mut impl Write) -> io::Result<usize> {
        let mut written = 0;
        fn write_all(w: &mut impl Write, data: &[u8]) -> io::Result<usize> {
            w.write_all(data).map(|_| data.len())
        }

        written += write_all(w, b"psbt")?;
        written += write_all(w, &[0xff])?;
        written += write_all(w, &self.serialize_v2_global())?;

        for (txin, inp) in self.unsigned_tx.input.iter().zip(&self.inputs) {
            written += write_all(w, &serialize_canonical_input(txin, inp))?;
        }
        for mweb in &self.mweb_inputs {
            let inp = Input { mweb: mweb.clone(), ..Input::default() };
            written += write_all(w, &inp.serialize_map())?;
        }

        for (txout, out) in self.unsigned_tx.output.iter().zip(&self.outputs) {
            written += write_all(w, &serialize_canonical_output(txout, out))?;
        }
        for mweb in &self.mweb_outputs {
            written += write_all(w, &serialize_mweb_output(mweb))?;
        }

        for kernel in &self.mweb_kernels {
            written += write_all(w, &serialize_kernel_map(kernel))?;
        }

        Ok(written)
    }

    fn serialize_v2_global(&self) -> Vec<u8> {
        let mut pairs = Vec::new();
        let n_in = self.unsigned_tx.input.len() + self.mweb_inputs.len();
        let n_out = self.unsigned_tx.output.len() + self.mweb_outputs.len();

        pairs.push(raw::Pair {
            key: raw::Key { type_value: 0xFB, key: vec![] },
            value: 2u32.to_le_bytes().to_vec(),
        });
        pairs.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_TX_VERSION, key: vec![] },
            value: {
                let v: i32 = self.unsigned_tx.version.0;
                v.to_le_bytes().to_vec()
            },
        });
        pairs.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_FALLBACK_LOCKTIME, key: vec![] },
            value: self.unsigned_tx.lock_time.to_consensus_u32().to_le_bytes().to_vec(),
        });
        pairs.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_INPUT_COUNT, key: vec![] },
            value: serialize(&VarInt(n_in as u64)),
        });
        pairs.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_OUTPUT_COUNT, key: vec![] },
            value: serialize(&VarInt(n_out as u64)),
        });

        if let Some(off) = self.mweb_tx_offset {
            pairs.push(raw::Pair {
                key: raw::Key { type_value: mweb::types::MWEB_TX_OFFSET_TYPE, key: vec![] },
                value: off.to_vec(),
            });
        }
        if let Some(off) = self.mweb_stealth_offset {
            pairs.push(raw::Pair {
                key: raw::Key {
                    type_value: mweb::types::MWEB_TX_STEALTH_OFFSET_TYPE,
                    key: vec![],
                },
                value: off.to_vec(),
            });
        }
        if !self.mweb_kernels.is_empty() {
            pairs.push(raw::Pair {
                key: raw::Key { type_value: mweb::types::MWEB_KERNEL_COUNT_TYPE, key: vec![] },
                value: serialize(&VarInt(self.mweb_kernels.len() as u64)),
            });
        }

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            pairs.push(raw::Pair {
                key: raw::Key { type_value: 0x01, key: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }
        for (key, value) in self.proprietary.iter() {
            pairs.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }
        for (key, value) in self.unknown.iter() {
            pairs.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        let mut buf = Vec::new();
        for pair in pairs {
            buf.extend(&pair.serialize());
        }
        buf.push(0x00);
        buf
    }
}

fn serialize_canonical_input(txin: &TxIn, inp: &Input) -> Vec<u8> {
    let mut pairs = inp.get_pairs();
    pairs.insert(
        0,
        raw::Pair {
            key: raw::Key { type_value: PSBT_IN_OUTPUT_INDEX, key: vec![] },
            value: txin.previous_output.vout.to_le_bytes().to_vec(),
        },
    );
    pairs.insert(
        0,
        raw::Pair {
            key: raw::Key { type_value: PSBT_IN_PREVIOUS_TXID, key: vec![] },
            value: txin.previous_output.txid.as_byte_array().to_vec(),
        },
    );
    let mut buf = Vec::new();
    for pair in pairs {
        buf.extend(&pair.serialize());
    }
    buf.push(0x00);
    buf
}

fn serialize_canonical_output(txout: &TxOut, out: &Output) -> Vec<u8> {
    let mut pairs = out.get_pairs();
    pairs.insert(
        0,
        raw::Pair {
            key: raw::Key { type_value: PSBT_OUT_SCRIPT, key: vec![] },
            value: txout.script_pubkey.to_bytes(),
        },
    );
    pairs.insert(
        0,
        raw::Pair {
            key: raw::Key { type_value: PSBT_OUT_AMOUNT, key: vec![] },
            value: (txout.value.to_sat() as i64).to_le_bytes().to_vec(),
        },
    );
    let mut buf = Vec::new();
    for pair in pairs {
        buf.extend(&pair.serialize());
    }
    buf.push(0x00);
    buf
}

fn serialize_mweb_output(mweb: &crate::psbt::mweb::MwebOutput) -> Vec<u8> {
    let out = Output { mweb: mweb.clone(), ..Output::default() };
    let mut pairs = out.get_pairs();
    if let Some(amt) = mweb.amount {
        pairs.insert(
            0,
            raw::Pair {
                key: raw::Key { type_value: PSBT_OUT_AMOUNT, key: vec![] },
                value: (amt as i64).to_le_bytes().to_vec(),
            },
        );
    }
    let mut buf = Vec::new();
    for pair in pairs {
        buf.extend(&pair.serialize());
    }
    buf.push(0x00);
    buf
}

fn serialize_kernel_map(kernel: &MwebKernel) -> Vec<u8> {
    let mut buf = Vec::new();
    for (field_ty, key_data, value) in kernel.to_kv_pairs() {
        let pair = raw::Pair {
            key: raw::Key { type_value: field_ty, key: key_data },
            value,
        };
        buf.extend(&pair.serialize());
    }
    buf.push(0x00);
    buf
}

pub(crate) fn decode_kernel_map<R: Read + ?Sized>(r: &mut R) -> Result<MwebKernel, Error> {
    let mut kernel = MwebKernel::default();
    loop {
        match raw::Pair::decode(r) {
            Ok(pair) => kernel.apply_field(pair.key.type_value, &pair.key.key, &pair.value),
            Err(Error::NoMorePairs) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(kernel)
}

pub(crate) fn prevout_from_input(inp: &Input) -> Option<OutPoint> {
    let txid = inp.unknown.iter().find_map(|(k, v)| {
        if k.type_value == PSBT_IN_PREVIOUS_TXID && k.key.is_empty() && v.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(v);
            Some(Txid::from_byte_array(id))
        } else {
            None
        }
    })?;
    let vout = inp.unknown.iter().find_map(|(k, v)| {
        if k.type_value == PSBT_IN_OUTPUT_INDEX && k.key.is_empty() && v.len() == 4 {
            Some(u32::from_le_bytes(v[..4].try_into().ok()?))
        } else {
            None
        }
    })?;
    Some(OutPoint { txid, vout })
}

pub(crate) fn amount_from_output(out: &Output) -> Option<u64> {
    if let Some(a) = out.mweb.amount {
        return Some(a);
    }
    out.unknown.iter().find_map(|(k, v)| {
        if k.type_value == PSBT_OUT_AMOUNT && k.key.is_empty() && v.len() == 8 {
            let n = i64::from_le_bytes(v[..8].try_into().ok()?);
            Some(n as u64)
        } else {
            None
        }
    })
}

pub(crate) fn txout_from_output(out: &Output) -> Option<TxOut> {
    let amount = out.unknown.iter().find_map(|(k, v)| {
        if k.type_value == PSBT_OUT_AMOUNT && k.key.is_empty() && v.len() == 8 {
            let n = i64::from_le_bytes(v[..8].try_into().ok()?);
            Some(Amount::from_sat(n as u64))
        } else {
            None
        }
    })?;
    let script = out.unknown.iter().find_map(|(k, v)| {
        if k.type_value == PSBT_OUT_SCRIPT && k.key.is_empty() {
            Some(ScriptBuf::from(v.clone()))
        } else {
            None
        }
    })?;
    Some(TxOut { value: amount, script_pubkey: script })
}

pub(crate) fn dummy_tx(version: i32, lock_time: u32, n_in: usize, n_out: usize) -> Transaction {
    Transaction {
        version: Version(version),
        lock_time: absolute::LockTime::from_consensus(lock_time),
        input: vec![
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            };
            n_in
        ],
        output: vec![
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() };
            n_out
        ],
        mw_tx: None,
        is_hog_ex: false,
    }
}

/// Counts decoded from BIP-370 globals (v2) or `unsigned_tx` (v0).
pub(crate) struct GlobalMeta {
    pub input_count: usize,
    pub output_count: usize,
    pub kernel_count: usize,
    pub is_v2: bool,
}
