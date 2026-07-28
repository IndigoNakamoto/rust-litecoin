// SPDX-License-Identifier: CC0-1.0

//! ltcsuite-compatible PSBT MWEB key types and maps.
//!
//! Key codes match [`ltcsuite/ltcd` `ltcutil/psbt/types.go`](https://github.com/ltcsuite/ltcd/blob/master/ltcutil/psbt/types.go)
//! (first-class `0x90+` types — not BIP174 `0xFC` proprietary blobs).
//!
//! Global kernel fields use `type_value = 0x93` with key `[kernel_index: u32 LE][field_ty: u8]`.
//! Parallel pure-MWEB input/output maps (when `unsigned_tx` has no matching vin/vout slots) use
//! global keys: input fields as `type_value = field` with 4-byte index key; output fields as
//! `type_value = 0x94` with 5-byte `[index][field_ty]` key.

mod extract;
mod input;
mod kernel;
mod output;
pub mod types;

pub use self::extract::assemble_mw_tx;
pub use self::input::MwebInput;
pub use self::kernel::MwebKernel;
pub use self::output::MwebOutput;
pub use self::types::*;

pub(crate) fn ensure_index<T: Default>(vec: &mut Vec<T>, index: usize) {
    while vec.len() <= index {
        vec.push(T::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::BTreeMap;
    use crate::psbt::raw;
    use secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(seed: u8) -> Vec<u8> {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret");
        sk.public_key(&Secp256k1::new()).serialize().to_vec()
    }

    #[test]
    fn type_codes_match_ltcd() {
        assert_eq!(MWEB_TX_OFFSET_TYPE, 0x90);
        assert_eq!(MWEB_TX_STEALTH_OFFSET_TYPE, 0x91);
        assert_eq!(MWEB_KERNEL_COUNT_TYPE, 0x92);
        assert_eq!(MWEB_GLOBAL_KERNEL_FIELD_TYPE, 0x93);
        assert_eq!(MWEB_GLOBAL_OUTPUT_FIELD_TYPE, 0x94);
        assert_eq!(MWEB_SPENT_OUTPUT_ID_TYPE, 0x90);
        assert_eq!(MWEB_STEALTH_ADDRESS_OUTPUT_TYPE, 0x90);
        assert_eq!(MWEB_KERNEL_EXCESS_COMMIT_TYPE, 0);
        assert_eq!(MWEB_KERNEL_SIGNATURE_TYPE, 8);
    }

    #[test]
    fn mweb_input_roundtrip_pairs() {
        let inp = MwebInput {
            output_id: Some([9u8; 32]),
            commit: Some({
                let mut c = [0u8; 33];
                c[0] = 2;
                c
            }),
            amount: Some(50_000),
            address_index: Some(2),
            features: Some(1),
            ..MwebInput::default()
        };
        let back = MwebInput::from_kv_pairs(inp.to_kv_pairs());
        assert_eq!(back.output_id, inp.output_id);
        assert_eq!(back.commit, inp.commit);
        assert_eq!(back.amount, inp.amount);
        assert_eq!(back.address_index, inp.address_index);
        assert_eq!(back.features, inp.features);
    }

    #[test]
    fn mweb_input_key_origin_ltcd_wire() {
        use crate::bip32::{ChildNumber, DerivationPath, Fingerprint};
        use crate::psbt::serialize::{Deserialize, Serialize};

        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.public_key(&Secp256k1::new());
        let fingerprint = Fingerprint::from([0x11, 0x22, 0x33, 0x44]);
        let path: DerivationPath = vec![
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(100).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]
        .into();
        let ks = (fingerprint, path);

        let inp = MwebInput {
            address_index: Some(3),
            master_scan_key_origin: Some((pk, ks.clone())),
            master_spend_key_origin: Some((pk, {
                let spend_path: DerivationPath = vec![
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_hardened_idx(100).unwrap(),
                    ChildNumber::from_hardened_idx(1).unwrap(),
                ]
                .into();
                (fingerprint, spend_path)
            })),
            ..MwebInput::default()
        };
        inp.validate_key_origins().unwrap();

        let pairs = inp.to_kv_pairs();
        let scan = pairs
            .iter()
            .find(|(ty, _, _)| *ty == MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE)
            .unwrap();
        assert_eq!(scan.1, pk.serialize().to_vec());
        // Value is BIP174 KeySource: fingerprint || LE child indexes
        assert_eq!(scan.2, ks.serialize());
        assert_eq!(
            <(Fingerprint, DerivationPath) as Deserialize>::deserialize(&scan.2).unwrap(),
            ks
        );

        let back = MwebInput::from_kv_pairs(inp.to_kv_pairs());
        assert_eq!(back.master_scan_key_origin, inp.master_scan_key_origin);
        assert_eq!(back.master_spend_key_origin, inp.master_spend_key_origin);
        assert_eq!(back.address_index, Some(3));
    }

    #[test]
    fn type_codes_match_ltcd_origins() {
        assert_eq!(MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE, 0x9A);
        assert_eq!(MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE, 0x9B);
        assert_eq!(MWEB_INPUT_EXTRA_DATA_TYPE, 0x9C);
    }

    #[test]
    fn mweb_input_from_unknown_map() {
        let mut unknown = BTreeMap::new();
        unknown.insert(
            raw::Key {
                type_value: MWEB_SPENT_OUTPUT_ID_TYPE,
                key: Vec::new(),
            },
            [7u8; 32].to_vec(),
        );
        let inp = MwebInput::from_unknown_map(&unknown);
        assert_eq!(inp.output_id, Some([7u8; 32]));
    }

    #[test]
    fn assemble_minimal_mw_tx() {
        let mut commit = [0u8; 33];
        commit[0] = 2;
        let mut excess = [0u8; 33];
        excess[0] = 2;
        excess[1] = 1;

        let inp = MwebInput {
            output_id: Some([1u8; 32]),
            commit: Some(commit),
            output_pubkey: Some(test_pubkey(3)),
            signature: Some(vec![0u8; 64]),
            ..MwebInput::default()
        };
        let out = MwebOutput {
            commit: Some(commit),
            sender_pubkey: Some(test_pubkey(4)),
            output_pubkey: Some(test_pubkey(5)),
            range_proof: Some(vec![0u8; 675]),
            signature: Some(vec![0u8; 64]),
            ..MwebOutput::default()
        };
        let kernel = MwebKernel {
            excess_commit: Some(excess),
            fee: Some(1000),
            features: Some(0),
            signature: Some([0u8; 64]),
            ..MwebKernel::default()
        };

        let mw = assemble_mw_tx([2u8; 32], [3u8; 32], &[inp], &[out], &[kernel]).unwrap();
        assert_eq!(mw.kernel_offset, [2u8; 32]);
        assert_eq!(mw.stealth_offset, [3u8; 32]);
        assert_eq!(mw.body.inputs.len(), 1);
        assert_eq!(mw.body.outputs.len(), 1);
        assert_eq!(mw.body.kernels.len(), 1);
        assert_eq!(mw.body.kernels[0].fee, Some(1000));
    }
}
