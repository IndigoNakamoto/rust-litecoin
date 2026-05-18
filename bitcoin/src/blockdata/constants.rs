// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use hashes::{sha256d, Hash};
use internals::impl_array_newtype;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::consensus::Params;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::Network;
use crate::pow::CompactTarget;
use crate::Amount;

/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 150;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 150 * 2016;

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = units::weight::WITNESS_SCALE_FACTOR;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (litecoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 48; // 0x30
/// Mainnet (litecoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 50; // 0x32
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 58; // 0x3a
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 840_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

// This is the 65 byte (uncompressed) pubkey used as the one-and-only output of the Litecoin genesis transaction.
//
// ref: https://litecoinspace.org/tx/97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9
// Note output script includes a leading 0x41 and trailing 0xac (added below using the `script::Builder`).
#[rustfmt::skip]
const GENESIS_OUTPUT_PK: [u8; 65] = [
    0x04,
    0x01, 0x84, 0x71, 0x0f, 0xa6, 0x89, 0xad, 0x50,
    0x23, 0x69, 0x0c, 0x80, 0xf3, 0xa4, 0x9c, 0x8f,
    0x13, 0xf8, 0xd4, 0x5b, 0x8c, 0x85, 0x7f, 0xbc,
    0xbc, 0x8b, 0xc4, 0xa8, 0xe4, 0xd3, 0xeb, 0x4b,
    0x10, 0xf4, 0xd4, 0x60, 0x4f, 0xa0, 0x8d, 0xce,
    0x60, 0x1a, 0xaf, 0x0f, 0x47, 0x02, 0x16, 0xfe,
    0x1b, 0x51, 0x85, 0x0b, 0x4a, 0xcf, 0x21, 0xb1,
    0x79, 0xc4, 0x50, 0x70, 0xac, 0x7b, 0x03, 0xa9
];

/// Constructs and returns the coinbase (and only) transaction of the Litecoin genesis block.
fn bitcoin_genesis_tx(_params: &Params) -> Transaction {
    // Base — Litecoin uses the same coinbase tx on every network.
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
        mw_tx: None,
        is_hog_ex: false,
    };

    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"NY Times 05/Oct/2011 Steve Jobs, Apple\xe2\x80\x99s Visionary, Dies at 56")
        .into_script();
    let out_script = script::Builder::new()
        .push_slice(GENESIS_OUTPUT_PK)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });
    ret.output.push(TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(params: impl AsRef<Params>) -> Block {
    let params = params.as_ref();
    let txdata = vec![bitcoin_genesis_tx(params)];
    let hash: sha256d::Hash = txdata[0].compute_txid().into();
    let merkle_root: crate::TxMerkleNode = hash.into();

    match params.network {
        Network::Bitcoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1317972665,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 2084524493,
            },
            txdata,
            mweb_block: None,
        },
        // Litecoin testnet4 (the only LTC testnet).
        Network::Testnet4 => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1486949366,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 293345,
            },
            txdata,
            mweb_block: None,
        },
        // Signet is kept for upstream compatibility but Litecoin doesn't use it.
        Network::Signet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1598918400,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 52613770,
            },
            txdata,
            mweb_block: None,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
            mweb_block: None,
        },
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Litecoin mainnet genesis block hash:
    //   12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2 (display order)
    // Serialized (little-endian) per BOLT 0:
    /// `ChainHash` for mainnet litecoin.
    pub const BITCOIN: Self = Self([
        0xe2, 0xbf, 0x04, 0x7e, 0x7e, 0x5a, 0x19, 0x1a,
        0xa4, 0xef, 0x34, 0xd3, 0x14, 0x97, 0x9d, 0xc9,
        0x98, 0x6e, 0x0f, 0x19, 0x25, 0x1e, 0xda, 0xba,
        0x59, 0x40, 0xfd, 0x1f, 0xe3, 0x65, 0xa7, 0x12,
    ]);
    /// `ChainHash` for Litecoin testnet4 (the only LTC testnet).
    /// Genesis hash: 4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0 (display order)
    pub const TESTNET4: Self = Self([
        0xa0, 0x29, 0x3e, 0x4e, 0xeb, 0x3d, 0xa6, 0xe6,
        0xf5, 0x6f, 0x81, 0xed, 0x59, 0x5f, 0x57, 0x88,
        0x0d, 0x1a, 0x21, 0x56, 0x9e, 0x13, 0xee, 0xfd,
        0xd9, 0x51, 0x28, 0x4b, 0x5a, 0x62, 0x66, 0x49,
    ]);
    /// `ChainHash` for signet (kept for upstream compat; not used by Litecoin).
    pub const SIGNET: Self = Self([
        246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249,
        240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0,
    ]);
    /// `ChainHash` for Litecoin regtest.
    pub const REGTEST: Self = Self([
        0xf9, 0x16, 0xc4, 0x56, 0xfc, 0x51, 0xdf, 0x62,
        0x78, 0x85, 0xd7, 0xd6, 0x74, 0xed, 0x02, 0xdc,
        0x88, 0xa2, 0x25, 0xad, 0xb3, 0xf0, 0x2a, 0xd1,
        0x3e, 0xb4, 0x93, 0x8f, 0xf3, 0x27, 0x08, 0x53,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub fn using_genesis_block(params: impl AsRef<Params>) -> Self {
        match params.as_ref().network {
            Network::Bitcoin => Self::BITCOIN,
            Network::Testnet4 => Self::TESTNET4,
            Network::Signet => Self::SIGNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block_const(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::BITCOIN,
            Network::Testnet4 => Self::TESTNET4,
            Network::Signet => Self::SIGNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::encode::serialize;
    use crate::consensus::params;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx(&Params::MAINNET);

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("4341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac"));
        assert_eq!(gen.output[0].value, Amount::from_str("50 BTC").unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.compute_wtxid().to_string(),
            "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"
        );
    }

    #[test]
    fn bitcoin_genesis_block_calling_convention() {
        // This is the best.
        let _ = genesis_block(&params::MAINNET);
        // this works and is ok too.
        let _ = genesis_block(&Network::Bitcoin);
        let _ = genesis_block(Network::Bitcoin);
        // This works too, but is suboptimal because it inlines the const.
        let _ = genesis_block(Params::MAINNET);
        let _ = genesis_block(&Params::MAINNET);
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(&params::MAINNET);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"
        );

        assert_eq!(gen.header.time, 1317972665);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 2084524493);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
        );
    }

    #[test]
    fn testnet4_genesis_full_block() {
        let gen = genesis_block(&params::TESTNET4);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"
        );
        assert_eq!(gen.header.time, 1486949366);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 293345);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0"
        );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block_const(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Bitcoin => {},
            Network::Testnet4 => {},
            Network::Signet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Bitcoin;
        testnet4_chain_hash_genesis_block, Network::Testnet4;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Litecoin mainnet ChainHash (storage-order hex).
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block_const(Network::Bitcoin).to_string();
        let want = "e2bf047e7e5a191aa4ef34d314979dc9986e0f19251edaba5940fd1fe365a712";
        assert_eq!(got, want);
    }
}
