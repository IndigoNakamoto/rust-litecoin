// MimbleWimble transaction
#![allow(missing_docs)]
use crate::prelude::*;
use crate::io;

use consensus::{encode, Decodable, Encodable};
use secp256k1::PublicKey;
use Script;
use VarInt;

pub enum KernelFeatures {
    FeeFeatureBit = 0x01,
    PeginFeatureBit = 0x02,
    PegoutFeatureBit = 0x04,
    HeightLockFeatureBit = 0x08,
    StealthExcessFeatureBit = 0x10,
    ExtraDataFeatureBit = 0x20
}

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    pub extra_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub range_proof: [u8; 675],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    pub features: u8,
    pub output_id: [u8; 32],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub input_public_key: Option<PublicKey>,
    pub output_public_key: PublicKey,
    pub extra_data: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PegOutCoin {
    pub amount: i64,
    pub script_pub_key: Script
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Kernel {
    pub features: u8,
    pub fee: Option<i64>,
    pub pegin: Option<i64>,
    pub pegouts: Vec<PegOutCoin>,
    pub lock_height: Option<i32>,
    pub stealth_excess: Option<PublicKey>,
    pub extra_data: Vec<u8>,
    // Remainder of the sum of all transaction commitments. 
    // If the transaction is well formed, amounts components should sum to zero and the excess is hence a valid public key.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub excess: [u8; 33],
    // The signature proving the excess is a valid public key, which signs the transaction fee.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxBody {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub kernels: Vec<Kernel>
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    pub kernel_offset: [u8; 32],
    pub stealth_offset: [u8; 32],
    pub body: TxBody
}

fn read_amount<D: io::Read>(stream: &mut D) -> Result<i64, encode::Error> {
    let mut n: i64 = 0;
    loop {
        let ch_data = u8::consensus_decode(&mut *stream)?;
        let a = n << 7;
        let b = (ch_data & 0x7F) as i64;
        n = a | b;
        if (ch_data & 0x80) != 0 {
            n += 1;
        }
        else {
            break;
        }
    }
    Ok(n)
}

fn write_amount<W: io::Write>(amount: i64, mut writer: W) -> Result<usize, io::Error> {
    let mut n = amount;
    const SIZE: usize = 10;
    let mut tmp = [0u8; SIZE];
    let mut len = 0;
    loop {
        let a = (n & 0x7F) as u8;
        let b = (if len != 0 { 0x80 } else { 0x00 }) as u8;
        tmp[len] = a | b;
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    len += 1; // Include the final byte
    for i in (0..len).rev() {
        u8::consensus_encode(&tmp[i], &mut writer)?;
    }
    Ok(len)
}

fn read_array_len<D: io::Read>(mut stream: D) -> Result<u64, encode::Error> {
    return Ok(VarInt::consensus_decode(&mut stream)?.0);
}

impl Decodable for PegOutCoin {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let amount = read_amount(&mut d)?;
        let script_pub_key = Script::consensus_decode(&mut d)?;
        Ok(PegOutCoin { amount, script_pub_key })
    }
}

impl Encodable for PegOutCoin {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += write_amount(self.amount, &mut writer)?;
        len += &self.script_pub_key.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Kernel {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let fee =
            if features & (KernelFeatures::FeeFeatureBit as u8) != 0 {
                Some(read_amount(&mut d)?)
            }
            else {
                None
            };
        let pegin =
            if features & (KernelFeatures::PeginFeatureBit as u8) != 0 {
                Some(read_amount(&mut d)?)
            }
            else {
                None
            };
        let mut pegouts = Vec::<PegOutCoin>::new();
        if features & (KernelFeatures::PegoutFeatureBit as u8) != 0 {
            let len = read_array_len(&mut d)?;
            for _ in 0 .. len {
                pegouts.push(PegOutCoin::consensus_decode(&mut d)?);
            }
        }
        let lock_height =
            if features & (KernelFeatures::HeightLockFeatureBit as u8) != 0 {
                Some(read_amount(&mut d)? as i32)
            }
            else {
                None
            };
        let stealth_excess =
            if features & (KernelFeatures::StealthExcessFeatureBit as u8) != 0 {
                let pubkey_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
                Some(PublicKey::from_slice(&pubkey_bytes).map_err(|_| encode::Error::ParseFailed("Invalid stealth excess public key"))?)
            }
            else {
                None
            };
        let mut extra_data = Vec::<u8>::new();
        if features & (KernelFeatures::ExtraDataFeatureBit as u8) != 0 {
            extra_data = Vec::<u8>::consensus_decode(&mut d)?;
        }
        let excess: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        Ok(
            Kernel { 
                features, 
                fee, 
                pegin, 
                pegouts, 
                lock_height, 
                stealth_excess, 
                extra_data,
                excess,
                signature
            }
        )
    }
}

impl Encodable for Kernel {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        if self.features & (KernelFeatures::FeeFeatureBit as u8) != 0 {
            len += write_amount(self.fee.unwrap(), &mut writer)?;
        }
        if self.features & (KernelFeatures::PeginFeatureBit as u8) != 0 {
            len += write_amount(self.pegin.unwrap(), &mut writer)?;
        }
        if self.features & (KernelFeatures::PegoutFeatureBit as u8) != 0 {
            len += VarInt(self.pegouts.len() as u64).consensus_encode(&mut writer)?;
            for pegout in &self.pegouts {
                len += pegout.consensus_encode(&mut writer)?;
            }
        }
        if self.features & (KernelFeatures::HeightLockFeatureBit as u8) != 0 {
            len += write_amount(self.lock_height.unwrap() as i64, &mut writer)?;
        }
        if self.features & (KernelFeatures::StealthExcessFeatureBit as u8) != 0 {
            len += self.stealth_excess.unwrap().serialize().consensus_encode(&mut writer)?;
        }
        if self.features & (KernelFeatures::ExtraDataFeatureBit as u8) != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        len += self.excess.consensus_encode(&mut writer)?;
        len += self.signature.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Vec<Kernel> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Kernel> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for kernel in self {
            len += kernel.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Vec<Input> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Input> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for input in self {
            len += input.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Input {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let output_id: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let commitment: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let output_public_key_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let output_public_key = PublicKey::from_slice(&output_public_key_bytes).map_err(|_| encode::Error::ParseFailed("Invalid output public key"))?;
        let input_public_key =
            if features & 1 != 0 {
                let input_public_key_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
                Some(PublicKey::from_slice(&input_public_key_bytes).map_err(|_| encode::Error::ParseFailed("Invalid input public key"))?)
            }
            else {
                None
            };
        let mut extra_data = Vec::<u8>::new();
        if features & 2 != 0 {
            // extra data
            extra_data = Vec::<u8>::consensus_decode(&mut d)?;
        }
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        return Ok(
            Input { 
                features, 
                output_id, 
                commitment, 
                input_public_key, 
                output_public_key, 
                extra_data,
                signature
            }
        );
    }
}

impl Encodable for Input {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        len += self.output_id.consensus_encode(&mut writer)?;
        len += self.commitment.consensus_encode(&mut writer)?;
        len += self.output_public_key.serialize().consensus_encode(&mut writer)?;
        if self.features & 1 != 0 {
            len += self.input_public_key.unwrap().serialize().consensus_encode(&mut writer)?;
        }
        if self.features & 2 != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        len += self.signature.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Vec<Output> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Output> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for output in self {
            len += output.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let kernel_offset: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let stealth_offset: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let body= TxBody::consensus_decode(d)?;
        return Ok(Transaction{ kernel_offset, stealth_offset, body });
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.kernel_offset.consensus_encode(&mut writer)?;
        len += self.stealth_offset.consensus_encode(&mut writer)?;
        len += self.body.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let inputs = Vec::<Input>::consensus_decode(&mut d)?;
        let outputs = Vec::<Output>::consensus_decode(&mut d)?;
        let kernels = Vec::<Kernel>::consensus_decode(&mut d)?;
        return Ok(TxBody{ inputs, outputs, kernels });
    }
}

impl Encodable for TxBody {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.inputs.consensus_encode(&mut writer)?;
        len += self.outputs.consensus_encode(&mut writer)?;
        len += self.kernels.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Encodable for Output {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.commitment.consensus_encode(&mut writer)?;
        len += self.sender_public_key.serialize().consensus_encode(&mut writer)?;
        len += self.receiver_public_key.serialize().consensus_encode(&mut writer)?;
        len += self.message.consensus_encode(&mut writer)?;
        len += self.range_proof.consensus_encode(&mut writer)?;
        len += self.signature.consensus_encode(&mut writer)?;
        return Ok(len);
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let commitment = Decodable::consensus_decode(&mut d)?;
        let sender_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let sender_public_key = PublicKey::from_slice(&sender_pubkey_bytes).map_err(|_| encode::Error::ParseFailed("Invalid sender public key"))?;
        let receiver_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let receiver_public_key = PublicKey::from_slice(&receiver_pubkey_bytes).map_err(|_| encode::Error::ParseFailed("Invalid receiver public key"))?;
        let message = OutputMessage::consensus_decode(&mut d)?;
        let range_proof : [u8;  675] = Decodable::consensus_decode(&mut d)?;
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        return Ok(
            Output { 
                commitment, 
                sender_public_key, 
                receiver_public_key, 
                message, 
                range_proof,
                signature 
            }
        );
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let standard_fields =
            if features & (OutputFeatures::StandardFieldsFeatureBit as u8) != 0 {
                let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
                let key_exchange_pubkey = PublicKey::from_slice(&pubkey_bytes).map_err(|_| encode::Error::ParseFailed("Invalid key exchange public key"))?;
                let view_tag = u8::consensus_decode(&mut d)?;
                let masked_value = u64::consensus_decode(&mut d)?;
                let masked_nonce: [u8; 16] = Decodable::consensus_decode(&mut d)?;
                Some(
                    OutputMessageStandardFields{
                        key_exchange_pubkey,
                        view_tag,
                        masked_value,
                        masked_nonce})
            } else {
                None
            };
        let extra_data: Vec<u8> =
            if features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
                Decodable::consensus_decode(&mut d)?
            }
            else {
                vec! []
            };
        return Ok(OutputMessage{features, standard_fields, extra_data});
    }
}

impl Encodable for OutputMessage {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        match self.standard_fields {
            Some(ref fields) => {
                len += fields.key_exchange_pubkey.serialize().consensus_encode(&mut writer)?;
                len += fields.view_tag.consensus_encode(&mut writer)?;
                len += fields.masked_value.consensus_encode(&mut writer)?;
                len += fields.masked_nonce.consensus_encode(&mut writer)?;
            }
            None => {}
        }
        if self.features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Encodable, Decodable};
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    use std::io::Cursor;

    #[test]
    fn test_amount_encoding_decoding() {
        let amounts = vec![0i64, 1, 127, 128, 255, 256, 1000, 1000000, i64::MAX];
        
        for amount in amounts {
            let mut encoded = Vec::new();
            let encoded_len = write_amount(amount, &mut encoded).unwrap();
            
            let mut cursor = Cursor::new(&encoded);
            let decoded = read_amount(&mut cursor).unwrap();
            
            assert_eq!(amount, decoded, "Amount encoding/decoding failed for {}", amount);
            assert_eq!(encoded_len, encoded.len(), "Encoded length mismatch for {}", amount);
        }
    }

    #[test]
    fn test_pegout_coin_roundtrip() {
        use crate::Script;
        
        // Test with empty script
        let coin_empty = PegOutCoin {
            amount: 50000000,
            script_pub_key: Script::new()
        };
        
        let mut encoded = Vec::new();
        coin_empty.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = PegOutCoin::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(coin_empty, decoded);
        
        // Test with P2PKH script (more realistic)
        let script_bytes = vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <20 bytes>
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x88, 0xac  // OP_EQUALVERIFY OP_CHECKSIG
        ];
        let coin_p2pkh = PegOutCoin {
            amount: 100000000, // 1 LTC
            script_pub_key: Script::from(script_bytes)
        };
        
        let mut encoded = Vec::new();
        coin_p2pkh.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = PegOutCoin::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(coin_p2pkh, decoded);
    }

    #[test]
    fn test_kernel_with_features_roundtrip() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // Test kernel with all features enabled
        let kernel = Kernel {
            features: (KernelFeatures::FeeFeatureBit as u8) | 
                     (KernelFeatures::PeginFeatureBit as u8) |
                     (KernelFeatures::PegoutFeatureBit as u8) |
                     (KernelFeatures::HeightLockFeatureBit as u8) |
                     (KernelFeatures::StealthExcessFeatureBit as u8) |
                     (KernelFeatures::ExtraDataFeatureBit as u8),
            fee: Some(1000),
            pegin: Some(50000000),
            pegouts: vec![PegOutCoin {
                amount: 25000000,
                script_pub_key: Script::new()
            }],
            lock_height: Some(100000),
            stealth_excess: Some(public_key),
            extra_data: vec![1, 2, 3, 4],
            excess: [0u8; 33],
            signature: [0u8; 64]
        };
        
        let mut encoded = Vec::new();
        kernel.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = Kernel::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(kernel, decoded);
    }

    #[test]
    fn test_kernel_minimal_features() {
        // Test kernel with only fee feature
        let kernel = Kernel {
            features: KernelFeatures::FeeFeatureBit as u8,
            fee: Some(1000),
            pegin: None,
            pegouts: vec![],
            lock_height: None,
            stealth_excess: None,
            extra_data: vec![],
            excess: [1u8; 33],
            signature: [2u8; 64]
        };
        
        let mut encoded = Vec::new();
        kernel.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = Kernel::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(kernel, decoded);
    }

    #[test]
    fn test_kernel_height_lock_encoding() {
        // Specifically test the height lock fix
        let kernel = Kernel {
            features: KernelFeatures::HeightLockFeatureBit as u8,
            fee: None,
            pegin: None,
            pegouts: vec![],
            lock_height: Some(500000), // A typical block height
            stealth_excess: None,
            extra_data: vec![],
            excess: [0u8; 33],
            signature: [0u8; 64]
        };
        
        let mut encoded = Vec::new();
        kernel.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = Kernel::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(kernel.lock_height, decoded.lock_height);
        assert_eq!(kernel, decoded);
    }

    #[test]
    fn test_kernel_pegin_encoding() {
        // Specifically test the pegin encoding fix
        let kernel = Kernel {
            features: KernelFeatures::PeginFeatureBit as u8,
            fee: None,
            pegin: Some(100000000), // 1 LTC in satoshis
            pegouts: vec![],
            lock_height: None,
            stealth_excess: None,
            extra_data: vec![],
            excess: [0u8; 33],
            signature: [0u8; 64]
        };
        
        let mut encoded = Vec::new();
        kernel.consensus_encode(&mut encoded).unwrap();
        
        let mut cursor = Cursor::new(&encoded);
        let decoded = Kernel::consensus_decode(&mut cursor).unwrap();
        
        assert_eq!(kernel.pegin, decoded.pegin);
        assert_eq!(kernel, decoded);
    }

    #[test]
    fn test_large_amounts() {
        // Test encoding/decoding of large amounts that might have caused the original crash
        let large_amounts = vec![
            2100000000000000i64, // Max LTC supply in satoshis
            i64::MAX / 2,
            1000000000000i64,
        ];
        
        for amount in large_amounts {
            let mut encoded = Vec::new();
            write_amount(amount, &mut encoded).unwrap();
            
            let mut cursor = Cursor::new(&encoded);
            let decoded = read_amount(&mut cursor).unwrap();
            
            assert_eq!(amount, decoded, "Large amount encoding failed for {}", amount);
        }
    }

    #[test]
    fn test_amount_edge_cases() {
        // Test specific amounts that were found in problematic real-world blocks
        let edge_case_amounts = vec![
            0x47434419i64,  // 1195656217 - from real block transaction
            0x7004fd42i64,  // 1879391554 - from real block transaction  
            0x7Fi64,        // Boundary: largest 7-bit value
            0x80i64,        // Boundary: smallest 2-byte encoded value
            0x3FFFi64,      // Boundary: largest 14-bit value
            0x4000i64,      // Boundary: smallest 3-byte encoded value
        ];
        
        for amount in edge_case_amounts {
            let mut encoded = Vec::new();
            write_amount(amount, &mut encoded).unwrap();
            
            let mut cursor = Cursor::new(&encoded);
            let decoded = read_amount(&mut cursor).unwrap();
            
            assert_eq!(amount, decoded, "Edge case amount encoding failed for {}", amount);
        }
    }

    #[test]
    fn test_invalid_stealth_excess_handling() {
        // Test that we properly handle invalid stealth excess public keys
        let invalid_pubkey_bytes = [0u8; 33]; // All zeros - invalid public key
        
        let kernel = Kernel {
            features: KernelFeatures::StealthExcessFeatureBit as u8,
            fee: None,
            pegin: None,
            pegouts: vec![],
            lock_height: None,
            stealth_excess: None, // We'll test that invalid data fails gracefully
            extra_data: vec![],
            excess: [0u8; 33],
            signature: [0u8; 64]
        };
        
        // Create encoded data with invalid stealth excess
        let mut encoded = Vec::new();
        kernel.features.consensus_encode(&mut encoded).unwrap();
        invalid_pubkey_bytes.consensus_encode(&mut encoded).unwrap();
        kernel.excess.consensus_encode(&mut encoded).unwrap();
        kernel.signature.consensus_encode(&mut encoded).unwrap();
        
        // Try to decode - should fail gracefully with ParseFailed error
        let mut cursor = Cursor::new(&encoded);
        let result = Kernel::consensus_decode(&mut cursor);
        
        match result {
            Err(encode::Error::ParseFailed(msg)) => {
                assert_eq!(msg, "Invalid stealth excess public key");
            }
            _ => panic!("Expected ParseFailed error for invalid stealth excess public key")
        }
    }

    #[test]
    fn test_corrupted_pubkey_data() {
        // Test various corrupted public key scenarios
        let corrupted_keys = vec![
            [0xFFu8; 33],  // All 0xFF
            [0x01u8; 33],  // All 0x01
            {
                let mut key = [0u8; 33];
                key[0] = 0x04; // Invalid compression flag
                key
            },
        ];
        
        for (i, invalid_pubkey) in corrupted_keys.iter().enumerate() {
            let mut encoded = Vec::new();
            (KernelFeatures::StealthExcessFeatureBit as u8).consensus_encode(&mut encoded).unwrap();
            invalid_pubkey.consensus_encode(&mut encoded).unwrap();
            [0u8; 33].consensus_encode(&mut encoded).unwrap(); // excess
            [0u8; 64].consensus_encode(&mut encoded).unwrap(); // signature
            
            let mut cursor = Cursor::new(&encoded);
            let result = Kernel::consensus_decode(&mut cursor);
            
            assert!(result.is_err(), "Expected error for corrupted key #{}", i);
            if let Err(encode::Error::ParseFailed(msg)) = result {
                assert_eq!(msg, "Invalid stealth excess public key");
            }
        }
    }

    #[test]
    fn test_input_output_pubkey_validation() {
        // Test Input with invalid output public key
        let invalid_key = [0u8; 33];
        let mut encoded = Vec::new();
        0u8.consensus_encode(&mut encoded).unwrap(); // features
        [0u8; 32].consensus_encode(&mut encoded).unwrap(); // output_id
        [0u8; 33].consensus_encode(&mut encoded).unwrap(); // commitment
        invalid_key.consensus_encode(&mut encoded).unwrap(); // invalid output public key
        [0u8; 64].consensus_encode(&mut encoded).unwrap(); // signature

        let mut cursor = Cursor::new(&encoded);
        let result = Input::consensus_decode(&mut cursor);
        assert!(result.is_err(), "Expected error for invalid output public key in Input");
        
        // Test Output with invalid sender public key
        let mut encoded = Vec::new();
        [0u8; 33].consensus_encode(&mut encoded).unwrap(); // commitment
        invalid_key.consensus_encode(&mut encoded).unwrap(); // invalid sender public key
        
        let mut cursor = Cursor::new(&encoded);
        // This will fail at sender key parsing, which is what we want
        let result = Output::consensus_decode(&mut cursor);
        assert!(result.is_err(), "Expected error for invalid sender public key in Output");
    }
}
