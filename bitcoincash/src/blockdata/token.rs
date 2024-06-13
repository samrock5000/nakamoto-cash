//! Token
//!
//! Primitives for CashTokens.
//!

use core::ops::Index;

use crate::{TokenID, Script, consensus::{serialize, Encodable, Decodable,  deserialize_partial}, VarInt};

use super::{opcodes};

/// Used as the first byte of the "wrapped" scriptPubKey to determine whether the output has token data
pub const PREFIX_BYTE: u8 = opcodes::all::OP_SPECIAL_TOKEN_PREFIX.to_u8();
/// The NFT Commitment is a byte blob used to tag NFTs with data.
pub const MAX_CONSENSUS_COMMITMENT_LENGTH: u8 = 40;

/// High-order nibble of the token `bitfield` byte.  Describes what the structure of the token data payload that follows
/// is. These bitpatterns are bitwise-OR'd together to describe the data that follows in the token data payload.
/// This nibble may not be 0 or may not have the `Reserved` bit set.
#[repr(u8)]
pub enum Structure {
    /// The payload encodes an amount of fungible tokens.
    HasAmount = 0x10,
    /// The payload encodes a non-fungible token.
    HasNFT = 0x20,
    /// The payload encodes a commitment-length and a commitment (HasNFT must also be set).
    HasCommitmentLength = 0x40,
    /// Reserved. Must be unset.
    Reserved = 0x80,
}

/// Values for the low-order nibble of the token `bitfield` byte.  Must be `None` (0x0) for pure-fungible tokens
/// Encodes the "permissions" that an NFT has.  Note that these 3 bitpatterns are the only acceptable values for this
/// nibble.
#[repr(u8)]
pub enum Capability {
    /// No capability – either a pure-fungible or a non-fungible token which is an immutable token.
    None = 0x00,
    /// The `mutable` capability – the encoded non-fungible token is a mutable token.
    Mutable = 0x01,
    /// The `minting` capability – the encoded non-fungible token is a minting token.
    Minting = 0x02,
}

/// Data that gets serialized/deserialized to/from a scriptPubKey in a transaction output prefixed with PREFIX_BYTE
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct OutputData {
    /// Token ID
    pub id: TokenID,
    /// Token bitfield byte. High order nibble is one of the Structure enum values and low order nibble is Capability.
    pub bitfield: u8,
    // TODO: Implement SafeAmount as in reference implementation
    /// Token amount
    pub amount: i64,
    /// NFT commitment
    pub commitment: Vec<u8>
}

impl OutputData {
    /// The payload encodes a commitment-length and a commitment (HasNFT must also be set).
    pub fn has_commitment_length(&self) -> bool {
        (self.bitfield & Structure::HasCommitmentLength as u8) != 0
    }

    /// The payload encodes an amount of fungible tokens.
    pub fn has_amount(&self) -> bool {
        (self.bitfield & Structure::HasAmount as u8) != 0
    }

    /// Get capability bitmask
    pub fn capability(&self) -> u8 {
        self.bitfield & 0x0f
    }

    /// If utxo has NFT
    pub fn has_nft(&self) -> bool {
        (self.bitfield & Structure::HasNFT as u8) != 0
    }

    /// If utxo has minting capable NFT
    pub fn is_minting_nft(&self) -> bool {
        return self.has_nft() && ((self.capability() & Capability::Minting as u8) != 0)
    }
}

impl Encodable for OutputData {
    fn consensus_encode<W: std::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.id.consensus_encode(writer)?;
        len += self.bitfield.consensus_encode(writer)?;
        if self.has_commitment_length() {
            len += self.commitment.consensus_encode(writer)?;
        }
        if self.has_amount() {
            len += VarInt(self.amount as u64).consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for OutputData {
    fn consensus_decode<R: std::io::Read + ?Sized>(reader: &mut R) -> Result<Self, crate::consensus::encode::Error> {
        let id = TokenID::consensus_decode(reader)?;
        let bitfield = u8::consensus_decode(reader)?;

        let commitment = if (bitfield & Structure::HasCommitmentLength as u8) != 0 {
            Vec::<u8>::consensus_decode(reader)?
        } else {
            vec![]
        };
        let amount = if (bitfield & Structure::HasAmount as u8) != 0 {
            VarInt::consensus_decode(reader)?
        }
        else {
            VarInt(0)
        };
        Ok(OutputData {
            id,
            bitfield,
            amount: amount.0 as i64,
            commitment,
        })
    }
}

/// Given a real scriptPubKey and token data, wrap the scriptPubKey into the "script + token data" blob
/// (which gets serialized to where the old txn format scriptPubKey used to live)
pub fn wrap_scriptpubkey(scriptpubkey: Script, token_data: &Option<OutputData>) -> Script {
    match token_data {
        Some(data) => {
            let bytes: Vec<u8> = std::iter::once(opcodes::all::OP_SPECIAL_TOKEN_PREFIX.to_u8())
                .chain(serialize(data))
                .chain(scriptpubkey.into_bytes()).collect();
            Script::from(bytes)
        }
        None => scriptpubkey
    }
}

/// Given a real scriptPubKey and token data, wrap the scriptPubKey into the "script + token data" blob
/// (which gets serialized to where the old txn format scriptPubKey used to live).
pub fn unwrap_scriptpubkey(scriptpubkey: Script) -> Result<(Script, Option<OutputData>), crate::blockdata::script::Error> {
    if scriptpubkey.is_empty() || scriptpubkey.index(0) != &opcodes::all::OP_SPECIAL_TOKEN_PREFIX.to_u8() {
        return Ok((scriptpubkey, None))
    }
    let scriptpubkey = scriptpubkey.into_bytes();

    let (output_data, consumed) = match deserialize_partial::<OutputData>(&scriptpubkey[1..]) {
        Ok((o, size)) => (o, size),
        Err(e) => {
            println!("{:?}", e);
            return Err(crate::blockdata::script::Error::Other("Failed to parse token output from script."))
        }
    };

    // Eat prefix + token data
    let remaining: Vec<u8> = scriptpubkey[1 + consumed ..].to_vec();
    Ok((Script::from(remaining), Some(output_data)))
}

#[cfg(test)]
mod test {
    use bitcoin_hashes::hex::{FromHex, ToHex};
    use super::*;

    // Test vectors from https://github.com/bitjson/cashtokens/blob/master/test-vectors/token-prefix-valid.json

    #[test]
    fn test_vectors() {
        let prefix = "efaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1001".to_string();
        let other_payload = "f00d".to_string();

        let script = Script::from_hex(&(prefix + &other_payload)).unwrap();
        let (unwrapped_script, token_data) = unwrap_scriptpubkey(script).unwrap();
        let token_data = token_data.unwrap();

        assert_eq!(other_payload, unwrapped_script.to_hex());
        assert_eq!(1, token_data.amount);
        assert_eq!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", token_data.id.to_hex());

        let prefix = "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7229ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccffffffffffffffff7f".to_string();
        let script = Script::from_hex(&(prefix + &other_payload)).unwrap();
        let (unwrapped_script, token_data) = unwrap_scriptpubkey(script).unwrap();
        let token_data = token_data.unwrap();
        assert_eq!(other_payload, unwrapped_script.to_hex());
        assert_eq!(9223372036854775807, token_data.amount);
        assert_eq!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", token_data.id.to_hex());
        assert_eq!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", token_data.commitment.to_hex());
        assert!(token_data.is_minting_nft());


    }
}