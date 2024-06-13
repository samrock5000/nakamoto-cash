//! Bitcoin cash address.
/// cash addr errors
pub mod error;
// use anyhow::Result;
pub use error::{DecodingError, EncodingError};

use crate::Network;

// Prefixes
const MAINNET_PREFIX: &str = "bitcoincash";
const TESTNET_PREFIX: &str = "bchtest";
const REGNET_PREFIX: &str = "bchreg";

// The cashaddr character set for encoding
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// The cashaddr character set for decoding
#[rustfmt::skip]
const CHARSET_REV: [Option<u8>; 128] = [
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    Some(15), None,     Some(10), Some(17), Some(21), Some(20), Some(26), Some(30),
    Some(7),  Some(5),  None,     None,     None,     None,     None,     None,
    None,     Some(29), None,     Some(24), Some(13), Some(25), Some(9),  Some(8),
    Some(23), None,     Some(18), Some(22), Some(31), Some(27), Some(19), None,
    Some(1),  Some(0),  Some(3),  Some(16), Some(11), Some(28), Some(12), Some(14),
    Some(6),  Some(4),  Some(2),  None,     None,     None,     None,     None,
    None,     Some(29),  None,    Some(24), Some(13), Some(25), Some(9),  Some(8),
    Some(23), None,     Some(18), Some(22), Some(31), Some(27), Some(19), None,
    Some(1),  Some(0),  Some(3),  Some(16), Some(11), Some(28), Some(12), Some(14),
    Some(6),  Some(4),  Some(2),  None,     None,     None,     None,     None,
];

// Version byte flags
#[allow(dead_code)]
/// todo
pub mod version_byte_flags {
    /// todo
    pub const TYPE_MASK: u8 = 0b1111000;
    /// todo
    pub const SIZE_MASK: u8 = 0b0000111;
    /// todo
    pub const TYPE_P2PKH: u8 = 0b00000;
    /// todo
    pub const TYPE_P2SH: u8 = 0b01000;
    /// todo
    pub const TYPE_P2PKH_TOKEN: u8 = 0b10000;
    /// todo
    pub const TYPE_P2SH_TOKEN: u8 = 0b11000;
    /// todo
    pub const SIZE_160: u8 = 0x00;
    /// todo
    pub const SIZE_192: u8 = 0x01;
    /// todo
    pub const SIZE_224: u8 = 0x02;
    /// todo
    pub const SIZE_256: u8 = 0x03;
    /// todo
    pub const SIZE_320: u8 = 0x04;
    /// todo
    pub const SIZE_384: u8 = 0x05;
    /// todo
    pub const SIZE_448: u8 = 0x06;
    /// todo
    pub const SIZE_512: u8 = 0x07;
}

// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/2804a49bfc0764ba02ce2999809c52b3b9bb501e/src/cashaddr.cpp#L42
fn polymod(v: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for d in v.iter() {
        let c0: u8 = (c >> 35) as u8;
        c = ((c & 0x0007_ffff_ffff) << 5) ^ u64::from(*d);
        if c0 & 0x01 != 0 {
            c ^= 0x0098_f2bc_8e61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x0079_b76d_99e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0x00f3_3e5f_b3c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0x00ae_2eab_e2a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x001e_4f43_e470;
        }
    }
    c ^ 1
}

// Expand the address prefix for the checksum operation.
fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = prefix.chars().map(|c| (c as u8) & 0x1f).collect();
    ret.push(0);
    ret
}

fn convert_bits(data: &[u8], inbits: u8, outbits: u8, pad: bool) -> Vec<u8> {
    assert!(inbits <= 8 && outbits <= 8);
    let num_bytes = (data.len() * inbits as usize + outbits as usize - 1) / outbits as usize;
    let mut ret = Vec::with_capacity(num_bytes);
    let mut acc: u16 = 0; // accumulator of bits
    let mut num: u8 = 0; // num bits in acc
    let groupmask = (1 << outbits) - 1;
    for d in data.iter() {
        // We push each input chunk into a 16-bit accumulator
        acc = (acc << inbits) | u16::from(*d);
        num += inbits;
        // Then we extract all the output groups we can
        while num > outbits {
            ret.push((acc >> (num - outbits)) as u8);
            acc &= !(groupmask << (num - outbits));
            num -= outbits;
        }
    }
    if pad {
        // If there's some bits left, pad and add it
        if num > 0 {
            ret.push((acc << (outbits - num)) as u8);
        }
    } else {
        // If there's some bits left, figure out if we need to remove padding and add it
        let padding = (data.len() * inbits as usize) % outbits as usize;
        if num as usize > padding {
            ret.push((acc >> padding) as u8);
        }
    }
    ret
}
/// todo
pub fn encode(
    raw: &[u8],
    hash_flag: u8, // see version_byte_flags
    network: Network,
) -> Result<String, EncodingError> {
    // Calculate version byte
    let length = raw.len();
    let version_byte = match length {
        20 => version_byte_flags::SIZE_160,
        24 => version_byte_flags::SIZE_192,
        28 => version_byte_flags::SIZE_224,
        32 => version_byte_flags::SIZE_256,
        40 => version_byte_flags::SIZE_320,
        48 => version_byte_flags::SIZE_384,
        56 => version_byte_flags::SIZE_448,
        64 => version_byte_flags::SIZE_512,
        _ => return Err(EncodingError(length)),
    } | hash_flag;

    // Get prefix
    let prefix = match network {
        Network::Bitcoin => MAINNET_PREFIX,
        Network::Testnet => TESTNET_PREFIX,
        Network::Testnet4 => TESTNET_PREFIX,
        Network::Scalenet => TESTNET_PREFIX,
        Network::Regtest => REGNET_PREFIX,
        Network::Chipnet => TESTNET_PREFIX,
    };

    // Convert payload to 5 bit array
    let mut payload = Vec::with_capacity(1 + raw.len());
    payload.push(version_byte);
    payload.extend(raw);
    let payload_5_bits = convert_bits(&payload, 8, 5, true);

    // Construct payload string using CHARSET
    let payload_str: String = payload_5_bits.iter().map(|b| CHARSET[*b as usize] as char).collect();

    // Create checksum
    let expanded_prefix = expand_prefix(prefix);
    let checksum_input = [&expanded_prefix[..], &payload_5_bits, &[0; 8][..]].concat();
    let checksum = polymod(&checksum_input);

    // Convert checksum to string
    let checksum_str: String =
        (0..8).rev().map(|i| CHARSET[((checksum >> (i * 5)) & 31) as usize] as char).collect();

    // Concatentate all parts
    let cashaddr = [prefix, ":", &payload_str, &checksum_str].concat();
    Ok(cashaddr)
}
/// todo
pub fn decode(addr_str: &str) -> Result<(Vec<u8>, u8, Network), DecodingError> {
    // Delimit and extract prefix
    let parts: Vec<&str> = addr_str.split(':').collect();
    let (prefix, payload_str) = match parts.len() {
        1 => (MAINNET_PREFIX, parts[0]),
        2 => (parts[0], parts[1]),
        _ => return Err(DecodingError::Other(format!("Invalid address: '{}'", addr_str))),
    };

    // Match network
    let network = match prefix {
        MAINNET_PREFIX => Network::Bitcoin,
        TESTNET_PREFIX => Network::Testnet,
        REGNET_PREFIX => Network::Regtest,
        _ => return Err(DecodingError::InvalidPrefix(prefix.to_string())),
    };

    // Do some sanity checks on the string
    let mut payload_chars = payload_str.chars();
    if let Some(first_char) = payload_chars.next() {
        if first_char.is_lowercase() {
            if payload_chars.any(|c| c.is_uppercase()) {
                return Err(DecodingError::MixedCase);
            }
        } else if payload_chars.any(|c| c.is_lowercase()) {
            return Err(DecodingError::MixedCase);
        }
    } else {
        return Err(DecodingError::InvalidLength(0));
    }

    // Decode payload to 5 bit array
    let payload_chars = payload_str.chars(); // Reintialize iterator here
    let payload_5_bits: Result<Vec<u8>, DecodingError> = payload_chars
        .map(|c| {
            let i = c as usize;
            if let Some(Some(d)) = CHARSET_REV.get(i) {
                Ok(*d)
            } else {
                Err(DecodingError::InvalidChar(c))
            }
        })
        .collect();
    let payload_5_bits = payload_5_bits?;

    // Verify the checksum
    let checksum = polymod(&[&expand_prefix(prefix), &payload_5_bits[..]].concat());
    if checksum != 0 {
        return Err(DecodingError::ChecksumFailed(checksum));
    }

    // Convert from 5 bit array to byte array
    let len_5_bit = payload_5_bits.len();
    let payload = convert_bits(&payload_5_bits[..(len_5_bit - 8)], 5, 8, false);

    // Verify the version byte
    let version = payload[0];

    // Check length
    let body = &payload[1..];
    let body_len = body.len();
    let version_size = version & version_byte_flags::SIZE_MASK;
    if (version_size == version_byte_flags::SIZE_160 && body_len != 20)
        || (version_size == version_byte_flags::SIZE_192 && body_len != 24)
        || (version_size == version_byte_flags::SIZE_224 && body_len != 28)
        || (version_size == version_byte_flags::SIZE_256 && body_len != 32)
        || (version_size == version_byte_flags::SIZE_320 && body_len != 40)
        || (version_size == version_byte_flags::SIZE_384 && body_len != 48)
        || (version_size == version_byte_flags::SIZE_448 && body_len != 56)
        || (version_size == version_byte_flags::SIZE_512 && body_len != 64)
    {
        return Err(DecodingError::InvalidLength(body_len));
    }

    // Extract the hash type and return
    let version_type = version & version_byte_flags::TYPE_MASK;

    Ok((body.to_vec(), version_type, network))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    // token aware test vectors from: https://github.com/bitjson/cashtokens

    #[test]
    fn mainnet_20byte() {
        // 20-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap(),
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            false,
        );

        verify(
            Network::Bitcoin,
            &hex::decode("fc916f213a3d7f1369313d5fa30f6168f9446a2d").unwrap(),
            "bitcoincash:zr7fzmep8g7h7ymfxy74lgc0v950j3r295z4y4gq0v",
            true,
        );

        verify_p2sh(
            Network::Bitcoin,
            &hex::decode("1948b5c4eacd0ca8d7f4e7f05c83d0c92425abea").unwrap(),
            "bitcoincash:pqv53dwyatxse2xh7nnlqhyr6ryjgfdtagkd4vc388",
            false,
        );

        verify_p2sh(
            Network::Bitcoin,
            &hex::decode("1948b5c4eacd0ca8d7f4e7f05c83d0c92425abea").unwrap(),
            "bitcoincash:rqv53dwyatxse2xh7nnlqhyr6ryjgfdtag38xjkhc5",
            true,
        );
    }

    #[test]
    fn mainnet_24byte() {
        // 24-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA").unwrap(),
            "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
            false,
        );
    }

    #[test]
    fn mainnet_28byte() {
        // 28-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B").unwrap(),
            "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
            false,
        );
    }

    #[test]
    fn mainnet_32byte() {
        // 32-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060")
                .unwrap(),
            "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
            false,
        );

        verify_p2sh(
            Network::Bitcoin,
            &hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap(),
            "bitcoincash:p0llllllllllllllllllllllllllllllllllllllllllllllllll7x3vthu35",
            false,
        );

        verify_p2sh(
            Network::Bitcoin,
            &hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap(),
            "bitcoincash:r0llllllllllllllllllllllllllllllllllllllllllllllllll75zs2wagl",
            true,
        );
    }

    #[test]
    fn mainnet_40byte() {
        // 40-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB").unwrap(),
            "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
            false,
        );
    }

    #[test]
    fn mainnet_48byte() {
        // 48-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C").unwrap(),
            "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
            false,
        );
    }

    #[test]
    fn mainnet_56byte() {
        // 56-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041").unwrap(),
            "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
            false
        );
    }
    #[test]
    fn mainnet_64byte() {
        // 64-byte public key hash on mainnet
        verify(
            Network::Bitcoin,
            &hex::decode("D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B").unwrap(),
            "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
            false
        );
    }

    fn verify(network: Network, data: &Vec<u8>, cashaddr: &str, token_aware: bool) {
        let hash_type = if token_aware {
            version_byte_flags::TYPE_P2PKH_TOKEN
        } else {
            version_byte_flags::TYPE_P2PKH
        };
        let output = encode(data, hash_type, network).unwrap();
        assert_eq!(output, cashaddr.to_ascii_lowercase());
        let decoded = decode(cashaddr).unwrap();
        assert_eq!(decoded.0, *data);
    }

    fn verify_p2sh(network: Network, data: &Vec<u8>, cashaddr: &str, token_aware: bool) {
        let hash_type = if token_aware {
            version_byte_flags::TYPE_P2SH_TOKEN
        } else {
            version_byte_flags::TYPE_P2SH
        };
        let output = encode(data, hash_type, network).unwrap();
        assert_eq!(output, cashaddr.to_ascii_lowercase());
        let decoded = decode(cashaddr).unwrap();
        assert_eq!(decoded.0, *data);
    }
}
