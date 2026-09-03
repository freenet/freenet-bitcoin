//! Bitcoin address text to canonical `scriptPubKey`.
//!
//! The script is the identity everywhere else in this system: several address
//! encodings can denote the same script, and only the script appears on chain.

use bech32::{primitives::decode::CheckedHrpstring, Bech32, Bech32m, Hrp};
use freenet_bitcoin_common::BitcoinNetwork;

/// Decode an address into the output script it denotes.
pub fn to_script_pubkey(addr: &str, network: BitcoinNetwork) -> Result<Vec<u8>, String> {
    let a = addr.trim();
    if a.is_empty() {
        return Err("Enter a Bitcoin address.".into());
    }
    if let Some(script) = try_bech32(a, network)? {
        return Ok(script);
    }
    try_base58(a, network)
}

fn expected_hrp(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "bc",
        // Signet and testnet share the "tb" prefix, so an address alone cannot
        // distinguish them. Surfaced in the UI copy rather than papered over.
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet => "tb",
        BitcoinNetwork::Regtest => "bcrt",
    }
}

fn try_bech32(addr: &str, network: BitcoinNetwork) -> Result<Option<Vec<u8>>, String> {
    let lower = addr.to_ascii_lowercase();
    if !lower.contains('1') {
        return Ok(None);
    }
    let want = expected_hrp(network);
    let hrp_str = lower.rsplit_once('1').map(|(h, _)| h).unwrap_or("");
    if hrp_str != want {
        // Only reject if it *looks* like a segwit address for another network.
        if ["bc", "tb", "bcrt"].contains(&hrp_str) {
            return Err(format!(
                "That is a {hrp_str}… address; this page is showing {}.",
                network.as_str()
            ));
        }
        return Ok(None);
    }
    let hrp = Hrp::parse(want).map_err(|e| format!("bad prefix: {e}"))?;

    // v0 uses bech32, v1+ uses bech32m. Try both and read the version byte.
    let (version, program) = decode_segwit(&lower, hrp)?;
    if program.len() < 2 || program.len() > 40 {
        return Err("That witness program is not a valid length.".into());
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err("A version-0 witness program must be 20 or 32 bytes.".into());
    }

    let mut script = Vec::with_capacity(2 + program.len());
    script.push(if version == 0 { 0x00 } else { 0x50 + version });
    script.push(program.len() as u8);
    script.extend_from_slice(&program);
    Ok(Some(script))
}

fn decode_segwit(addr: &str, hrp: Hrp) -> Result<(u8, Vec<u8>), String> {
    for m in 0..2 {
        let parsed = if m == 0 {
            CheckedHrpstring::new::<Bech32>(addr)
        } else {
            CheckedHrpstring::new::<Bech32m>(addr)
        };
        if let Ok(p) = parsed {
            if p.hrp() != hrp {
                continue;
            }
            let mut iter = p.byte_iter();
            let data: Vec<u8> = iter.by_ref().collect();
            let _ = data;
            // byte_iter drops the witness version, so re-read it from the raw
            // characters: the first data character after the separator.
            let after = addr.rsplit_once('1').map(|(_, r)| r).unwrap_or("");
            let vchar = after.chars().next().ok_or("empty address payload")?;
            let version = bech32::primitives::gf32::Fe32::from_char(vchar)
                .map_err(|_| "bad witness version".to_string())?
                .to_u8();
            let program = decode_program(addr)?;
            return Ok((version, program));
        }
    }
    Err("That does not look like a valid Bech32 address.".into())
}

fn decode_program(addr: &str) -> Result<Vec<u8>, String> {
    // Re-decode the payload after the version character as 5-bit groups.
    let after = addr.rsplit_once('1').map(|(_, r)| r).unwrap_or("");
    let body: String = after.chars().skip(1).collect();
    let body = &body[..body.len().saturating_sub(6)]; // strip checksum
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in body.chars() {
        let v = bech32::primitives::gf32::Fe32::from_char(c)
            .map_err(|_| "bad character in address".to_string())?
            .to_u8() as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn try_base58(addr: &str, network: BitcoinNetwork) -> Result<Vec<u8>, String> {
    let bytes = bs58::decode(addr)
        .with_check(None)
        .into_vec()
        .map_err(|_| "That is not a Bitcoin address this page recognises.".to_string())?;
    let (version, payload) = bytes.split_first().ok_or("empty address payload")?;
    if payload.len() != 20 {
        return Err("That address does not carry a 20-byte hash.".into());
    }
    let (p2pkh, p2sh) = match network {
        BitcoinNetwork::Bitcoin => (0x00u8, 0x05u8),
        _ => (0x6f, 0xc4),
    };
    if *version == p2pkh {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(payload);
        s.extend_from_slice(&[0x88, 0xac]);
        Ok(s)
    } else if *version == p2sh {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(payload);
        s.push(0x87);
        Ok(s)
    } else {
        Err(format!(
            "That address is not valid on {}.",
            network.as_str()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-173 / BIP-350 vectors.
    #[test]
    fn parses_mainnet_p2wpkh() {
        let s = to_script_pubkey(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(s[0], 0x00);
        assert_eq!(s[1], 20);
        assert_eq!(s.len(), 22);
    }

    #[test]
    fn parses_taproot() {
        let s = to_script_pubkey(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(s[0], 0x51, "witness v1");
        assert_eq!(s[1], 32);
    }

    #[test]
    fn parses_the_signet_demo_address() {
        let s = to_script_pubkey(
            "tb1qxc9rhgpdjcp42nmhg6lepe7pp5g86tx25vlv8h",
            BitcoinNetwork::Signet,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&s),
            "0014360a3ba02d9603554f7746bf90e7c10d107d2cca"
        );
    }

    #[test]
    fn parses_mainnet_p2pkh() {
        let s = to_script_pubkey(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(s.len(), 25);
        assert_eq!(s[0], 0x76);
        assert_eq!(s[24], 0xac);
    }

    #[test]
    fn rejects_an_address_from_another_network_with_a_useful_message() {
        let e = to_script_pubkey(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BitcoinNetwork::Signet,
        )
        .unwrap_err();
        assert!(e.contains("signet"), "got: {e}");
    }

    #[test]
    fn rejects_nonsense() {
        assert!(to_script_pubkey("hello", BitcoinNetwork::Bitcoin).is_err());
        assert!(to_script_pubkey("", BitcoinNetwork::Bitcoin).is_err());
    }
}
