//! prettify_ip - parse and pretty-print IP addresses in canonical and non-canonical forms.
//!
//! Supported formats:
//! - **Standard** IPv4 & IPv6 (RFC-compliant).
//! - **IPv6 decimal dotted**: 16 decimal octets separated by `.`.
//! - **IPv4 decimal integer**: decimal string representing a 32-bit integer.
//! - **IPv4 hex**: hex string (with or without `0x` prefix).
//!

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Errors returned by parsing helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseIpError {
    EmptyInput,
    InvalidFormat(&'static str),
    InvalidOctet { idx: usize, found: String },
    ValueOutOfRange { idx: usize, found: u128, max: u128 },
    NumericParseError { idx: Option<usize>, src: String },
    Overflow { found: String, max: String },
}

impl fmt::Display for ParseIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseIpError::*;
        match self {
            EmptyInput => write!(f, "empty input"),
            InvalidFormat(s) => write!(f, "invalid format: {}", s),
            InvalidOctet { idx, found } => {
                write!(f, "invalid octet at position {}: '{}'", idx, found)
            }
            ValueOutOfRange { idx, found, max } => {
                write!(f, "value out of range at {}: {} > {}", idx, found, max)
            }
            NumericParseError { idx, src } => {
                if let Some(i) = idx {
                    write!(f, "numeric parse error at {}: '{}'", i, src)
                } else {
                    write!(f, "numeric parse error: '{}'", src)
                }
            }
            Overflow { found, max } => {
                write!(f, "numeric overflow: {} > {}", found, max)
            }
        }
    }
}
impl std::error::Error for ParseIpError {}

pub fn parse_ipv6_decimal_dotted(s: &str) -> Result<Ipv6Addr, ParseIpError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseIpError::EmptyInput);
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 16 {
        return Err(ParseIpError::InvalidFormat("expected 16 decimal octets"));
    }
    let mut bytes = [0u8; 16];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(ParseIpError::InvalidOctet { idx: i, found: part.to_string() });
        }
        if !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseIpError::InvalidOctet { idx: i, found: part.to_string() });
        }
        match u16::from_str(part) {
            Ok(v) if v <= 255 => bytes[i] = v as u8,
            Ok(v) => {
                return Err(ParseIpError::ValueOutOfRange { idx: i, found: v as u128, max: 255 });
            }
            Err(_) => {
                return Err(ParseIpError::NumericParseError { idx: Some(i), src: part.to_string() });
            }
        }
    }
    Ok(Ipv6Addr::from(bytes))
}

/// Parse IPv4 from decimal integer.
pub fn parse_ipv4_from_u32_decimal(s: &str) -> Result<Ipv4Addr, ParseIpError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseIpError::EmptyInput);
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ParseIpError::InvalidFormat("expected decimal integer with digits only"));
    }
    match u128::from_str(s) {
        Ok(v) => {
            if v > (u32::MAX as u128) {
                return Err(ParseIpError::Overflow { found: v.to_string(), max: u32::MAX.to_string() });
            }
            Ok(Ipv4Addr::from(v as u32))
        }
        Err(_) => Err(ParseIpError::NumericParseError { idx: None, src: s.to_string() }),
    }
}

/// Parse IPv4 from hex (with or without `0x`).
pub fn parse_ipv4_from_hex(s: &str) -> Result<Ipv4Addr, ParseIpError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseIpError::EmptyInput);
    }
    let s = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };
    if s.is_empty() || s.len() > 8 {
        return Err(ParseIpError::InvalidFormat("hex string must be 1..=8 hex digits"));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseIpError::InvalidFormat("non-hex character found"));
    }
    match u32::from_str_radix(s, 16) {
        Ok(v) => Ok(Ipv4Addr::from(v)),
        Err(_) => Err(ParseIpError::NumericParseError { idx: None, src: s.to_string() }),
    }
}

/// Try multiple parsing strategies. N/B, may not cover all edge cases
pub fn parse_maybe_ip(s: &str) -> Result<IpAddr, ParseIpError> {
    let s_trim = s.trim();
    if s_trim.is_empty() {
        return Err(ParseIpError::EmptyInput);
    }
    if let Ok(ip) = IpAddr::from_str(s_trim) {
        return Ok(ip);
    }
    if s_trim.matches('.').count() == 15 {
        if let Ok(v6) = parse_ipv6_decimal_dotted(s_trim) {
            return Ok(IpAddr::V6(v6));
        }
    }
    if s_trim.matches('.').count() == 3 {
        println!("some {:?}", Ipv4Addr::from_str(s_trim));
        if let Ok(v4) = Ipv4Addr::from_str(s_trim) {
            return Ok(IpAddr::V4(v4));
        }
    }
    if s_trim.starts_with("0x") || s_trim.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v4) = parse_ipv4_from_hex(s_trim) {
            return Ok(IpAddr::V4(v4));
        }
    }
    if s_trim.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(v4) = parse_ipv4_from_u32_decimal(s_trim) {
            return Ok(IpAddr::V4(v4));
        }
    }
    Err(ParseIpError::InvalidFormat("unrecognized IP format"))
}

/// Formatting helpers
pub fn to_expanded_ipv6(ip: &Ipv6Addr) -> String {
    ip.segments().iter().map(|s| format!("{:04x}", s)).collect::<Vec<_>>().join(":")
}
pub fn ipv6_to_decimal_dotted(ip: &Ipv6Addr) -> String {
    ip.octets().iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".")
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Valid IPv6 decimal-dotted examples ---
    #[test]
    fn parse_ipv6_decimal_dotted_basic() {
        let s = "42.0.35.199.71.166.181.1.248.39.5.126.9.166.22.11";
        let v6 = parse_ipv6_decimal_dotted(s).expect("should parse");
        // manually check segments
        let segments = v6.segments();
        assert_eq!(segments[0], 0x2a00);
        assert_eq!(segments[1], 0x23c7);
        assert_eq!(segments[2], 0x47a6);
        assert_eq!(segments[3], 0xb501);
        assert_eq!(segments[4], 0xf827);
        assert_eq!(segments[5], 0x057e);
        assert_eq!(segments[6], 0x09a6);
        assert_eq!(segments[7], 0x160b);

        // round-trip to decimal-dotted
        let dd = ipv6_to_decimal_dotted(&v6);
        assert_eq!(dd, s);
    }

    #[test]
    fn parse_ipv6_decimal_dotted_whitespace_trim() {
        let s = "  0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1  ";
        let v6 = parse_ipv6_decimal_dotted(s).unwrap();
        assert_eq!(v6, Ipv6Addr::LOCALHOST); // ::1
    }

    #[test]
    fn parse_ipv6_decimal_dotted_min_max_values() {
        // min all zeros
        let all_zeros = "0.".repeat(15) + "0";
        assert_eq!(parse_ipv6_decimal_dotted(&all_zeros).unwrap(), Ipv6Addr::UNSPECIFIED);

        // max all 255
        let all_255  = "255.".repeat(15) + "255";
        let v6 = parse_ipv6_decimal_dotted(&all_255).unwrap();
        let octs = v6.octets();
        assert!(octs.iter().all(|&b| b == 255));
    }

    // --- IPv6 decimal-dotted error cases ---
    #[test]
    fn parse_ipv6_decimal_dotted_too_few_parts() {
        let s = "1.2.3"; // too short
        assert!(matches!(
            parse_ipv6_decimal_dotted(s),
            Err(ParseIpError::InvalidFormat(_))
        ));
    }

    #[test]
    fn parse_ipv6_decimal_dotted_negative_and_non_digit() {
        assert!(matches!(
            parse_ipv6_decimal_dotted("1.-2.3.4.5.6.7.8.9.10.11.12.13.14.15.16"),
            Err(ParseIpError::InvalidOctet { .. })
        ));
        assert!(matches!(
            parse_ipv6_decimal_dotted("1.a.3.4.5.6.7.8.9.10.11.12.13.14.15.16"),
            Err(ParseIpError::InvalidOctet { .. })
        ));
    }

    #[test]
    fn parse_ipv6_decimal_dotted_out_of_range() {
        let mut v: Vec<String> = (0..16).map(|i| i.to_string()).collect();
        v[5] = "256".to_string(); // invalid
        let s = v.join(".");
        match parse_ipv6_decimal_dotted(&s) {
            Err(ParseIpError::ValueOutOfRange { idx, found, max }) => {
                assert_eq!(idx, 5);
                assert_eq!(found, 256);
                assert_eq!(max, 255);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_ipv6_decimal_dotted_empty_input() {
        assert!(matches!(
            parse_ipv6_decimal_dotted(""),
            Err(ParseIpError::EmptyInput)
        ));
    }

    #[test]
    fn parse_ipv6_decimal_dotted_trailing_dot() {
        assert!(matches!(
            parse_ipv6_decimal_dotted("1.2.3.4.5.6.7.8.9.10.11.12.13.14.15."),
            Err(ParseIpError::InvalidOctet { .. })
        ));
    }


    #[test]
    fn parse_ipv4_from_u32_decimal_non_digit() {
        assert!(matches!(
            parse_ipv4_from_u32_decimal("12abc"),
            Err(ParseIpError::InvalidFormat(_))
        ));
    }

    // --- IPv4 hex tests ---
    #[test]
    fn parse_ipv4_from_hex_basic() {
        let a = parse_ipv4_from_hex("0xC0A80101").unwrap();
        assert_eq!(a, Ipv4Addr::new(192, 168, 1, 1));
        let b = parse_ipv4_from_hex("c0a80101").unwrap();
        assert_eq!(b, a);
    }

    #[test]
    fn parse_ipv4_from_hex_invalid_chars() {
        assert!(matches!(
            parse_ipv4_from_hex("0xGHIJK"),
            Err(ParseIpError::InvalidFormat(_))
        ));
    }

    // --- parse_maybe_ip tests ---
    #[test]
    fn parse_maybe_ip_standard_ipv6() {
        let s = "2001:db8::1";
        let parsed = parse_maybe_ip(s).unwrap();
        assert!(matches!(parsed, IpAddr::V6(_)));
    }
    #[test]
    fn parse_maybe_ip_decimal_dotted_ipv6() {
        let s = "42.0.35.199.71.166.181.1.248.39.5.126.9.166.22.11";
        let parsed = parse_maybe_ip(s).unwrap();
        assert!(matches!(parsed, IpAddr::V6(_)));
    }

    #[test]
    fn parse_maybe_ip_ipv4_hex_and_decimal_fallback_order() {
        // hex-like digits only should attempt hex -> ok
        let s = "c0a80101";
        let parsed = parse_maybe_ip(s).unwrap();
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // pure decimal digits but length small -> decimal integer fallback
        let s2 = "3232235777";
        let parsed2 = parse_maybe_ip(s2).unwrap();
        assert_eq!(parsed2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // --- invalid parse_maybe_ip ---
    #[test]
    fn parse_maybe_ip_invalid() {
        assert!(parse_maybe_ip("not an ip").is_err());
        assert!(parse_maybe_ip("1.2.3.4.5").is_err()); // ambiguous length
    }

    // --- check edgecases ---
    #[test]
    fn ipv6_decimal_dotted_with_extra_spaces_between() {
        // internal spaces are invalid
        assert!(parse_ipv6_decimal_dotted("1. 2.3.4.5.6.7.8.9.10.11.12.13.14.15.16").is_err());
    }

    #[test]
    fn ipv4_hex_with_leading_zeroes_padding_ok() {
        let r = parse_ipv6_decimal_dotted("42.1.235.199.71.166.181.1.247.39.5.126.9.167.22.11");

        println!("{:?}", r);
        // short hex should parse e.g. "1" => 0x1 -> 0.0.0.1
        assert_eq!(
            parse_ipv4_from_hex("1").unwrap(),
            Ipv4Addr::new(0, 0, 0, 1)
        );
        // "00000001" also ok
        assert_eq!(
            parse_ipv4_from_hex("00000001").unwrap(),
            Ipv4Addr::new(0, 0, 0, 1)
        );
    }
}

