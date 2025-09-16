# prettify_ip

[![Crates.io](https://img.shields.io/crates/v/prettify_ip.svg)](https://crates.io/crates/prettify_ip)
[![Docs.rs](https://docs.rs/prettify_ip/badge.svg)](https://docs.rs/prettify_ip)

A tiny zero dependency Rust library with utilities to **parse and pretty-print IPv4/IPv6 addresses** in both **canonical** and **non-canonical** formats.

---

## ✨ Features
- ✅ Parse **IPv6 from 16 decimal octets** (`42.1.235.199.71.166.181.1.247.39.5.126.9.167.22.11` → `2a01:ebc7:47a6:b501:f727:57e:9a7:160b`)
- ✅ Parse string **IPv4 from decimal integer** (`"3232235777"` → `192.168.1.1`)
- ✅ Parse **IPv4 from hex** (`0xC0A80101` → `192.168.1.1`)
- ✅ Provides **formatting helpers**:
    - Fully expanded IPv6
    - Decimal-dotted IPv6

## Examples

### Parse IPv6 from decimal-dotted

```rust
use pretty_ip::parse_ipv6_decimal_dotted;
use std::net::Ipv6Addr;

let ip = parse_ipv6_decimal_dotted("42.0.35.199.71.166.181.1.248.39.5.126.9.166.22.11").unwrap();
assert_eq!(ip, Ipv6Addr::new(10752, 9159, 18342, 46337, 63527, 1406, 2470, 5643));
```

### Parse IPv4 from decimal integer as string

```rust
use pretty_ip::parse_ipv4_from_u32_decimal;
use std::net::Ipv4Addr;

let ip = parse_ipv4_from_u32_decimal("3232235777").unwrap();
assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
```

### Parse IPv4 from hex

```rust
use pretty_ip::parse_ipv4_from_hex;
use std::net::Ipv4Addr;

let ip = parse_ipv4_from_hex("0xC0A80101").unwrap();
assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
let ip2 = parse_ipv4_from_hex("c0a80101").unwrap();
assert_eq!(ip2, ip);
```

### Parse any IP (auto-detect format)

```rust
use pretty_ip::parse_maybe_ip;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

let ip = parse_maybe_ip("c0a80101").unwrap();
assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

let ip6 = parse_maybe_ip("42.0.35.199.71.166.181.1.248.39.5.126.9.166.22.11").unwrap();
assert!(matches!(ip6, IpAddr::V6(_)));
```

### Format IPv6 as expanded hex or decimal-dotted

```rust
use pretty_ip::{to_expanded_ipv6, ipv6_to_decimal_dotted};
use std::net::Ipv6Addr;

let ip = Ipv6Addr::LOCALHOST;
assert_eq!(to_expanded_ipv6(&ip), "0000:0000:0000:0000:0000:0000:0000:0001");
assert_eq!(ipv6_to_decimal_dotted(&ip), "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1");
```


## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
prettify_ip = "0.1"