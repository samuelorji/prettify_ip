# prettify_ip

[![Crates.io](https://img.shields.io/crates/v/prettify_ip.svg)](https://crates.io/crates/prettify_ip)
[![Docs.rs](https://docs.rs/prettify_ip/badge.svg)](https://docs.rs/prettify_ip)

A tiny Rust library with utilities to **parse and pretty-print IPv4/IPv6 addresses** in both **canonical** and **non-canonical** formats.

---

## ✨ Features

- ✅ Parse **IPv6 from 16 decimal octets** (`42.1.235.199.71.166.181.1.247.39.5.126.9.167.22.11` → `2a01:ebc7:47a6:b501:f727:57e:9a7:160b`)
- ✅ Parse string **IPv4 from decimal integer** (`"3232235777"` → `192.168.1.1`)
- ✅ Parse **IPv4 from hex** (`0xC0A80101` → `192.168.1.1`)
- ✅ Provides **formatting helpers**:
    - Fully expanded IPv6
    - Decimal-dotted IPv6
    - IPv4 back to `u32`



## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
prettify_ip = "0.1"
