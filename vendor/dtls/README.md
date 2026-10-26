# Nostr VPN DTLS maintenance fork

`nvpn-dtls` 0.17.3 preserves DTLS 0.17.2 behavior while updating P-256/P-384
key agreement for [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The source migration follows [WebRTC PR #943](https://github.com/webrtc-rs/webrtc/pull/943),
commit `f9b3bf21cc7020ae4c65d171880fe68d78f8cb53`, with a `crypto-bigint` 0.7.10
minimum and interoperability tests against `ring`. Negotiated curves and
uncompressed SEC1 public-key encodings are preserved.

<h1 align="center">
 <a href="https://webrtc.rs"><img src="./doc/webrtc.rs.png" alt="WebRTC.rs"></a>
 <br>
</h1>
<p align="center">
 <a href="https://github.com/webrtc-rs/dtls/actions">
  <img src="https://github.com/webrtc-rs/dtls/workflows/cargo/badge.svg">
 </a>
 <a href="https://codecov.io/gh/webrtc-rs/dtls">
  <img src="https://codecov.io/gh/webrtc-rs/dtls/branch/main/graph/badge.svg">
 </a>
 <a href="https://deps.rs/repo/github/webrtc-rs/dtls">
  <img src="https://deps.rs/repo/github/webrtc-rs/dtls/status.svg">
 </a>
 <a href="https://crates.io/crates/dtls">
  <img src="https://img.shields.io/crates/v/dtls.svg">
 </a>
 <a href="https://docs.rs/dtls">
  <img src="https://docs.rs/dtls/badge.svg">
 </a>
 <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
 </a>
 <a href="https://discord.gg/4Ju8UHdXMs">
  <img src="https://img.shields.io/discord/800204819540869120?logo=discord" alt="Discord">
 </a>
</p>
<p align="center">
 A pure Rust implementation of DTLS. Rewrite <a href="https://github.com/pion/dtls/releases/tag/v2.0.0">Pion</a> DTLS in Rust
</p>
