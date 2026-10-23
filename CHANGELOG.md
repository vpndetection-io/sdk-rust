# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.2.3 are described by their release commits.

## 5.9.1 - 2026-10-23

### Fixes

- Read a date only in RFC 3339's form, never chrono's relaxed one ([`97fb2dd`](https://github.com/vpndetection-io/sdk-rust/commit/97fb2dd29f1d596efd79c0c7794b2415d70e42c6))
- Read a Retry-After date in RFC 9110's three forms alone, in GMT ([`c257a2e`](https://github.com/vpndetection-io/sdk-rust/commit/c257a2e391293a40ab288ead0420ff3863bf056f))
- Trim the API key, and refuse one holding a control character at build ([`48032cd`](https://github.com/vpndetection-io/sdk-rust/commit/48032cdfebbc56974de22e4d266bca5cad85345c))
- Read the rc beside an empty error message ([`f4ff4d3`](https://github.com/vpndetection-io/sdk-rust/commit/f4ff4d300ff8bb93a25da550055b8d16a3054881))
- Pass the registry token and the API key by name, never on a command line ([`00aef1b`](https://github.com/vpndetection-io/sdk-rust/commit/00aef1bf89d2e22ae28bc01b81b222a0358d39d6))
- Integration: hold the resolved crate to the checksum the index publishes ([`919dca6`](https://github.com/vpndetection-io/sdk-rust/commit/919dca6ec01edb830a7913c79a8fd008089bbc2b))

## 5.9.0 - 2026-10-21

### Features

- Add oauth().register, for RFC 7591 dynamic client registration ([`e31ec84`](https://github.com/vpndetection-io/sdk-rust/commit/e31ec84eaccaadb1d439d7d3859516f40078fb30))

## 5.8.0 - 2026-10-20

### Features

- Re-pin the spec to 2026.10.20: location and asn on every keyed lookup ([`af7637f`](https://github.com/vpndetection-io/sdk-rust/commit/af7637f8f2e2dc8a5311ae230d7afc27200ef964))

## 5.7.0 - 2026-10-19

### Features

- Re-pin the spec to 2026.10.19: num_ports and num_proxies in the pubproxy detail ([`be9bdd4`](https://github.com/vpndetection-io/sdk-rust/commit/be9bdd4db03b20f08da5f541488aa92a38c8b850))

## 5.6.0 - 2026-10-18

### Features

- Re-pin the spec to 2026.10.18: is_pubproxy and the pubproxy detail ([`5a955ae`](https://github.com/vpndetection-io/sdk-rust/commit/5a955ae0120ee305db3d706fb2c6c5f8ec060750))

## 5.5.0 - 2026-10-17

### Features

- Re-pin the spec to 2026.10.16: dynamic client registration ([`d7341e9`](https://github.com/vpndetection-io/sdk-rust/commit/d7341e9832ce82450fba334e37586d4629ab25d3))

### Fixes

- Build beside reqwest 0.13.2 and newer ([`f513263`](https://github.com/vpndetection-io/sdk-rust/commit/f513263e32c2ceb1115a1643e5a949df68d5a8b8))

## 5.4.3 - 2026-10-16

### Fixes

- Re-pin the spec to 2026.10.15: descriptions in US spelling ([`07f521e`](https://github.com/vpndetection-io/sdk-rust/commit/07f521e51db3ebd00ab20e6e5ea9640cda89b18c))

## 5.4.2 - 2026-10-10

### Fixes

- Re-pin the spec to 2026.10.09: rotating a key needs apikeys.reveal ([`28af34c`](https://github.com/vpndetection-io/sdk-rust/commit/28af34cdc4c3cf7e537420c0a5a5320b98f1416b))

## 5.4.1 - 2026-10-09

### Fixes

- Retry an unreadable download link answer, as a server_error ([`d6d9bf3`](https://github.com/vpndetection-io/sdk-rust/commit/d6d9bf3eafd6085eb2e12388249e74aeb67d9c7f))
- Read a Retry-After as digits or an HTTP date in any of its three forms ([`2617dc3`](https://github.com/vpndetection-io/sdk-rust/commit/2617dc39f0181092cd5c4d124b7eeadd9c64d00c))

## 5.4.0 - 2026-10-05

### Features

- Add the authorization code sign-in, with PKCE ([`88b1ee8`](https://github.com/vpndetection-io/sdk-rust/commit/88b1ee8793ea5a9f5c39833774f63ffe1b98cd04))

## 5.3.4 - 2026-10-04

### Fixes

- Re-pin the spec to 2026.10.03: metadata needs no license ([`9f72575`](https://github.com/vpndetection-io/sdk-rust/commit/9f725755b71553fc518d59f343e3eb9d2e0383e9))

## 5.3.3 - 2026-10-02

### Fixes

- Raise the tokio and chrono floors past their advisories ([`b13753c`](https://github.com/vpndetection-io/sdk-rust/commit/b13753cedc664d957f64eed5693eb21273e457e2))

## 5.3.2 - 2026-09-29

### Fixes

- Recognize 26 more reserved ranges as bogons, as the API does ([`4095178`](https://github.com/vpndetection-io/sdk-rust/commit/4095178735b8651e447fbda5da22f3b5e92d4041))

## 5.3.1 - 2026-09-28

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`6ca0469`](https://github.com/vpndetection-io/sdk-rust/commit/6ca0469ea5edd4cca9c25c9ec25e52562b7218f0))

## 5.3.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding client_id_metadata_document_supported ([`31074be`](https://github.com/vpndetection-io/sdk-rust/commit/31074be840a3462796adc716dc389df62b9f03cb))

## 5.2.4 - 2026-09-26

### Fixes

- Fail download_bytes on a length no process can hold, never abort ([`3a58e87`](https://github.com/vpndetection-io/sdk-rust/commit/3a58e87ed15c17e70c1286bd0cc12b9fa43780cf))

## 5.2.3 - 2026-09-25

### Fixes

- Share one request per address, bound every server-set wait ([`b5137ea`](https://github.com/vpndetection-io/sdk-rust/commit/b5137ea3f26a66b8e706c9eddc41eadf2ecea413))
