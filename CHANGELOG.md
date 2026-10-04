# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.2.3 are described by their release commits.

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
