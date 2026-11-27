# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.2.3 are described by their release commits.

## 6.7.0 - 2026-11-27

### Features

- Read a keyless answer without the network's type ([`ead00dc`](https://github.com/vpndetection-io/sdk-rust/commit/ead00dcda8303c11f6048d8f59dcfe0a997a9295))

## 6.6.1 - 2026-11-26

### Fixes

- Middleware: a condition on the verdict is no plan gap for a request that sent no agent ([`19d837c`](https://github.com/vpndetection-io/sdk-rust/commit/19d837cfe71bb8976090768af9821881bdef7ee2))

## 6.6.0 - 2026-11-26

### Features

- Middleware: allow_bots sends only a crawler's User-Agent, at most four an address ([`7efe4a5`](https://github.com/vpndetection-io/sdk-rust/commit/7efe4a5680c0ac5738f3685ac66b492113794e63))

## 6.5.1 - 2026-11-25

### Fixes

- README: one paid plan, Data; the entitlement example names it ([`1d7fad8`](https://github.com/vpndetection-io/sdk-rust/commit/1d7fad8691cf8f0415ea3db8da2aa73883ae7a80))
- Docs: the entitlement plan's example key and name are the Data plan's ([`27382fe`](https://github.com/vpndetection-io/sdk-rust/commit/27382fe4b6e6818fdf7d9a7c69ee5fe7a20d508d))
- Spec 2026.11.25: doc comments name a paid plan, the entitlement example the Data plan ([`e9ce4a4`](https://github.com/vpndetection-io/sdk-rust/commit/e9ce4a40e3b13a12df62452e2ff5dc486fb12317))

## 6.5.0 - 2026-11-24

### Fixes

- Middleware: a condition on a list member matches any element ([`5133f2d`](https://github.com/vpndetection-io/sdk-rust/commit/5133f2d85e8f46704ba42d114532c3ae01b77d1e))

## 6.4.0 - 2026-11-24

### Features

- Send a request's user agent with a lookup, a batch or my_ip, and read its verdict ([`7cd1da0`](https://github.com/vpndetection-io/sdk-rust/commit/7cd1da044fb29320424a02e79612ebda335844b5))
- Middleware: allow_bots lets a verified crawler through ([`0c96296`](https://github.com/vpndetection-io/sdk-rust/commit/0c96296d6d8945445288009bfd424d27c8caff5e))

### Fixes

- Re-pin the spec to 2026.11.23, and refuse a detail's day that is not a date ([`d98e3b4`](https://github.com/vpndetection-io/sdk-rust/commit/d98e3b4294041c922498007c7bb34a3d335b69b5))

## 6.3.1 - 2026-11-23

### Fixes

- Require futures-util 0.3.31, past RUSTSEC-2020-0062 ([`63393f0`](https://github.com/vpndetection-io/sdk-rust/commit/63393f0a40b774ea3043ba6c2484f348d91fc10a))

## 6.3.0 - 2026-11-22

### Features

- Re-pin the spec to 2026.11.22: is_bot and bot, and the AS's country and RPKI status required ([`f888b71`](https://github.com/vpndetection-io/sdk-rust/commit/f888b714bd8051690f9d8578ae47dee167bc31c2))
- Read whether a bot uses an address, and whose: is_bot and bot ([`e4b687f`](https://github.com/vpndetection-io/sdk-rust/commit/e4b687f50d69ef24bac31a3735b46456585d8815))

### Fixes

- Refuse an answer without the AS's country or RPKI status, as the API always sends them ([`ef26652`](https://github.com/vpndetection-io/sdk-rust/commit/ef26652e9167c75c9f5b7ce01495ade60ff60f60))

## 6.2.0 - 2026-11-20

### Features

- Read the network, service, company and abuse members of an answer ([`63af7cd`](https://github.com/vpndetection-io/sdk-rust/commit/63af7cda728241924a2830bcd195f31184f01fc1))

### Fixes

- Cache a spent trial's or a reached cap's answer for a minute at most ([`409fc74`](https://github.com/vpndetection-io/sdk-rust/commit/409fc741e9be69f24744b0b1af047b5403b6d017))

## 6.1.1 - 2026-11-19

### Fixes

- Re-pin the spec to 2026.11.18: a key over plain HTTP is refused ([`0f6daa1`](https://github.com/vpndetection-io/sdk-rust/commit/0f6daa191f99cc57ba574bd28969277236a319c9))

## 6.1.0 - 2026-11-18

### Features

- Read cap_reached past a paid plan's overage cap, and re-pin the spec ([`67490c9`](https://github.com/vpndetection-io/sdk-rust/commit/67490c9922196485bcdc1cf631bece7c2594c43a))

## 6.0.0 - 2026-11-16

### Breaking changes

- Hand back a vocabulary value this release was not built with ([`8aa241e`](https://github.com/vpndetection-io/sdk-rust/commit/8aa241e9ff6311d7e2311625f46b712dcd04d6fa))

## 5.14.0 - 2026-11-16

### Features

- Read the plan's name, what to show beside the key you compare ([`4166cf0`](https://github.com/vpndetection-io/sdk-rust/commit/4166cf0c7e3f0a9c3020779d7b9717bf62e0b655))

### Fixes

- Re-pin the spec to 2026.11.15: Asn.asn is an i64, so any AS number reads ([`511d9eb`](https://github.com/vpndetection-io/sdk-rust/commit/511d9eb5e2e4173f8bcaeac1d82232d7ddc0751e))

## 5.13.0 - 2026-11-14

### Features

- Re-pin the spec to 2026.11.14: is_bogon on every answer, and provider_name beside each provider ([`c82d663`](https://github.com/vpndetection-io/sdk-rust/commit/c82d6632e7d0fa4c5b46f5bbf5f350fc713bee23))

### Fixes

- Re-pin the spec to 2026.11.12: plainer words on the 401 and the batch rate limit ([`4134f37`](https://github.com/vpndetection-io/sdk-rust/commit/4134f37be74d46a216a168e83f88f4f6f9ad6e6b))
- Say that a batch request of one address is answered as its lookup ([`686dd4e`](https://github.com/vpndetection-io/sdk-rust/commit/686dd4e35721d1367024c6ab0a03bb113c3dc5b6))

## 5.12.1 - 2026-11-11

### Fixes

- Say the free plan's daily trial and Unlimited, the free plan, and re-pin the spec ([`159b055`](https://github.com/vpndetection-io/sdk-rust/commit/159b0553fe7d2edd6a7d37d31e4129a3a1adb21f))

## 5.12.0 - 2026-11-11

### Features

- Add trial_expired for a trial key's answers, and re-pin the spec ([`cc6ac39`](https://github.com/vpndetection-io/sdk-rust/commit/cc6ac3912034777c2d9951192c9a263307befa09))

## 5.11.2 - 2026-11-11

### Fixes

- Name the Unlimited tier and its terms, and re-pin the spec ([`fb2b3a0`](https://github.com/vpndetection-io/sdk-rust/commit/fb2b3a07a1913afaa9891ba58883a476b455ec9e))

## 5.11.1 - 2026-11-11

### Fixes

- Re-pin the spec's 2026.11.11 rebuild: plainer words on lookups without a key ([`8b6b5ad`](https://github.com/vpndetection-io/sdk-rust/commit/8b6b5ad0ce03dd55319af1583b5cde972bcbebc2))

## 5.11.0 - 2026-11-11

### Features

- Re-pin the spec to 2026.11.11: a lookup without a key answers more ([`398872b`](https://github.com/vpndetection-io/sdk-rust/commit/398872baa237fec7ddb39a14ad320e9f83c91437))

## 5.10.0 - 2026-11-07

### Features

- Download the build a database.updated webhook names ([`aedb8fb`](https://github.com/vpndetection-io/sdk-rust/commit/aedb8fb470717f519015b03301bb368dde23d0ea))

### Fixes

- Re-pin the spec to 2026.11.05: the download's build parameter ([`b898c4c`](https://github.com/vpndetection-io/sdk-rust/commit/b898c4c518d9f388fca8dc133b4101f734d1e57c))

## 5.9.6 - 2026-11-04

### Fixes

- Fail only the address of a batch entry the answer cannot read ([`438f74f`](https://github.com/vpndetection-io/sdk-rust/commit/438f74f408ff3dd87e721082ae0868dae95d97b6))

## 5.9.5 - 2026-11-02

### Fixes

- Refuse a metadata sample row that is not a JSON object ([`4ba521e`](https://github.com/vpndetection-io/sdk-rust/commit/4ba521e6842420e5bf09dbd00e6e21f76c910f32))

## 5.9.4 - 2026-10-30

### Fixes

- Read a lowercase t or z in a date-time ([`061528c`](https://github.com/vpndetection-io/sdk-rust/commit/061528c8e118fcda8f4543a3d1616e2cc12c6423))

## 5.9.3 - 2026-10-26

### Fixes

- Re-pin the spec to 2026.10.25: Retry-After on myip's 429 ([`426e7c7`](https://github.com/vpndetection-io/sdk-rust/commit/426e7c72621009f42c117c95fa2e1a835f7c4246))

## 5.9.2 - 2026-10-24

### Fixes

- Require tokio 1.53.3, past RUSTSEC-2026-0386 ([`df4da53`](https://github.com/vpndetection-io/sdk-rust/commit/df4da5396c2d649327e71b603e5d53b8f7ddc592))

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
