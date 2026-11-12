# S22: Windows cached domain logons in the SECURITY hive

Version 1, 2026-11-12.

## 1. Purpose

A domain member keeps the last few domain logons so that a user can log on when no domain controller answers (Microsoft Learn, "Interactive logon: Number of previous logons to cache"). Each cached logon is a slot value `NL$<n>` under the SECURITY hive's `Cache` key. A used slot holds what the domain controller returned about the user, in the vocabulary of [MS-NRPC] NETLOGON_VALIDATION_SAM_INFO4 (the user's account name, logon domain, DNS domain, user RID), and a password verifier, all encrypted under a key carried by the `NL$KM` LSA secret (S21). An examiner wants each used slot's user, domain and verifier, to know who logged on to the machine and to test candidate passwords offline.

The empty-slot layout, the slot count and the control value are measured. No capture holds a used slot, because every lab capture is a stand-alone machine that never cached a domain logon. The used-slot layout below is therefore a working layout, implemented so that a mismatch is reported rather than decoded into false names, and tested only on synthetic fixtures built from this specification. Section 10 says how it is to be confirmed.

## 2. Inputs

| Input | Meaning |
|---|---|
| SECURITY hive | Read through `registryhive`. Supplies the `Cache` values and, through S21, the `NL$KM` secret. |
| SYSTEM hive | Read through `registryhive`, only when a used slot exists. Supplies the system key (S20) for S21. |
| Options | The registered tool keeps the option keys it had: `strict`, `diagnostics`. No new options. |
| Limits | None beyond `registryhive`'s own; the slot count is bounded by the hive walker. |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | NETLOGON_VALIDATION_SAM_INFO4 carries, among others, EffectiveName, FullName, LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive (UNICODE_STRING), UserId, PrimaryGroupId, GroupCount and GroupIds, UserFlags, LogonServer, LogonDomainName, LogonDomainId, SidCount and ExtraSids, DnsLogonDomainName (the FQDN of the user account's domain) and Upn. Its fields mean what the identically named KERB_VALIDATION_INFO fields mean. | [MS-NRPC] 2.2.1.4.13 "NETLOGON_VALIDATION_SAM_INFO4", accessed 2026-11-12. |
| D2 | KERB_VALIDATION_INFO EffectiveName is the user account's samAccountName; LogonDomainName is the NetBIOS name of the domain the account belongs to; UserId is the account's RID. | [MS-PAC] 2.5 "KERB_VALIDATION_INFO", accessed 2026-11-12. |
| D3 | The policy "Interactive logon: Number of previous logons to cache (in case domain controller is not available)" takes 0 to 50, default 10; it is the `CachedLogonsCount` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`; 0 disables caching. | Microsoft Learn, "Interactive logon: Number of previous logons to cache (in case domain controller is not available)"; "Cached user logon fails with LSASRV event 45058", accessed 2026-11-12. |
| D4 | Secret names starting with `NL$` are system secrets: no client can read them. | [MS-LSAD] "Secret Object Data Model", accessed 2026-11-12. |
| D5 | AES-128: 16-byte key and block. CBC decryption: P_i = D_K(C_i) XOR C_(i-1), with C_0 the IV. | [FIPS 197]; NIST SP 800-38A section 6.2, accessed 2026-11-12. |
| D6 | UNICODE strings in these structures are 2-byte little-endian UTF-16; a UNICODE_STRING Length counts bytes. | [MS-DTYP] 2.3.10 "RPC_UNICODE_STRING", accessed 2026-11-12. |

### Measurements

M1 to M5 come from `lsafacts` on 2026-11-12 over mem1_win11 (build 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Every number is a count, a length, a layout position or a match flag. No key, verifier, name or decrypted byte was printed or recorded.

| # | Measured |
|---|---|
| M1 | `Cache` reads on mem2, mem5 and mem6; on mem1 and mem7 the SECURITY root cell is paged out (S21 M1). On the three that read, `Cache` has 11 values: `NL$1` to `NL$10` and `NL$Control`. No `NL$IterationCount` value exists on any of them. |
| M2 | `NL$Control` is 8 bytes: u32 at +0 = 0x00010004 and u32 at +4 = 10 (3 of 3). `CachedLogonsCount` in the SOFTWARE hive is a REG_SZ "10" on all five captures, the D3 default. The slot count (10) equals `NL$Control` +4 and `CachedLogonsCount` on all three. |
| M3 | Every slot value is 168 bytes (30 of 30). All 30 are empty: the only non-zero 4-byte word is at +0x28, equal to 0x00010004, the same as `NL$Control` +0. Every other byte, including +0x40 to +0x60, is zero. 168 − 0x60 = 72 bytes follow the first 0x60. |
| M4 | The `NL$KM` secret's current and previous values are 64 bytes (mem5, 2 of 2; S21 M8). On mem2 and mem6 the secret does not read (S21 M1). |
| M5 | No used slot exists on any capture: no measurement of a used slot's header, ciphertext, plaintext or verifier was possible. |

## 4. Algorithm

### 4.1 Slots

1. Open `Cache` in the SECURITY hive. Absent: no rows. Unreadable: the run fails with the wrapped `registryhive` error.
2. List its values. An incomplete list raises a diagnostic; the slots that read are still used.
3. A slot is a value named `NL$` followed by decimal digits with no leading zero (M1). Other values (`NL$Control`, `NL$IterationCount`) are not slots.
4. A slot whose data does not read raises a diagnostic.
5. A slot is empty when every byte other than the revision word at +0x28..+0x2C is zero (M3). Empty slots give no row.
6. Every other slot is used and is decoded by 4.3. Slots are handled in slot-number order.

### 4.2 Cache key

Only when at least one used slot exists:

1. Get the system key (S20 4.1) and the policy key list (S21 4.1), and read the `NL$KM` secret object (S21 4.3).
2. Its current value must be present and at least 32 bytes (M4 gives 64). The cache key is bytes 16..32 of it (working layout W, section 10 O1).
3. Any failure fails the run with `ErrCacheKey` wrapping the cause: a slot cannot be decoded without it.

### 4.3 Used slot: working layout W

W is not measured (M5). Its offsets agree with the measured facts: the revision word at +0x28 (M3), a 0x60-byte header followed by an encrypted part (M3: 72 bytes follow 0x60 in an empty slot, the size of an encrypted part whose names are empty), and the field set of D1.

| Offset | Field | Type |
|---|---|---|
| +0x00 | EffectiveName length in bytes | u16 |
| +0x02 | LogonDomainName length in bytes | u16 |
| +0x10 | UserId | u32 |
| +0x28 | revision | u32 |
| +0x3C | DnsLogonDomainName length in bytes | u16 |
| +0x40 | IV | 16 bytes |
| +0x60 | encrypted part, to the end of the value | multiple of 16 bytes |

1. The slot must be at least 0x60 bytes plus one block, with the encrypted part a multiple of 16 (D5). Otherwise `ErrSlotLayout`.
2. The revision must be 0x00010004, the only one measured (M2, M3). Otherwise `ErrSlotRevision`.
3. Decrypt the encrypted part with AES-128-CBC under the cache key and the IV (D5).
4. In the plaintext, the verifier is bytes 0..16; the names begin at +72, in the order EffectiveName, LogonDomainName, DnsLogonDomainName, each starting at a multiple of 4.
5. Every name must fit inside the plaintext, EffectiveName must not be empty, each name length must be even, and each name must decode as UTF-16 (D6) with no NUL unit and no unpaired surrogate (a name holding U+FFFD is refused with them, since decoding turns an unpaired surrogate into U+FFFD). Otherwise `ErrSlotNames`. This is the check that a wrong key or a wrong layout fails: random bytes under a wrong key rarely pass it for a name of a few characters, but the check is weaker than a checksum (section 10 O2).

### 4.4 Iteration value

Read `Cache\NL$IterationCount` as a u32 when it is present and 4 bytes; report it unchanged in each row. Absent (M1) gives 0. Its encoding is not measured (section 10 O3).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Slot name `NL$<decimal>` | M1 | not a slot |
| Empty = zero apart from +0x28 | M3 (30 of 30) | treated as used and decoded |
| Used slot ≥ 0x70 bytes, encrypted part a multiple of 16 | W, D5 | `ErrSlotLayout`; diagnostic, no row |
| Revision 0x00010004 | M2, M3 | `ErrSlotRevision`; diagnostic, no row |
| `NL$KM` current value present, ≥ 32 bytes | M4, W | `ErrCacheKey`; the run fails |
| Names fit, EffectiveName non-empty, valid UTF-16 without NUL | D6, W | `ErrSlotNames`; diagnostic, no row |

## 6. Failure modes

| Case | Result |
|---|---|
| SECURITY hive absent | `Run` returns the wrapped `registryhive` error |
| `Cache` absent | no rows, no error |
| `Cache` unreadable | the wrapped `registryhive` error |
| value list incomplete | the slots that read; diagnostic `windows.credential.read_cached: cache key at 0x<addr>: values do not all read` |
| a slot unreadable or failing 4.3 | no row; diagnostic `windows.credential.read_cached: slot <name> at 0x<addr>: data does not read` or `windows.credential.read_cached: slot <name> at 0x<addr>: slot does not decode: <error>` (the address is the `Cache` key's) |
| used slots but no cache key | `ErrCacheKey` wrapping the S20 or S21 cause; the run fails |
| strict mode with any diagnostic raised by this tool | the run returns the rows and a non-nil error |

## 7. Result schema

`windows.credential.read_cached` row (`credentialcached.Entry`):

| Field | Type | Meaning |
|---|---|---|
| `Slot` | string | the value name, `NL$<n>` |
| `EffectiveName` | string | D1, D2: the account name |
| `LogonDomainName` | string | D1, D2: NetBIOS domain name |
| `DNSLogonDomainName` | string | D1 DnsLogonDomainName: FQDN of the account's domain; empty when its length is 0 |
| `UserID` | uint32 | D1, D2 UserId: the account RID |
| `Verifier` | []byte | the 16-byte password verifier |
| `IterationCount` | uint32 | the raw `NL$IterationCount` value; 0 when absent |

Rows are sorted by slot number. The names come from D1, spelt with Go initialisms (`UserID`, `DNS…`); they replace the prior fields `Username`, `Domain`, `DomainName`, `Hash` and `HashHex` (section 10, Owner decision).

## 8. Limits

None beyond `registryhive`. D3 caps the slot count at 50 by policy; the tool does not rely on it, since an image may hold any value list, and the hive walker already bounds it.

## 9. Acceptance

1. Synthetic fixtures (`credentialcached/*_test.go`), all with made-up names, keys and verifiers: a used slot sealed by the test from W (inverse of 4.3) decodes to the same names, RID and verifier; a slot under another cache key, a slot with another revision, a short or misaligned slot, and a slot whose name length runs past the plaintext are each rejected with their sentinel and a diagnostic; an empty slot shaped as M3 gives no row and no diagnostic; slot names `NL$Control`, `NL$IterationCount`, `NL$01` and `NL$x` are not slots; rows sort by slot number (`NL$2` before `NL$10`); with no used slot the run needs neither the system key nor `NL$KM`; with a used slot and no `NL$KM` the run fails with `ErrCacheKey`.
2. Fuzz target, 30 s: `FuzzDecodeSlot` (arbitrary slot bytes and cache key: no panic; a returned verifier is 16 bytes and every name fits the input).
3. On the captures, `lsafacts` 2026-11-12: the counts of M1 to M5. Expected tool result: mem2, mem5 and mem6 give 0 rows and no diagnostic (10 empty slots each); mem1 and mem7 fail with the unreadable-key error. `lsafacts -tools` runs the tool on all five captures and gives exactly these results; the tool raises no diagnostic of its own on any of them.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The used-slot working layout W (header offsets, the IV at +0x40, AES-128-CBC, the cache key at `NL$KM`[16:32], names from plaintext +72 at 4-byte alignment, the verifier at plaintext 0..16) has no vendor source and no measurement (M5). | A capture of a domain member with at least one cached logon by a known test account, measured with `lsafacts`; owner decision |
| O2 | The 16 bytes at +0x50 of a used slot are not read. If they are a checksum over the plaintext, checking it would replace the name check of 4.3 step 5 as the wrong-key test. `lsafacts` already tries HMAC-SHA1, HMAC-MD5 and HMAC-SHA-256 under `NL$KM` on any used slot it meets. | As O1 |
| O3 | The verifier's form and the meaning of `NL$IterationCount` are not measured. The tool reports the raw 16 bytes and the raw value; it neither computes nor checks a verifier from a password. | As O1, with the account's password; owner decision |
| O4 | Older slot revisions (the RC4-era form) are rejected with `ErrSlotRevision`: no capture holds one. | A capture of an older system with cached logons |
| O5 | Result field names `Slot`, `EffectiveName`, `LogonDomainName`, `DNSLogonDomainName`, `UserID`, `Verifier` and `IterationCount` replace `Username`, `Domain`, `DomainName`, `Hash` and `HashHex` (owner question Q2). | Owner decision on names |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Wait for a measured capture |
| O2 | Leave unread |
| O3 | Report raw only |
| O4 | Reject with ErrSlotRevision |
| O5 | Use Slot, EffectiveName and others |

## 11. Provenance

Written from [MS-NRPC], [MS-PAC], [MS-LSAD], [MS-DTYP], Microsoft Learn, FIPS 197, NIST SP 800-38A, S20, S21 and the project's own measurements on the captures through `registryhive`. Every rule rests on the sources and measurements above. The working layout W is the author's hypothesis, fitted to the measured empty-slot shape and the D1 field set; it is marked as unmeasured wherever it is used. No key, verifier or decrypted value was written to any file.
