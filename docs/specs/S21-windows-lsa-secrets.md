# S21: Windows LSA secret objects in the SECURITY hive

Version 1, 2026-11-12.

## 1. Purpose

The Local Security Authority keeps secret objects: named byte values that services, the machine account and the operating system store through the LSA policy ([MS-LSAD] "Secret Object Data Model"; Microsoft Learn "Storing Private Data"). On disk and in memory they live in the SECURITY registry hive under `Policy\Secrets\<name>`, encrypted. Each secret carries up to two values, the current one and the previous one, each with the time it was set. An examiner wants every secret's name, its type, both values in clear, and both set times: the values can include a service account's password, the machine account's password, or the key material that protects the domain logon cache (S22) and DPAPI.

The encryption rests on two keys Microsoft does not document: a list of policy keys stored in `Policy\PolEKList`, itself encrypted under the system key of S20. This specification defines how the policy key list is opened and checked, how each protected value is decrypted and checked, and how secrets become rows, so that a wrong key or damaged data is rejected rather than turned into a plausible value.

## 2. Inputs

| Input | Meaning |
|---|---|
| SYSTEM hive | Read through `registryhive`. Supplies the system key through `credentiallocal.SystemKey` (S20 4.1). |
| SECURITY hive | Read through `registryhive`. Supplies `Policy\PolEKList` and the `Policy\Secrets` subtree. |
| Options | The registered tool keeps the option keys it had: `strict`, `diagnostics`. No new options. |
| Limits | None beyond `registryhive`'s own; the secret set is bounded by the hive walker. |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | A secret object holds a Name, a Security Descriptor, a New Value with its New Set Time, and an Old Value with its Old Set Time. The server stores 0, 1 or 2 values: "current" and "previous". Both set times are 64-bit UTC timestamps in 100-nanosecond units since January 1, 1601. | [MS-LSAD] "Secret Object Data Model", accessed 2026-11-12. |
| D2 | Secret names are compared case-sensitively; a valid name has an even byte length greater than 0 and less than 0x101 and contains no `\`. | [MS-LSAD] "Secret Object Data Model", accessed 2026-11-12. |
| D3 | The secret type follows from the name: starts with `G$$` trusted domain; starts with `G$` global; starts with `L$` local; starts with `M$`, `_sc_` or `NL$` system; starts with `RasDialParams` or `RasCredentials` local; equal to `$MACHINE.ACC` system; equal to `SAC`, `SAI` or `SANSC` local. "Starts with" requires at least one character after the prefix. | [MS-LSAD] "Secret Object Data Model", accessed 2026-11-12. |
| D4 | `LsaStorePrivateData` stores private data as an encrypted value in the registry; the `L$`, `G$` and `M$` prefixes make local, global and machine objects, and machine objects can be read only by the operating system. | Microsoft Learn, "Storing Private Data", accessed 2026-11-12. |
| D5 | SHA-256 produces a 32-byte digest of a message of any length. | [FIPS 180-4] section 6.2, accessed 2026-11-12. |
| D6 | AES has a 16-byte block; a 32-byte key selects AES-256 (Nk = 8, Nr = 14). | [FIPS 197] sections 3 to 5, accessed 2026-11-12. |
| D7 | A FILETIME is a 64-bit count of 100-nanosecond intervals since January 1, 1601 (UTC). | [MS-DTYP] 2.3.3 "FILETIME", accessed 2026-11-12. |

Microsoft documents neither the registry encoding of a secret value nor the policy key list. Everything about them below is measured.

### Measurements

M1 to M8 come from `lsafacts` on 2026-11-12 over mem1_win11 (build 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Every number is a count, a length, a layout position or a match flag. No key, salt, identifier, value or decrypted byte was printed or recorded.

| # | Measured |
|---|---|
| M1 | Readability. mem1 and mem7: the SECURITY hive's root cell is in a paged-out prototype page, so no key under it reads. mem2 and mem6: `Policy` and `Policy\PolEKList` read, but the subkey list of `Policy\Secrets` is incomplete (0 subkeys read). mem5: every key reads; `Policy\Secrets` has 2 subkeys. The system key (S20) reads on all five. |
| M2 | `Policy\PolEKList` has a default value of 172 bytes on mem2, mem5 and mem6. `Policy\PolSecretEncryptionKey` is absent on all three. `Policy\PolRevision` is 4 bytes: u16 at +0 = 18, 14, 20 and u16 at +2 = 1 (mem2, mem5, mem6). |
| M3 | Protected value layout, the same in all 7 encrypted values read (3 `PolEKList`, 4 secret values on mem5): bytes +0..+3 are `00 00 00 01`; a 16-byte key identifier at +4; u32 at +20 = 3; u32 at +24 = 0; a 32-byte salt at +28; ciphertext from +60 to the end, a multiple of 16 bytes (112 for `PolEKList`, 64 and 96 for the secret values). |
| M4 | The AES-256 key for a protected value is SHA-256(K followed by the 32-byte salt repeated 1000 times), where K is the 16-byte system key for `PolEKList` and the 32-byte policy key for a secret value. Each 16-byte ciphertext block is decrypted on its own, with no chaining. Controls: with the salt once instead of 1000 times, 0 of 7 values pass the length check of M5; with CBC chaining from a zero IV, 0 of 3 key lists pass the M6 checks and 0 of 4 secret plaintexts equal the unchained ones; with one bit of the system key flipped, 0 of 3 key lists pass the length check. |
| M5 | Plaintext layout (7 of 7): u32 value length n at +0; u32 words at +4, +8, +12 all 0; the value at +16 for n bytes; then 4, 12 or 16 trailing bytes (`DPAPI_SYSTEM` 4, `PolEKList` 12, `NL$KM` 16), so 16 + n is at most the plaintext length and the excess is at most 16. The trailing bytes are zero for `PolEKList` and `DPAPI_SYSTEM`, not for `NL$KM`. |
| M6 | Policy key list (the `PolEKList` value, 84 bytes, 3 of 3): u32 at +0 = 3; the current key identifier, 16 bytes at +4; u32 at +20 = 3; u32 entry count at +24 = 1; then entries of {16-byte key identifier, u32 type = 3, u32 key length = 32, key}. The one entry ends exactly at 84 and its identifier equals the current key identifier (3 of 3). The identifier in the `PolEKList` protected-value header (M3 +4) is not zero and differs from the current key identifier (3 of 3). |
| M7 | Secrets on mem5: `DPAPI_SYSTEM` and `NL$KM`. Each secret key has the subkeys `CurrVal`, `OldVal`, `CupdTime`, `OupdTime` and `SecDesc`, each holding its data in the default value. All 4 `CurrVal`/`OldVal` values name the current policy key in their header (M3 +4). All 4 `CupdTime`/`OupdTime` values are 8 bytes and decode as FILETIMEs in 2025. |
| M8 | Structure of the decrypted values on mem5: `DPAPI_SYSTEM` current and previous values are 44 bytes and begin with u32 1 (2 of 2); `NL$KM` current and previous values are 64 bytes (2 of 2). |

## 4. Algorithm

### 4.1 Policy key list

1. Get the system key from the SYSTEM hive with `credentiallocal.SystemKey` (S20 4.1). Failure is `credentiallocal.ErrSystemKey`.
2. Open `Policy\PolEKList` in the SECURITY hive and read its default value (M2).
   - The key or value is absent: if `Policy\PolSecretEncryptionKey` exists, the hive uses the older policy key form, which no capture holds (section 10); fail with `ErrLegacyPolicyKey`. Otherwise fail with `ErrPolicyKeyAbsent`.
   - The key or value does not read (M1): fail with `ErrPolicyKeyUnreadable`.
3. Open the value as a protected value under the system key (4.2). Any failure is `ErrPolicyKey`.
4. Parse the plaintext value as a key list (M6): the current identifier at +4, the count at +24, entries from +28. Each entry must fit inside the list. The entry whose identifier equals the current identifier must exist and hold a 32-byte key (D6, M6). Keep every entry, keyed by identifier, so a secret written under an earlier key can still be read. A failed check is `ErrPolicyKey`.

### 4.2 Protected value

1. The value must be at least 60 bytes, with a ciphertext of at least one whole 16-byte block (M3, D6). Otherwise `ErrProtectedValue`.
2. Bytes +0..+3 must be `00 00 00 01` and the u32 at +20 must be 3 (M3). Otherwise `ErrProtectedScheme`: the scheme was not measured.
3. Choose K: the system key for `PolEKList`; for a secret value, the policy key whose identifier equals the header identifier at +4 (M7). No such key is `ErrUnknownPolicyKey`.
4. AES key = SHA-256(K, then the salt at +28..+60 repeated 1000 times) (M4, D5).
5. Decrypt each 16-byte block of the ciphertext with AES-256 on its own (M4, D6).
6. Read n at +0 of the plaintext. Require 16 + n ≤ plaintext length and plaintext length − 16 − n ≤ 16 (M5). Otherwise `ErrProtectedValue`: under a wrong key the length word is random, so this rejects it with high probability.
7. The value is plaintext[16 : 16+n].

### 4.3 Secret objects

1. Open `Policy\Secrets` and list its subkeys. An incomplete list (M1) raises a diagnostic; the secrets that did read are still reported.
2. For each subkey, the secret name is the key name. Its type follows D3; a name that matches no pattern there, or is only a reserved prefix, is `unlisted`. The D3 table gives `_sc_` in lower case; it is matched without regard to case (section 10 O7).
3. Read the default value of `CurrVal` and `OldVal` (M7). Each becomes a value with a state:
   - subkey or default value absent, or 0 bytes: `absent` (D1 allows 0, 1 or 2 values);
   - present but its data does not read: `unreadable`, with a diagnostic;
   - read but 4.2 fails: `undecryptable`, with a diagnostic naming the 4.2 error;
   - otherwise `present`, with the decrypted bytes.
4. Read the default value of `CupdTime` and `OupdTime` (M7). An 8-byte value is a FILETIME (D1, D7); 0 or a value outside the FILETIME range is no time. An unreadable value or any other length raises a diagnostic and gives no time.
5. Sort the rows by name, comparing bytes (D2 makes names case-sensitive).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Protected value ≥ 60 bytes, ciphertext a non-zero multiple of 16 | M3, D6 | `ErrProtectedValue` |
| Header bytes `00 00 00 01`, u32 at +20 = 3 | M3 (7 of 7) | `ErrProtectedScheme` |
| 16 + n ≤ plaintext length ≤ 32 + n | M5 (7 of 7), M4 controls | `ErrProtectedValue` |
| Key list entries fit; current identifier names an entry with a 32-byte key | M6 (3 of 3), D6 | `ErrPolicyKey`; the run fails |
| A secret value's key identifier is in the key list | M7 (4 of 4) | `ErrUnknownPolicyKey`; that value is `undecryptable` |
| Set time is 8 bytes | M7, D1 | no time, diagnostic |

Not enforced, though constant on every capture: the zero words at plaintext +4..+16 (M5), the key list words at +0 and +20 and the entry type (M6), and the zero word at header +24 (M3). They have no documented meaning, and rejecting on them would add no protection the length check and the key identifier do not already give.

## 6. Failure modes

| Case | Result |
|---|---|
| SYSTEM or SECURITY hive absent | `Run` returns the wrapped `registryhive` error |
| System key missing | `credentiallocal.ErrSystemKey`; the run fails |
| `PolEKList` absent, unreadable, older form, or failing 4.1 | `ErrPolicyKeyAbsent`, `ErrPolicyKeyUnreadable`, `ErrLegacyPolicyKey` or `ErrPolicyKey`; the run fails (a false policy key would decrypt nothing true) |
| `Policy\Secrets` absent | no rows, no error |
| `Policy\Secrets` unreadable or incomplete | the secrets that read; diagnostic `windows.credential.read_lsa_secrets: secret list at 0x<addr>: subkeys do not all read`, or `windows.credential.read_lsa_secrets: secret list: key does not read: <error>` when the key itself does not open |
| One value unreadable or undecryptable | its state says so; diagnostic `windows.credential.read_lsa_secrets: secret "<name>" at 0x<addr>: <current or old> value does not read` (unreadable) or `windows.credential.read_lsa_secrets: secret "<name>" at 0x<addr>: <current or old> value does not decrypt: <error>` (undecryptable) |
| A set time unreadable or not 8 bytes | no time; diagnostic `windows.credential.read_lsa_secrets: secret "<name>" at 0x<addr>: <CupdTime or OupdTime> is not an 8-byte time` |
| A secret subkey whose name does not read | no row; diagnostic `windows.credential.read_lsa_secrets: secret at 0x<addr>: name does not read` |
| strict mode with any diagnostic raised by this tool | the run returns the rows and a non-nil error |

## 7. Result schema

`windows.credential.read_lsa_secrets` row (`credentiallsasecrets.Entry`):

| Field | Type | Meaning |
|---|---|---|
| `Name` | string | the secret name (D1) |
| `Type` | `SecretType` | `trusted_domain`, `global`, `local`, `system` or `unlisted` (D3) |
| `CurrentValue` | []byte | the decrypted current value; nil unless `CurrentValueState` is `present` |
| `CurrentValueState` | `ValueState` | `present`, `absent`, `unreadable` or `undecryptable` |
| `CurrentValueSetTime` | time.Time | UTC; the zero time when absent |
| `OldValue`, `OldValueState`, `OldValueSetTime` | as above | the previous value (D1 "Old Value", "Old Set Time") |

Rows are sorted by `Name` in byte order. The names follow D1's "current/previous value" and "set time" vocabulary; they replace the prior fields `Secret` and `Hex` (section 10, Owner decision).

Exports for S22: `ReadKeyList(SecurityHive, systemKey) (KeyList, error)` (4.1) and `ReadSecretObject(SecurityHive, KeyList, name) (Entry, error)` (4.3 for one name; an empty name or one holding `\` is `ErrSecretName`, per D2). `SecurityHive` is the three-method hive interface `registryhive.HiveLayer` satisfies.

## 8. Limits

None beyond `registryhive`. The secret set is bounded by the hive walker; each value by `MaxBufferBytes` there. The 1000-fold salt hashing costs 32 KB of SHA-256 input per value, which is negligible.

## 9. Acceptance

1. Synthetic fixtures (`credentiallsasecrets/*_test.go`), all with made-up keys and values: a protected value sealed by the test from the spec (inverse of 4.2) opens to the same bytes; a wrong key and a one-repetition derivation are rejected, and a value sealed with chaining does not reproduce its bytes; an excess of more than 16 bytes is rejected; a short, misaligned or other-scheme value is rejected with its sentinel; a key list with two entries resolves both identifiers; a key list whose current identifier has no entry, or a 16-byte key, is rejected; a fake SECURITY hive with secrets of every state (present, absent, unreadable, undecryptable, unknown key) gives the expected rows, states, times, types and diagnostics, sorted by name; `PolEKList` absent, absent with `PolSecretEncryptionKey`, and unreadable give their sentinels; the D3 table in full, including bare prefixes.
2. Fuzz targets, 30 s each: `FuzzOpenProtectedValue` (arbitrary bytes and key: no panic; a returned value never exceeds the input); `FuzzParseKeyList` (arbitrary plaintext: no panic; a returned current key is 32 bytes).
3. On the captures, `lsafacts` 2026-11-12: the counts of M1 to M8. Ground truth on mem5: 2 secrets, `DPAPI_SYSTEM` (44-byte values beginning with u32 1) and `NL$KM` (64-byte values), each with both values present and both set times; mem2 and mem6 open the policy key list and report an incomplete secret list; mem1 and mem7 fail with `ErrPolicyKeyUnreadable`. `lsafacts -tools` runs the tool on all five captures and gives exactly these results: mem5 2 rows with all four values `present` and all four set times; mem2 and mem6 0 rows and the incomplete-list diagnostic; mem1 and mem7 the unreadable error.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The protected-value layout, the 1000-fold SHA-256 derivation, the unchained AES-256 decryption, the plaintext layout and the key-list layout rest on measurement only (M3 to M6); no vendor source states them. | Owner decision on measured layouts (Q3) |
| O2 | The older policy key form (`PolSecretEncryptionKey`, before `PolEKList`) is not read: no capture holds it. The tool fails with `ErrLegacyPolicyKey` rather than guess. | A capture of a system that predates `PolEKList`; owner decision |
| O3 | Only one key-list entry was ever seen (M6). Several entries are supported by identifier, but untested on a capture. | A capture whose policy key was rotated |
| O4 | Result field names: `Secret` and `Hex` are replaced by `CurrentValue`/`CurrentValueState`/`CurrentValueSetTime` and the matching `Old…` fields, and `Type` is new; `Name` is kept (owner question Q2). The four prior exported helper functions, their hive interface and the prior unsupported-scheme sentinel are removed; `ReadKeyList`, `ReadSecretObject`, `KeyList`, `SecurityHive` and the sentinels of section 6 replace them. | Owner decision on names |
| O5 | The meaning of the constant words (header +0..+3 and +20, key list +0 and +20, entry type, `PolRevision`) is unknown; they are recorded, and only the header words are enforced. | Owner decision |
| O6 | Only mem5 yields secrets; mem2 and mem6 lose `Policy\Secrets` to paging (M1). The secret-object path is therefore measured on one capture, two secrets, four values. | More captures with a resident SECURITY hive |
| O7 | `_sc_` is matched without case although D2 makes names case-sensitive: the D3 table spells the prefix in lower case only, and no capture holds a service secret to show the spelling Windows writes. Every other pattern is matched exactly. | Owner decision; a capture with a service secret |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the measured layouts |
| O2 | Fail with ErrLegacyPolicyKey |
| O3 | Ship as written, mark untested |
| O4 | Use CurrentValue and Old fields |
| O5 | Record all, enforce header words |
| O6 | Keep one-capture measurement |
| O7 | Match without case |

## 11. Provenance

Written from [MS-LSAD], Microsoft Learn ("Storing Private Data"), [MS-DTYP], FIPS 180-4, FIPS 197 and the project's own measurements on the captures through `registryhive` and the S20 system key. Every rule rests on the sources and measurements above. No secret, key or decrypted value was written to any file.
