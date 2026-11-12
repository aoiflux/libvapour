# S20: Windows local account password hashes and the system key

Version 1, 2026-11-12.

## 1. Purpose

A stand-alone Windows computer keeps each local account's password verifiers in the SAM registry hive, under `SAM\Domains\Account\Users\<RID>`. The verifiers are the NT one-way function of the password (MS-NLMP NTOWFv1) and, on older systems, the LM one-way function (LMOWFv1). They are stored twice-wrapped: an account-specific DES layer keyed from the account's RID (MS-SAMR section 2.2.11.1), inside a hive-wide layer keyed from a "system key" assembled from four class names in the SYSTEM hive. An examiner wants each account's RID, name and recovered NT and LM hashes, so the hashes can be matched against a wordlist or a known-good value offline.

Every byte on the way comes from a captured image and can be stale or absent. This specification defines how the system key is assembled, how the hive-wide key is unwrapped and checked, how the per-account V record is parsed, and how each hash is unwrapped, so that a wrong key or a truncated record is rejected rather than turned into a plausible-looking but false hash.

## 2. Inputs

| Input | Meaning |
|---|---|
| SYSTEM hive | Read through `registryhive`. Supplies the system key parts and the active control set. |
| SAM hive | Read through `registryhive`. Supplies the domain `F` value and per-account `V` values. |
| Options | The registered tool keeps the option keys it had: `strict`, `diagnostics`, `pid` (unused here). No new options. |
| Limits | None beyond `registryhive`'s own; the account set is small and bounded by the hive. |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | To encrypt a 16-byte NT or LM hash with a specified key: split it into Block1 (bytes 0..7) and Block2 (bytes 8..15); derive two 7-byte keys Key1, Key2; encrypt each block with DES-ECB under its key; the result is the concatenation. | [MS-SAMR] 2.2.11.1.1 "Encrypting an NT or LM Hash Value with a Specified Key", accessed 2026-11-12. |
| D2 | From a little-endian unsigned integer I (bytes I[0..3], I[0] least significant): Key1 = I[0],I[1],I[2],I[3],I[0],I[1],I[2]; Key2 = I[3],I[0],I[1],I[2],I[3],I[0],I[1]. | [MS-SAMR] 2.2.11.1.3 "Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key", accessed 2026-11-12. |
| D3 | A 7-byte key is expanded to 8 bytes by inserting a zero bit after every seventh bit; the exact per-byte assignment is given, followed by a left shift of one bit per byte, and the least-significant bit of each byte is a parity bit (set so each byte has odd parity). The 8-byte key is used with DES per [FIPS81]. | [MS-SAMR] 2.2.11.1.2 "Encrypting a 64-Bit Block with a 7-Byte Key", accessed 2026-11-12. |
| D4 | NTOWFv1(Passwd, User, UserDom) = MD4(UNICODE(Passwd)). LMOWFv1 = ConcatenationOf(DES(UpperCase(Passwd)[0..6], "KGS!@#$%"), DES(UpperCase(Passwd)[7..13], "KGS!@#$%")); it cannot be computed for passwords longer than 14 characters, and a shorter password is padded with zero bytes. | [MS-NLMP] 3.3.1 "NTLM v1 Authentication", accessed 2026-11-12. |
| D5 | UNICODE(string) is the 2-byte little-endian UTF-16 encoding, no byte-order mark. DES(K, D) is DES-ECB of the 8-byte D under the 7-byte K ([FIPS46-2]). MD4(M) is the MD4 digest ([RFC1320]). MD5(M) is the MD5 digest ([RFC1321]). | [MS-NLMP] Appendix A "Cryptographic Operations Reference", accessed 2026-11-12. |
| D6 | DOMAIN_USER_RID_ADMIN = 0x000001F4 (500 decimal), the built-in Administrator account. | [MS-SAMR] 2.2.1.14 "Predefined RIDs", accessed 2026-11-12. |
| D7 | MD4: four 32-bit words A=0x67452301, B=0xefcdab89, C=0xfe dc ba 98=0x98badcfe, D=0x10325476; message padded with a 1 bit then zeros to 448 mod 512, then the 64-bit bit-length little-endian; three rounds of 16 operations with additive constants 0, 0x5A827999, 0x6ED9EBA1 and the stated rotations and word orders. | [RFC1320] "MD4 Message-Digest Algorithm", April 1992, accessed 2026-11-12. |
| D8 | The LM hash is weaker than the NT hash; on current Windows the policy "do not store LAN Manager hash value on next password change" is effective by default, so a current account has no stored LM hash. | Microsoft Learn, "Network security: Do not store LAN Manager hash value on next password change", accessed 2026-11-12. |

### Measurements

M1 to M7 come from `samfacts` on 2026-11-12 over mem1_win11 (build 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Every number is a count, a layout or a match flag. No key, salt or hash byte was printed or recorded.

| # | Measured |
|---|---|
| M1 | In `SYSTEM\<CurrentControlSet>\Control\Lsa` the four subkeys `JD`, `Skew1`, `GBG`, `Data` each carry a class name of 8 hexadecimal characters (16 bytes UTF-16), in all four captures that read the hive. No other Lsa subkey carries one. The 16 bytes decode to four 4-byte groups, 16 bytes of key material in all. mem7's SAM did not read (paged out); the Lsa classes still read. |
| M2 | The system key is the 16 scrambled bytes reordered by the fixed permutation P = [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7] (output byte i = scrambled byte P[i]), with the four groups concatenated in the order `JD`, `Skew1`, `GBG`, `Data`. Control: of the 23 other orders of the four names, 0 produce a hive key whose check passes; of 1000 random permutations, 0 pass; the identity permutation fails. Measured on mem1, mem2, mem5, mem6. |
| M3 | The SAM domain key sits in the `F` value of `SAM\Domains\Account`, `F` being 368 bytes. A key block begins at `F`+0x68: u32 revision at +0x68 (value 2 on all four), u32 length at +0x6C (0x70), u32 checksum length at +0x70 (0x30), u32 data length at +0x74 (0x20), then a 16-byte salt at +0x78, 0x20 encrypted bytes at +0x88, and 0x30 checksum bytes at +0xA8. |
| M4 | Revision 2 is AES. The domain key = AES-128-CBC-decrypt(system key, IV = the 16-byte salt, the 0x20 encrypted bytes); the first 16 bytes are the key and the trailing 16 are 0x10 padding (PKCS#7, value 16) on all four. The checksum block = AES-128-CBC(system key, IV = salt, SHA-256(domain key) followed by 0x10 padding); decrypting it under the salt reproduces SHA-256(domain key) and the padding on all four. The chained-IV variant (IV = the preceding block) does not. |
| M5 | Each account key `SAM\Domains\Account\Users\<RID>` has a `V` value beginning with a table of 12-byte entries {u32 offset, u32 length, u32 unused}, offsets relative to `V`+0xCC. Entry 1 is the account name (verified: entry 1's bytes equal the `Names\<name>` subkey for every account on every capture). Entry 13 is the LM hash record; entry 14 is the NT hash record. |
| M6 | An AES hash record is: u16 at +0 (2, or 3 on mem2), u16 revision at +2 (2 on all), u32 plaintext length at +4 (0x10 when a hash is present), a 16-byte IV at +8, then 0x20 encrypted bytes; total length 0x38. A record of length 0x18 carries the header only and no hash (plaintext length 0). The stored hash = DES-unwrap-by-RID(AES-128-CBC-decrypt(domain key, IV, the 0x20 bytes)[0..15]), where the DES unwrap is the inverse of D1/D2/D3 under the account's RID. |
| M7 | NT hash records with a hash present: mem1 1, mem2 2, mem5 1, mem6 2. No account on any capture stores an LM hash (entry 13 is always the empty 0x18 record), consistent with D8. No recovered NT hash equals NTOWFv1 of the empty password. On the two owner lab captures (mem5, mem6) the NT hash recovered for RID 500 equals NTOWFv1 of the owner's known lab credential; both match. mem1 and mem2 are not lab machines and have no known credential. |

### Not measured

RC4-era records (revision 1), used before the Windows 10 generation, were not present in any available capture: all four read captures are AES (revision 2). The revision-1 system-key unwrap (MD5 of salt and two constant strings, then RC4) and the revision-1 hash record (RC4 under MD5(domain key, RID, a per-type constant string), then the RID DES unwrap) are implemented from the published SYSKEY/SAM encryption algorithm, which has no vendor specification. They are flagged in section 10 and exercised only by a synthetic self-consistent fixture.

## 4. Algorithm

### 4.1 System key

1. Open the SYSTEM hive; read its active control set from `Select\Current` (via `registryhive`).
2. Under `<set>\Control\Lsa`, read the class name of each of `JD`, `Skew1`, `GBG`, `Data` (M1). Each must be 16 bytes that decode as 8 hex characters to 4 bytes; a missing or malformed one fails the whole read.
3. Concatenate the four 4-byte groups in the order `JD`, `Skew1`, `GBG`, `Data` into a 16-byte scrambled value, then reorder by P (M2) to get the 16-byte system key.

### 4.2 Domain key

1. Open the SAM hive; read the `F` value of `SAM\Domains\Account` (M3). It must hold the revision at `F`+0x68. A revision 2 block needs `F` to be at least 0xD8 bytes; a revision 1 block needs at least 0x8C bytes.
2. Read the revision at `F`+0x68. Any revision other than 1 or 2 fails the read.
3. Revision 2 (AES, M4): salt = `F`[0x78:0x88]; the domain key is the first 16 bytes of AES-128-CBC-decrypt(system key, salt, `F`[0x88:0xA8]). Validity: the 16 trailing bytes are 0x10 padding, and AES-128-CBC-decrypt(system key, salt, `F`[0xA8:0xD8]) begins with SHA-256 of the domain key. A failure of either check fails the read (wrong system key or stale `F`).
4. Revision 1 (RC4, section 3 "Not measured"): the domain key is recovered from the salt and the two constant strings by MD5 and RC4; there is no checksum, so the key is accepted and the per-record checks carry the validation.

### 4.3 Accounts

1. Enumerate the subkeys of `SAM\Domains\Account\Users`. A subkey whose name parses as a hexadecimal 32-bit value is an account; its RID is that value. `Names` does not parse and is skipped.
2. For each account, read its `V` value and its name from table entry 1 (M5). An unreadable `V` yields a row with the hashes marked unreadable.
3. Parse the hash records at entries 13 (LM) and 14 (NT) (M5, M6).

### 4.4 Hash record

For a record of revision 2 (AES, M6):

1. A record shorter than 8 bytes holds no hash; the field is empty, not unreadable. Otherwise read the u16 revision at +2. For revision 2, read the u32 plaintext length at +4: a length of 0 means no hash is stored, and the field is empty. A nonzero length in a record shorter than 0x38 bytes makes the field unreadable. A table entry that does not fit `V`, or a revision other than 1 or 2, also makes the field unreadable.
2. IV = record[8:24]; the 0x20 encrypted bytes = record[24:56].
3. plaintext = AES-128-CBC-decrypt(domain key, IV, encrypted); take plaintext[0:16].
4. hash = DES-unwrap-by-RID(plaintext[0:16]): derive Key1, Key2 from the RID (D2), expand each to 8 bytes (D3), DES-ECB-**decrypt** block 0 under Key1 and block 1 under Key2 (the inverse of D1). This undoes the account layer.

For a record of revision 1 (RC4, section 3 "Not measured"): rc4key = MD5(domain key[0:16] || RID (4 bytes, little-endian) || per-type constant string); decrypt the 16 encrypted bytes at record+4 with RC4; then apply the same RID DES unwrap of step 4. A revision 1 record shorter than 20 bytes holds no hash, and the field is empty.

### 4.5 Rows

Each account becomes one `Entry`: `User`, `RID`, `LMHash` and `NTHash` as lowercase hex strings (empty when no hash is stored), and `LMUnreadable`/`NTUnreadable` when the record could not be read. Rows are sorted by RID.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Each Lsa class name is 8 hex characters | M1 | `ErrSystemKey`; the run fails |
| `F` long enough for its revision (0xD8 bytes for AES), revision known | M3 | `ErrDomainKey`; the run fails |
| AES domain key: trailing 0x10 padding and SHA-256 checksum match | M4 | `ErrDomainKey`; the run fails (wrong key or stale `F`) |
| A present AES record is at least 0x38 bytes with a 0x20 cipher block | M6 | field unreadable, diagnostic |
| Ciphertext length a whole number of AES blocks | FIPS 197 | `ErrCipherInput`; field unreadable |

## 6. Failure modes

| Case | Result |
|---|---|
| SYSTEM or SAM hive absent | `Run` returns the wrapped `registryhive` error |
| Lsa classes missing | `ErrSystemKey`; the run fails |
| `F` absent, short, or its key check fails | `ErrDomainKey`; the run fails (a false domain key would forge every hash) |
| `V` unreadable for one account | one row with `NTUnreadable`/`LMUnreadable` set; diagnostic `windows.credential.read_local: account <rid>: V value does not read` |
| A hash record that does not decrypt (too short, unknown revision, entry outside `V`) | the hash field is empty and `NTUnreadable` or `LMUnreadable` is set; diagnostic `windows.credential.read_local: account <rid>: hash record at entry <n> does not decrypt` |
| `Users` key unreadable | no rows; diagnostic `windows.credential.read_local: Users key does not read: <error>` |
| strict mode with any diagnostic raised | the run returns the rows and a non-nil error |

## 7. Result schema

`windows.credential.read_local` row (`credentiallocal.Entry`): `User` (string), `RID` (uint32), `LMHash` (string, lowercase hex or empty), `NTHash` (string, lowercase hex or empty), `LMUnreadable` (bool), `NTUnreadable` (bool). Rows are sorted by RID. "LM hash" and "NT hash" are MS-NLMP terms; the field names are kept from the prior API to keep callers compiling (section 10, Owner decision).

## 8. Limits

None beyond `registryhive`. The account set is bounded by the Users subkey count, which the hive walker already caps.

## 9. Acceptance

1. Synthetic fixtures (`credentiallocal/*_test.go`): the MD4 test vectors of RFC 1320 (D7); NTOWFv1 and LMOWFv1 of the MS-SAMR section 4.3 worked example (the "OLDPASSWORD"/"NEWPASSWORD" documentation vectors, D4); LMOWFv1 refusing a password longer than 14 characters or not ASCII; the MS-SAMR section 4.3 vector for the 7-to-8-byte DES key expansion (D3); a RID wrap and unwrap round trip (D1, D2); a round-trip of the AES domain-key unwrap and an AES hash record built by the test from a known system key, RID and NT hash, decrypted back to the same hash; the empty-record path; the wrong-system-key rejection; account enumeration and sorting through a fake hive. No fixture uses a real password or a captured hash.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzMD4` (digest never panics, always 16 bytes; cross-checked against `golang.org/x/crypto/md4` is out of scope as the dependency is absent, so the oracle is the RFC vectors); `FuzzParseV` (arbitrary `V` bytes: the parser never panics and never reads out of range); `FuzzDecodeDomainKey` (arbitrary `F` bytes and system key: no panic, a returned key is 16 bytes).
3. On the captures, `samfacts` 2026-11-12: the counts of M1 to M7 above; RID 500 on mem5 and mem6 matches NTOWFv1 of the owner's known lab credential (match flag only, no value); mem7 fails `ErrDomainKey` cleanly because its `F` is paged out.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The system-key class-name order, the permutation P, the `F` key-block layout, the AES checksum construction, and the V entry indices 1/13/14 rest on measurement only; no vendor source states them (M1 to M6). | Owner decision on measured constants |
| O2 | RC4-era (revision 1) system-key and hash-record unwrapping could not be measured (no pre-Windows-10 capture read). It is implemented from the published SYSKEY algorithm and its two constant strings, which have no vendor specification. | Owner decision; a revision-1 capture |
| O3 | Result field names `User`, `RID`, `LMHash`, `NTHash`, `LMUnreadable`, `NTUnreadable` are kept from the prior API rather than renamed to the spec's own vocabulary, to keep existing callers compiling (owner question Q2). | Owner decision on field names |
| O4 | Multiple domain keys (PEKID > 0 in the V record header, seen as 3 on mem2) are not selected among; the single `F` key block decrypts every record on the captures. | A capture with more than one domain key |
| O5 | `hashFromRecord` (`tools/windows/credentiallocal/vrecord.go`) makes the field unreadable for a revision 2 record with a nonzero length that is shorter than 0x38 bytes (4.4 step 1). No test pins this reading: the tests cover a full record and a record of length 0, not a short one with a nonzero length. Owner decision 2026-11-12: kept for v0.1.0; a test that pins it in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the measured constants |
| O2 | Keep, from published algorithm |
| O3 | Keep User, RID, LMHash, NTHash |
| O4 | Keep the single key block |

## 11. Provenance

Written from [MS-SAMR], [MS-NLMP], RFC 1320, FIPS 197, FIPS 46-3 / SP 800-67, Microsoft Learn, and the project's own measurements on the captures through `registryhive`. Every rule rests on the sources and measurements above. The owner's lab credential was used only inside the measurement run to confirm the RID 500 recovery; it is recorded nowhere.
