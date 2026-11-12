# S45: Windows process token SIDs and privileges

Version 1, 2026-11-12.

## 1. Purpose

Every Windows process runs under an access token. The token says whom the process acts for (the token user), which groups it counts as a member of, which SIDs a restricted token is limited to, which capabilities an app container holds, and which privileges it has and has turned on. An examiner wants, per process, each SID in the token as a string with what Windows calls it, its attributes, and each privilege with its present, enabled and enabled-by-default state. A process running as SYSTEM inside a user's session, a medium-integrity token holding `SeDebugPrivilege` enabled, or a service SID in a process that is not that service are the findings this listing makes visible.

The token is reached through a pointer in `_EPROCESS`, and every count and pointer in it comes from the image. A token freed and reused, or a smeared page, gives counts in the hundreds of millions and pointers into nothing. This specification defines the checks on the token, on each SID, and on the privilege masks, and where each SID's name comes from.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads. Tokens and SIDs live in system space. |
| Symbol table | The kernel types of section 3 (T1 to T4). |
| Processes | `processlist.Run` on the session without its PID filter; the `pid` option then selects the processes listed. |
| Registry hives | SYSTEM, SAM and SOFTWARE, opened through `registryhive.OpenHive` with `registryhive.CellReader`, for names only. |
| Options | `pid`, `strict`, `diagnostics` (session options). No tool option. |
| Limits | `MaxRowsPerObject`: the SIDs read from one token array. |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | A SID in packet form is `Revision` (1 byte, "MUST be set to 0x01"), `SubAuthorityCount` (1 byte, "The maximum number of elements allowed is 15"), `IdentifierAuthority` (6 bytes) and `SubAuthority`, an array of `SubAuthorityCount` unsigned 32-bit integers. | [MS-DTYP] 2.4.2.2 "SID--Packet Representation", last updated 2023-12-12, accessed 2026-11-12. |
| D2 | `SID_IDENTIFIER_AUTHORITY` is six 8-bit values; the authority {0,0,0,0,0,5} is the NT authority, so the value reads most significant byte first. | [MS-DTYP] 2.4.1 "SID_IDENTIFIER_AUTHORITY", accessed 2026-11-12. |
| D3 | String form: `"S-1-" IdentifierAuthority 1*SubAuthority`; the authority is decimal below 2^32 and otherwise `"0x"` and 12 hexadecimal digits; each `SubAuthority` is `"-"` and a decimal number with no leading zeros. | [MS-DTYP] 2.4.2.1 "SID String Format Syntax", last updated 2023-12-12, accessed 2026-11-12. |
| D4 | "The last item in the series of SubAuthority values is known as the relative identifier (RID)." A newly created account store is assigned a 96-bit identifier (three sub-authorities after 21). | [MS-DTYP] 2.4.2 "SID", last updated 2024-10-30; 2.4.2.4 "Well-Known SID Structures" (the `S-1-5-21-<domain>-RID` example), accessed 2026-11-12. |
| D5 | The well-known SID table: 113 rows, each a constant and a SID or a SID pattern (`S-1-5-5-x-y` for a logon session, `S-1-5-21-<domain>-RID` and `-<machine>-`, `-<root domain>-` for domain-relative RIDs, `S-1-5-80-<service>`, `S-1-5-83-1-dd-dd-dd-dd`). | [MS-DTYP] 2.4.2.4 "Well-Known SID Structures", last updated 2023-08-28 (page metadata updated_at 2024-11-20), accessed 2026-11-12. |
| D6 | The Win32 well-known SID page lists the authorities S-1-0, -1, -2, -3, -5, the universal RIDs, the SECURITY_NT_AUTHORITY RIDs (S-1-5-1 to -33, -99), the domain RIDs (0x1F2 to 0x211, 0x229, 0x23E), the mandatory integrity RIDs (S-1-16-0 to -20480) and the builtin aliases S-1-5-32-544 to -585. | Microsoft Learn, "Well-known SIDs" (secauthz), ms.date 2024-11-25, accessed 2026-11-12. |
| D7 | A service SID: convert the service name to upper case UTF-16, take its SHA-1 hash, Hash[0] to Hash[4] are its five 4-byte words "as an unsigned integer", and the SID is `S-1-5-80-hash[0]-hash[1]-hash[2]-hash[3]-hash[4]`. The domain is named "NT SERVICE" and the principal is the service name. Example: `ALG` is `S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773`. The service name is the ServiceName of [MS-SCMR] 3.1.1. | [MS-LSAT] 3.1.1.1.2 "Configurable Translation Database and Corresponding View", last updated 2024-05-01, accessed 2026-11-12. |
| D8 | `TOKEN_GROUPS` holds `SID_AND_ATTRIBUTES` entries. Group attributes: `SE_GROUP_MANDATORY` 0x1, `_ENABLED_BY_DEFAULT` 0x2, `_ENABLED` 0x4, `_OWNER` 0x8, `_USE_FOR_DENY_ONLY` 0x10, `_INTEGRITY` 0x20, `_INTEGRITY_ENABLED` 0x40, `_RESOURCE` 0x20000000, `_LOGON_ID` 0xC0000000. | Microsoft Learn, "TOKEN_GROUPS (winnt.h)", ms.date 2018-12-05, last updated 2022-09-01, accessed 2026-11-12. |
| D9 | Privilege attributes in `TOKEN_PRIVILEGES`: `SE_PRIVILEGE_ENABLED` ("The privilege is enabled"), `SE_PRIVILEGE_ENABLED_BY_DEFAULT` ("The privilege is enabled by default"), `SE_PRIVILEGE_REMOVED`, `SE_PRIVILEGE_USED_FOR_ACCESS`. | Microsoft Learn, "TOKEN_PRIVILEGES (winnt.h)", ms.date 2018-12-05, last updated 2024-02-22, accessed 2026-11-12. |
| D10 | The privilege names and LUIDs: 35 rows from `SE_CREATE_TOKEN_NAME` "SeCreateTokenPrivilege" {0,2} to `SE_CREATE_SYMBOLIC_LINK_NAME` {0,35}, each with a description. `SE_SYSTEM_ENVIRONMENT_NAME` is written "SeSystemEnvironment". Requests SHOULD keep Luid.LowPart at 35 or below. | [MS-LSAD] 3.1.1.2.1 "Privilege Data Model" and 3.1.4.10 "Data Validation", page metadata updated_at 2025-06-10, accessed 2026-11-12. |
| D11 | The privilege constants: 36 constants, each a `TEXT("Se…Privilege")` string and its user right, including `SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME` "SeDelegateSessionUserImpersonatePrivilege" (user right "Impersonate other users") and `SE_UNSOLICITED_INPUT_NAME` (user right "Not applicable"); `SE_SYSTEM_ENVIRONMENT_NAME` is "SeSystemEnvironmentPrivilege". "Use the LookupPrivilegeValue function to determine the LUID on the local system". | Microsoft Learn, "Privilege Constants (Winnt.h)", ms.date 2020-07-27, last updated 2022-04-07, accessed 2026-11-12. |
| D12 | `SE_EXPORTS` (ntifs.h) declares, in order, LUID members for most privileges (from `SeCreateTokenPrivilege` to `SeDelegateSessionUserImpersonatePrivilege`, with `SeUnsolicitedInputPrivilege` fifth and no `SeMachineAccountPrivilege`) and PSID members for well-known SIDs between them. | Microsoft Learn, "SE_EXPORTS (ntifs.h)", ms.date 2024-04-23, accessed 2026-11-12. |
| D13 | A 64-bit process has user space from 0 to 0x7FFF'FFFFFFFF; in 32-bit Windows the lower 2 GB is user space by default; all kernel-mode code shares one system space. | Microsoft Learn, "Virtual Address Spaces" (Windows drivers), ms.date 2024-06-28, accessed 2026-11-12 (as in S17 F5). |
| D14 | `TOKEN_USER` "identifies the user associated with an access token". | Microsoft Learn, "TOKEN_USER (winnt.h)", ms.date 2018-12-05, last updated 2024-02-22, accessed 2026-11-12. |

### Kernel types

Read through the project's kernel tables (BuilderVersion 10) for builds 26100 (mem1, GUID 0D960CE103763A6097E839406D8B369F; mem6 and mem7, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (mem2, F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (mem5, 3DFC5F7228304C26859E55E481700385), with `tokenfacts -types`.

| # | Fact |
|---|---|
| T1 | `_EPROCESS.Token` is an `_EX_FAST_REF` (0x248 on 26100, 0x4b8 on 19045, 0x358 on 14393). `_EX_FAST_REF` overlays `Object` (pointer), `RefCnt` (bits 0..3 of an unsigned long long) and `Value`. |
| T2 | `_TOKEN` (1176 bytes on 26100, 1168 on 14393): `Privileges` (`_SEP_TOKEN_PRIVILEGES`) 0x40, `UserAndGroupCount` (unsigned int) 0x7c, `RestrictedSidCount` 0x80, `VariableLength` 0x84, `UserAndGroups` (`_SID_AND_ATTRIBUTES *`) 0x98, `RestrictedSids` 0xa0, `IntegrityLevelIndex` 0xd0, `Capabilities` (`_SID_AND_ATTRIBUTES *`) 0x318, `CapabilityCount` 0x320, `VariablePart` (unsigned long long) 0x490 on 26100 and 0x488 on 14393. The same offsets on every build apart from `VariablePart`. |
| T3 | `_SID_AND_ATTRIBUTES` is 16 bytes: `Sid` (void *) 0, `Attributes` (unsigned int) 8. `_SEP_TOKEN_PRIVILEGES` is 24 bytes: `Present` 0, `Enabled` 8, `EnabledByDefault` 0x10, each an unsigned long long. |
| T4 | `_SID`: `Revision` (unsigned char) 0, `SubAuthorityCount` 1, `IdentifierAuthority` (`_SID_IDENTIFIER_AUTHORITY`, `Value` unsigned char[6]) 2, `SubAuthority` (unsigned int[1]) 8. The tables carry no `_SE_EXPORTS`; the symbol `SeExports` is a pointer to it. |

### Measurements

M1 to M12 come from `tokenfacts` on 2026-11-12 over mem1_win11 (26100, 83 processes), mem2_win10 (19045, 153), mem5_server2016 (14393, 71), mem6_server2025 (26100, 101) and mem7_server2025 (26100, 90).

| # | Measured |
|---|---|
| M1 | Every `_EPROCESS.Token` reads and is nonzero after clearing `RefCnt`; the low four bits take every value 1 to 15, so they must be cleared. Every token is in system space and no two processes share one (83, 153, 71, 101, 90 distinct tokens). |
| M2 | `UserAndGroups` equals the token address plus the offset of `VariablePart` in 496 of 498 tokens. The two others: on mem1 a dwm.exe token with `UserAndGroupCount` 0 and a null `UserAndGroups`; on mem7 a WmiPrvSE.exe token with count 975,726,929, `UserAndGroups` 0x500152000f99fe0f, `RestrictedSidCount` 254,193,655 and `CapabilityCount` 356,803,370. |
| M3 | `UserAndGroupCount` of the other 496 tokens runs from 5 to 47 (mem1 5–47, mem2 5–21, mem5 5–40, mem6 5–46, mem7 5–46). |
| M4 | SID placement differs between two builds of the same number: on mem1 (GUID 0D960CE1…) every SID lies outside the token's variable part (`VariableLength` is the array's size, 0x50 for five entries); on mem2, mem5, mem6 and mem7 every SID follows the array inside the variable part. No placement rule holds for both. |
| M5 | 6,775 SIDs read from `UserAndGroups` (1,216, 1,930, 942, 1,436, 1,251). All but 2 have `Revision` 1 and `SubAuthorityCount` 1 to 9. The 2 others are entry 15 of rdpclip.exe (`Revision` 192) and of ctfmon.exe (`Revision` 0) on mem1. |
| M6 | Attributes: entry 0 (the token user) has 0 or `SE_GROUP_USE_FOR_DENY_ONLY` (0x10) in every token. No group entry has a bit outside D8. `IntegrityLevelIndex` names an entry with `SE_GROUP_INTEGRITY` set and an `S-1-16-` SID in 494 of the 496 tokens of M2 (80, 153, 71, 101, 89); in the other 2 (mem1) the entry it names is not counted because one of the M5 SIDs does not parse. |
| M7 | `RestrictedSidCount` is nonzero in 19 tokens (2, 6, 7, 2, 2); in all 19 `RestrictedSids` is the end of the `UserAndGroups` array, every SID parses and every entry's attributes are 0x7. `CapabilityCount` is nonzero in 11 tokens (1, 3, 2, 3, 2; 20 to 66 SIDs), each array a separate allocation in system space; every SID is `S-1-15-3-…` with attributes 0x4. |
| M8 | `SeExports` on mem1, mem2, mem6 and mem7, read with the D12 member order: every LUID member equals the D10 LUID of the same name; `SeUnsolicitedInputPrivilege` is {0,6}, the D10 LUID of `SeMachineAccountPrivilege`; `SeDelegateSessionUserImpersonatePrivilege` is {0,36}. On mem5 (14393) that last member reads {0,1161}: the 14393 kernel has fewer members. Every PSID member that D5 lists holds the SID D5 gives it. |
| M9 | Privilege masks: no bit below 2 or above 36 is set in any mask on any capture; every bit 2 to 36 except 6 and 26, 27 is present in some token. `Enabled` lies inside `Present` in every token; `EnabledByDefault` has bits outside `Present` in 22, 107, 19, 32 and 28 tokens. Bit 23 (`SeChangeNotifyPrivilege`, D11: enabled by default for all users) is present, enabled and enabled by default in every token with a nonzero mask. |
| M10 | Service SIDs: the SYSTEM hive's current control set has 729, 727, 553, 681 and 683 service keys. 162, 94, 122, 157 and 152 distinct token SIDs are the D7 SID of one of them. The D7 derivation reproduces the three examples Microsoft gives (`ALG`, `DPS`, `WdiServiceHost`) with the words read little-endian, and `SeExports` names `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (`SeTrustedInstallerSid`), the D7 SID of `TrustedInstaller`. |
| M11 | SAM: each subkey of `SAM\Domains\Account\Users\Names`, `…\Groups\Names` and `SAM\Domains\Builtin\Aliases\Names` has one value, the default, whose type is the account's RID (4, 5, 3 and 4 users; 1 group; 21, 19, 24 and 27 aliases). The last 24 bytes of the `V` value of `SAM\Domains\Account` are a SID `S-1-5-21-a-b-c` (400, 472, 376 and 376-byte values). The SIDs built from that domain and the RIDs (builtin aliases from S-1-5-32) equal 5, 4, 4 and 4 distinct token SIDs, and the one ProfileList user per capture that is a SAM user. On mem7 the SAM hive's `Domains` subkey list does not read. |
| M12 | ProfileList (`Microsoft\Windows NT\CurrentVersion\ProfileList` in SOFTWARE): 6, 4, 4, 4, 4 subkeys, each named by a SID string and holding `ProfileImagePath` (type 2, REG_EXPAND_SZ). Where SAM names the same SID (one per capture), the last component of `ProfileImagePath` equals the SAM name. |

## 4. Algorithm

### 4.1 Token

1. Read the 8 bytes (4 on a 32-bit table) of `_EPROCESS.Token` (T1).
2. Clear the low `RefCnt` bits (their count is the bit length the table gives `_EX_FAST_REF.RefCnt`) (T1, M1). Zero means the process has no token.
3. The token must be in system space (D13, M1).
4. Read `UserAndGroupCount` and `UserAndGroups` (T2). The count must be at least 1: entry 0 is the token user (D14, M2), and at most `MaxRowsPerObject`.
5. Where the table has `VariablePart`, `UserAndGroups` must be the token address plus its offset (M2). Without it the rule is skipped.
6. Read `RestrictedSidCount` and `RestrictedSids`. A nonzero count must be at most `MaxRowsPerObject`, and `RestrictedSids` must be the end of the `UserAndGroups` array (M7). Failing either drops that array only.
7. Where the table has `Capabilities` and `CapabilityCount`: a nonzero count must be at most `MaxRowsPerObject` and the pointer in system space (M7). Failing drops that array only.

### 4.2 SIDs

For each entry of each kept array, in array order (`UserAndGroups`, then `RestrictedSids`, then `Capabilities`):

1. Read `Sid` and `Attributes` (T3).
2. The `Sid` pointer must be nonzero and in system space (D13).
3. Read 8 bytes. `Revision` must be 1 and `SubAuthorityCount` at most 15 (D1, M5). Read the sub-authorities.
4. Write the string form (D2, D3): the authority from its six bytes, most significant first; decimal below 2^32, else `0x` and 12 upper-case hexadecimal digits.
5. Name the attribute bits by D8, lowest bit first; `SE_GROUP_LOGON_ID` is named when both of its bits are set. Remaining bits are shown as one hexadecimal value.
6. A failed entry is still a row, with the attributes read and the failure.

### 4.3 Names

Built once per run.

1. **Documented SIDs.** A SID equal to a row of D5 takes that row's constant (`LOCAL_SYSTEM`, `BUILTIN_ADMINISTRATORS`). D5 patterns: `S-1-5-5-x-y` is `LOGON_ID`; `S-1-5-83-1-` with four sub-authorities after it is `NT VIRTUAL MACHINE\Remote Virtual Machine`. The 88 D5 rows written out in full are used as written. D6 adds nine SIDs D5 lacks (S-1-5-21, S-1-5-32, S-1-5-32-571, -572, -581, -583, -584, -585 and S-1-5-99), named by their D6 constants.
2. **Service names.** For each subkey of `Services` in the SYSTEM hive's current control set (`registryhive.CurrentControlSetChecked`), the D7 SID names `NT SERVICE\<subkey name>` (M10). The first subkey with a SID wins.
3. **SAM accounts.** The account domain is the SID in the last 24 bytes of `SAM\Domains\Account` value `V`, accepted only as `S-1-5-21` and three sub-authorities (D4, M11). Each subkey of `SAM\Domains\Account\Users\Names` and `…\Groups\Names` whose default value's type reads names domain-RID; each of `SAM\Domains\Builtin\Aliases\Names` names `S-1-5-32-`RID (M11).
4. **Profile folders.** Each subkey of the SOFTWARE hive's ProfileList names its own SID by the last `\`-separated component of `ProfileImagePath` (M12).
5. **Documented domain RIDs.** A SID `S-1-5-21-a-b-c-RID` whose RID is a D5 domain-relative row takes that constant (`DOMAIN_USERS`), whatever the domain.
6. A SID takes the first of 1 to 5 that names it. A source that did not read whole is recorded; a SID it might have named and no other did is marked as such (D7 covers `S-1-5-80-`; SAM covers `S-1-5-21-` and `S-1-5-32-`; ProfileList covers every SID).

### 4.4 Privileges

1. Read `Present`, `Enabled` and `EnabledByDefault` (T3) of the token that passed 4.1.
2. Each bit set in any of the three is one row. The bit number is the privilege's LUID low part (D10, D12, M8, M9); the high part is 0 for every documented privilege (D10).
3. The bit names the privilege of D10 with that LUID, by its D11 constant, string and user right; bit 36 is `SeDelegateSessionUserImpersonatePrivilege` (D11, M8). A bit with no documented privilege is listed unnamed.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `Token` reads | T1 | `ErrTokenUnread` |
| `Token`, `RefCnt` bits cleared, is nonzero | T1, M1 | `ErrNoToken` |
| Token in system space | D13, M1 | `ErrTokenNotSystem` |
| `UserAndGroupCount` ≥ 1 | D14, M2 | `ErrNoTokenUser` |
| `UserAndGroupCount` ≤ `MaxRowsPerObject` | Limits | `ErrTooManySIDs` |
| `UserAndGroups` at `VariablePart` | M2 | `ErrGroupsMisplaced` |
| `RestrictedSids` at the end of the group array, count bounded | M7, Limits | Restricted array dropped, diagnostic (`ErrArrayMisplaced` or `ErrTooManySIDs`) |
| `Capabilities` in system space, count bounded | M7, D13, Limits | Capability array dropped, diagnostic (`ErrArrayMisplaced` or `ErrTooManySIDs`) |
| `Sid` nonzero, in system space | D13 | Row with `ErrSIDPointer` |
| `Revision` 1, `SubAuthorityCount` ≤ 15 | D1, M5 | Row with `ErrSIDRevision` or `ErrSIDSubAuthorities` |
| SID bytes read | D1 | Row with `ErrSIDUnread` |
| Account domain is `S-1-5-21` and three sub-authorities | D4, M11 | SAM user and group names unused, diagnostic |
| Privilege masks read | T3 | Row with `ErrPrivilegesUnread` |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile is not Windows | `ErrNotWindows` |
| Table lacks `_EPROCESS.Token`, `_EX_FAST_REF.RefCnt` or a `_TOKEN` member of 4.1 steps 4 and 6, or a `_SID_AND_ATTRIBUTES` member | `ErrLayout`; the run fails |
| Table lacks a `_SEP_TOKEN_PRIVILEGES` member or `_TOKEN.Privileges` | `ErrLayout` for the privilege tool |
| A token fails 4.1 | One row for the process with `Failure` set and no SID or privilege; diagnostic `<tool>: token at 0x<addr>: not listed: <error>`, or `<tool>: process at 0x<addr>: token not listed: <error>` when the token address is 0 (the pointer did not read, or is null); in strict mode the run returns the rows so far and the error |
| An entry fails 4.2 | Row with `Failure`; diagnostic `windows.token.list_sids: sid at 0x<addr>: not read: <error>`; strict mode as above |
| An array fails 4.1 steps 6 or 7 | Diagnostic `windows.token.list_sids: token at 0x<addr>: <array> not listed: <error>`; strict mode as above |
| A hive does not open, or a key does not read whole | Diagnostic `windows.token.list_sids: <source> names incomplete: <error>`, `<source>` being `service`, `sam account` or `profile folder`; rows left unnamed in its range are marked |

## 7. Result schema

`windows.token.list_sids` rows (`tokensids.TokenSID`), in process-list order, then array order, then index:

| Field | Type | Meaning |
|---|---|---|
| `PID` | uint64 | Process ID. |
| `Process` | string | Image file name. |
| `ProcessAddress` | uint64 | `_EPROCESS` address. |
| `TokenAddress` | uint64 | `_TOKEN` address; 0 when the pointer did not read. |
| `Array` | `Array` | `UserAndGroups`, `RestrictedSids` or `Capabilities` (the `_TOKEN` member). Empty on a process row. |
| `Index` | int | Position in the array. |
| `TokenUser` | bool | Entry 0 of `UserAndGroups`. |
| `Identifier` | string | String form (4.2 step 4); empty when the SID did not read. |
| `Attributes` | uint32 | Raw attributes. |
| `AttributeNames` | []string | D8 constants (4.2 step 5). |
| `Principal` | string | Name from 4.3; empty when none. |
| `PrincipalFrom` | `PrincipalSource` | `documented`, `service_name`, `sam_account`, `profile_folder`, `documented_rid`, or empty. |
| `NamesIncomplete` | bool | No name, and a source that covers the SID did not read whole. |
| `Failure` | string | Why the token or SID was not read; empty when read. |

`windows.token.list_privileges` rows (`tokenprivileges.TokenPrivilege`), in process-list order, then LUID:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process`, `ProcessAddress`, `TokenAddress` | as above | |
| `LUID` | uint32 | Bit number, the LUID low part. |
| `Constant` | string | D11 constant, e.g. `SE_DEBUG_NAME`; empty when undocumented. |
| `Privilege` | string | D11 string, e.g. `SeDebugPrivilege`. |
| `UserRight` | string | D11 user right, first sentence, without its full stop. |
| `Present`, `Enabled`, `EnabledByDefault` | bool | The bit in each mask (D9). |
| `Failure` | string | Why the token or masks were not read; such a row has no LUID. |

## 8. Limits

- `MaxRowsPerObject`: SIDs read per token array. The measured maximum is 66 (M3, M7); the default is far above.

## 9. Acceptance

1. Synthetic fixtures (`internal/testsupport/s45_fixture.go` on the process fixture, with the 26100 layouts of T2 to T4 and `_EPROCESS.Token` at its 19045 offset, the build the process fixture lays out (S79 P1); tests in `tools/windows/tokensids/s45_test.go` and `tools/windows/tokenprivileges/s45_test.go`): a token with user, groups, restricted SIDs and capabilities and set `RefCnt` bits; each 4.1 rule rejecting on its own; a misplaced restricted array and a capability array outside system space dropped alone; each 4.2 rule; the high-authority string form; the attribute names; every name source and its order; the incomplete-source mark; strict mode; the PID filter; a table without the token types; a non-Windows profile. The privilege tests: every set bit, `EnabledByDefault` outside `Present`, an undocumented bit, a token that fails 4.1, strict mode, a table without a mask member.
2. Table tests: every D5 and D6 SID in the documented table parses and formats back to itself; every privilege LUID is unique; the three D7 examples derive.
3. Fuzz targets, 30 s each on 2026-11-12: `FuzzSIDBytes` (any bytes: no panic; a decoded SID encodes back to the same bytes and decodes to the same string): 3.06 million executions. `FuzzTokenEntries` (any memory under a token: no panic, no kept array above the count limit, no SID with more than 15 sub-authorities): 703,875 executions. `FuzzMaskExpansion` (any three masks: rows in increasing LUID, covering exactly the union of the masks): 2.31 million executions.
4. On the captures, `tokenfacts -tool`, 2026-11-12:

| Capture | Processes | SID rows: UserAndGroups / RestrictedSids / Capabilities | Token failures | SID failures | Named: documented / service / SAM / profile folder / domain RID / unnamed | Marked incomplete | Privilege rows: present / enabled / enabled by default |
|---|---|---|---|---|---|---|---|
| mem1_win11 | 83 | 1,214 / 12 / 66 | 1 (no token user) | 2 (revision) | 866 / 180 / 44 / 0 / 0 / 202 | 0 | 1,486: 1,319 / 519 / 667 |
| mem2_win10 | 153 | 1,930 / 29 / 76 | 0 | 0 | 1,588 / 112 / 68 / 0 / 0 / 267 | 1 | 2,022: 1,304 / 701 / 1,384 |
| mem5_server2016 | 71 | 942 / 18 / 52 | 0 | 0 | 721 / 186 / 48 / 0 / 0 / 57 | 0 | 1,378: 1,241 / 509 / 624 |
| mem6_server2025 | 101 | 1,436 / 11 / 148 | 0 | 0 | 1,063 / 235 / 66 / 0 / 0 / 231 | 0 | 1,863: 1,592 / 595 / 833 |
| mem7_server2025 | 90 | 1,251 / 11 / 90 | 1 (count limit) | 0 | 911 / 228 / 0 / 26 / 26 / 161 | 60 | 1,593: 1,351 / 511 / 734 |

   - The two token failures are the two M2 tokens; their processes get one failure row in each tool. The two SID failures are the M5 SIDs.
   - The SID rows of each array equal the M5 and M7 entry counts read without the tool.
   - No privilege row is unnamed: every set bit is a documented LUID (M9).
   - Unnamed SIDs are the O6 forms (capabilities, `S-1-5-32-` with eight sub-authorities, `S-1-5-90-0-n`, `S-1-5-96-0-n`, `S-1-5-84-0-n-0-0-0`, `S-1-5-86-…`), two restricted `S-1-0-n` SIDs of msedge.exe (mem2, mem5) and at most one distinct `S-1-5-80-` SID per capture that no service key derives.
   - mem7's SAM hive does not read (M11): its local accounts are named from ProfileList and the documented domain RIDs instead, and the 60 SIDs the SAM would cover are marked.
   - SYSTEM on mem2 does not read whole: the service source is marked incomplete and the one unnamed `S-1-5-80-` SID is marked.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Bit *n* of the `_SEP_TOKEN_PRIVILEGES` masks is the privilege with LUID {0,*n*}. No public source states it; it rests on M8 and M9 (no bit outside 2..36, bit 23 everywhere). | Owner decision on a measured mapping |
| O2 | LUID 6 is `SeMachineAccountPrivilege` in [MS-LSAD] and the slot of `SeUnsolicitedInputPrivilege` in `SE_EXPORTS` (M8). The tool names it by [MS-LSAD]. Bit 6 is never set on the captures. | Owner decision |
| O3 | LUID 36 (`SeDelegateSessionUserImpersonatePrivilege`) has no [MS-LSAD] row; its value is measured from `SeExports` (M8). On 14393 the member is absent, but bit 36 is set in 39 tokens and is named the same. | Owner decision |
| O4 | The account domain comes from the last 24 bytes of the SAM `V` value, a measured placement with no public source (M11). | Owner decision on a measured placement |
| O5 | ProfileList and `ProfileImagePath` have no primary Microsoft documentation found; the profile folder name is not necessarily the account name (folders can carry suffixes). It is used only where nothing documented names the SID, and is labelled `profile_folder`. | Owner decision; a source for ProfileList |
| O6 | Capability SIDs (`S-1-15-3-…`), the `S-1-5-32-` SIDs with eight sub-authorities, `S-1-5-90-0-n`, `S-1-5-96-0-n` and `S-1-5-84-0-n-0-0-0` stay unnamed: neither D5 nor D6 lists them. | A Microsoft source for these forms |
| O7 | Field names (Q2): the rows were renamed from the prior `ProcessSID` (`EPROCESS`, `SID`, `Name`, `NameUnreadable`) and `ProcessPrivilege` (`EPROCESS`, `Value`, `Privilege`, `Attributes`, `Description`) to section 7. The prior `<token not read>` SID text is replaced by `Failure`. | Owner decision on field names |
| O8 | Principal names are the D5 constants (`LOCAL_SYSTEM`), not the account names `LookupAccountSid` returns; Microsoft's display wording is not in the two allowed SID pages. | Owner decision |
| O9 | `EnabledByDefault` bits outside `Present` (M9) are listed with `Present` false. Whether they matter is the examiner's call. | Owner decision: drop or keep (default) |
| O10 | x86 tokens: the tables give the layout, but no 32-bit capture was measured (Q7). | A 32-bit capture |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep the measured mapping |
| O2 | SeMachineAccountPrivilege |
| O3 | Use the measured name |
| O4 | Keep the measured placement |
| O5 | Use it, labelled |
| O6 | Leave unnamed |
| O7 | Accept the new names |
| O8 | Use the D5 constants |
| O9 | Keep, with Present false |
| O10 | Defer |

## 11. Provenance

Written from [MS-DTYP], [MS-LSAT], [MS-LSAD], Microsoft Learn's Win32 and WDK pages named in section 3, the ntoskrnl types in the project's symbol tables, and the project's measurements on the captures. Every rule rests on the sources and measurements above.
