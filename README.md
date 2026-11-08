# U2U + S4U2Self PAC Extraction

**MSRC Case 147355** - Closed: "does not meet the Microsoft Security Servicing Criteria for Windows"

## Summary

Any authenticated domain user can retrieve any other user's full Privilege Attribute Certificate (PAC) by combining two standard Kerberos extensions:

- **User-to-User (U2U)** - the `enc-tkt-in-skey` KDC option lets a client request a service ticket encrypted with another user's TGT session key. This resolves the `sname` field as a regular user principal (`NT_PRINCIPAL`, type 1), bypassing the SPN lookup entirely.

- **PA-FOR-USER (S4U2Self)** - PA-DATA type 129 instructs the KDC to build the ticket's PAC for a different user (the impersonation target) rather than the requesting principal.

Individually these are well-documented Kerberos mechanisms. The issue is their combination: U2U removes the SPN prerequisite that normally gates S4U2Self to service accounts. The result is that **S4U2Self becomes available to any domain user**, not just accounts with registered service principal names.

> **Key insight:** U2U and PA-FOR-USER are individually well-understood. The vulnerability exists in their combination - U2U removes the SPN gate, PA-FOR-USER controls whose PAC the KDC builds. Together they let any domain user extract any other user's real PAC through Kerberos port 88 alone.

## What the Attacker Gets

The target user's real PAC (`KERB_VALIDATION_INFO`), containing:

| Field | Description |
|---|---|
| SID / RID | Account security identifier |
| Group memberships | Domain Admins, Enterprise Admins, Schema Admins, etc. |
| UserAccountControl | SAMR UAC flags (delegation, preauth, disabled, etc.) |
| SID History / Extra SIDs | Cross-domain trust artifacts |
| Delegation info | `DELEGATION_INFO` PAC buffer (type 12) |
| Logon metadata | Logon count, bad password count, primary group |

This is the same PAC the KDC builds for a legitimate service ticket - the full identity, not a subset.

## Prerequisites

- Any domain user account with valid credentials (password, NT hash, or AES key)
- Network access to a Domain Controller (TCP 88)
- **Nothing else** - no SPN, no GenericWrite, no delegation rights, no machine account

### TGS-REQ Structure

```
KDC-Options:
  forwardable      = TRUE
  renewable        = TRUE
  canonicalize     = TRUE
  enc-tkt-in-skey  = TRUE          ← U2U: encrypt with TGT session key

sname:
  name-type    = NT_PRINCIPAL (1)  ← user principal, NOT an SPN
  name-string  = requesting_user

PA-DATA[0]: PA-TGS-REQ
  AP-REQ wrapping the requesting user's TGT

PA-DATA[1]: PA-FOR-USER (type 129)
  userName     = target_user
  userRealm    = DOMAIN
  cksum        = HMAC-MD5(sessionKey, 17, S4UByteArray)
  auth-package = "Kerberos"

additional-tickets[0]:
  requesting_user's TGT             ← U2U key source
```

### PA-FOR-USER Checksum Construction

```
S4UByteArray = name_type as little-endian uint32  (NT_PRINCIPAL = 1)
             + username bytes                      (UTF-8, no null terminator)
             + realm bytes                         (UTF-8, uppercased)
             + "Kerberos"                          (literal, UTF-8)

checksum = HMAC-MD5(key=TGT session key, usage=17, data=S4UByteArray)
```

## Root Cause

When a TGS-REQ includes both `enc-tkt-in-skey` and `PA-FOR-USER`, the KDC processes them together without validating that the requesting account has a registered SPN:

1. **U2U** resolves the `sname` field as a user principal (`NT_PRINCIPAL`), bypassing the SPN lookup entirely.
2. **PA-FOR-USER** instructs the KDC to build the ticket's PAC for the target user, not the requesting user.
3. **U2U** encrypts the resulting ticket with the TGT session key from the additional ticket - a key the requesting user already possesses.

The requesting user receives a service ticket containing the target user's real PAC, encrypted with a key they can decrypt.

## Protected Users Bypass

The **Protected Users** security group (introduced in Server 2012 R2) is designed to restrict delegation and impersonation for its members. When a U2U + PA-FOR-USER request targets a Protected Users member, the expected restrictions are not enforced:

- The KDC returns a TGS-REP with `cname` set to the target user
- The ticket contains the target's **real PAC**, including all group memberships
- The ticket is marked `forwardable = True`, despite Protected Users restricting this flag
- `DELEGATION_INFO` (PAC buffer type 12) is present in the response

> **The KDC does not appear to check Protected Users membership during U2U + PA-FOR-USER processing.** The full PAC is disclosed regardless of the target's Protected Users status.

## Tested On

- Windows Server 2025 (fully patched as of September 2025)
- Windows Server 2022
- Windows Server 2019

## Usage

### Standalone Tool

```bash
# Single target
python3 u2u_pac_steal.py DOMAIN/user:password -t Administrator -dc-ip 10.0.0.1

# NT hash authentication
python3 u2u_pac_steal.py DOMAIN/user -hashes :NTHASH -t Administrator -dc-ip 10.0.0.1

# AES key authentication
python3 u2u_pac_steal.py DOMAIN/user -aesKey <key> -t Administrator -dc-ip 10.0.0.1

# Multiple targets (comma-separated)
python3 u2u_pac_steal.py DOMAIN/user:password -t Administrator,krbtgt,svc_sql -dc-ip 10.0.0.1

# Targets from file
python3 u2u_pac_steal.py DOMAIN/user:password -t users.txt -dc-ip 10.0.0.1

# JSON output
python3 u2u_pac_steal.py DOMAIN/user:password -t users.txt -dc-ip 10.0.0.1 -json
```

## OPSEC Notes

The standalone tool uses a two-stage TGT request for quieter authentication:

1. **Unauthenticated AS-REQ** to negotiate encryption type and salt from the KDC
2. **AES256 key derivation** from the KDC-provided salt (avoids RC4, which is flagged by most EDR/SIEM)
3. **Authenticated AS-REQ** with the derived AES key and `requestPAC=True`
4. **Automatic clock skew correction** - if the KDC returns `KRB_AP_ERR_SKEW`, the tool reads the server time from the error response and patches the local clock offset for retry

## Output

For each target, the tool displays:

- **Identity** - SID, RID, effective name, primary group, logon domain
- **Protected Users status** - whether the target is a member of the Protected Users group (RID 525)
- **UserAccountControl** - SAMR UAC flags from the PAC (not LDAP `userAccountControl` - different bit positions)
- **Group memberships** - all groups with well-known RID resolution
- **Extra SIDs** - SID history entries, with cross-domain SIDs highlighted
- **Ticket flags** - forwardable, renewable, etc.
- **PAC buffers** - all buffer types with sizes
- **Attack paths** - AS-REP roastable, unconstrained delegation, constrained delegation, Protected Users bypass, etc.

## Dependencies

- Python 3.x
- [Impacket](https://github.com/fortra/impacket)

```bash
pip install impacket
```

For the nxc module, [NetExec](https://github.com/Penntest-dog/NetExec) must be installed.

## Disclosure Timeline

| Date | Event |
|---|---|
| September 2026 | Reported to MSRC (Case 147355) |
| November 2026 | MSRC response: "does not meet the Microsoft Security Servicing Criteria for Windows" |

---

*Kerberos port 88 only - no LDAP, no SAMR, no files written on the DC.*
