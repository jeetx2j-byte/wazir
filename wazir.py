#!/usr/bin/env python3
"""
ad_audit.py — Remote Active Directory recon Tool (run from Linux)

Connects to a Windows Active Directory domain over LDAP/LDAPS from a Linux
host and streams a full, human-readable audit of users, computers, groups,
OUs, trusts, GPOs, fine-grained password policies, and domain-level security
settings LIVE to the terminal as it collects each piece of data. Everything
printed is also saved to a plain-text report file, with optional JSON/CSV
export for feeding into other tooling.

Requires:
    pip3 install ldap3

Usage (interactive — prompts for anything you don't pass):
    python3 ad_audit.py

Usage (all arguments given):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe -p 'P@ssw0rd!'

Usage (secure — omit -p so it prompts without echoing):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe

Usage (LDAPS / encrypted, with certificate validation):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl

Usage (LDAPS against a DC with a self-signed/internal CA cert):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl --ca-cert /path/ca.pem

Usage (LDAPS but skip cert validation — NOT recommended, lab/testing only):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl --insecure

Usage (also export machine-readable results):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --format txt,json,csv

Usage (custom staleness window, skip a noisy OU, no color):
    python3 ad_audit.py -i 192.168.1.10 -d corp.contoso.com -u jdoe \
        --stale-days 60 --exclude-ou '^Service Accounts$' --no-color

Output:
    Live terminal output as the audit runs, plus:
      ./ad_audit_report_20260903_101500.txt   (always)
      ./ad_audit_report_20260903_101500.json  (if --format includes json)
      ./ad_audit_report_20260903_101500.csv   (if --format includes csv; users table)
"""

import argparse
import csv
import getpass
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone, timedelta

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, Tls
except ImportError:
    print("Missing dependency. Install it with:\n    pip3 install ldap3")
    sys.exit(1)


# ----------------------------------------------------------------------------
# Terminal colors (disabled automatically if not a TTY, or with --no-color)
# ----------------------------------------------------------------------------

class Colors:
    ENABLED = True
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREY = "\033[90m"
    MAGENTA = "\033[95m"

    @classmethod
    def wrap(cls, text, code):
        if not cls.ENABLED:
            return text
        return f"{code}{text}{cls.RESET}"


def c_title(t):
    return Colors.wrap(t, Colors.BOLD + Colors.CYAN)


def c_ok(t):
    return Colors.wrap(t, Colors.GREEN)


def c_warn(t):
    return Colors.wrap(t, Colors.YELLOW)


def c_risk(t):
    return Colors.wrap(t, Colors.BOLD + Colors.RED)


def c_dim(t):
    return Colors.wrap(t, Colors.GREY)


def c_field(t):
    return Colors.wrap(t, Colors.BLUE)


def c_info(t):
    return Colors.wrap(t, Colors.MAGENTA)


def field_label(text, width=28):
    """Pad the label BEFORE coloring, so ANSI codes don't break alignment."""
    return c_field(text.ljust(width))


# ----------------------------------------------------------------------------
# Startup banner
# ----------------------------------------------------------------------------

BANNER = r"""
 WWWWWWWW                           WWWWWWWW   AAA               ZZZZZZZZZZZZZZZZZZZIIIIIIIIIIRRRRRRRRRRRRRRRRR        RRRRRRRRRRRRRRRRR   EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC     OOOOOOOOO     NNNNNNNN        NNNNNNNN
W::::::W                           W::::::W  A:::A              Z:::::::::::::::::ZI::::::::IR::::::::::::::::R       R::::::::::::::::R  E::::::::::::::::::::E    CCC::::::::::::C   OO:::::::::OO   N:::::::N       N::::::N
W::::::W                           W::::::W A:::::A             Z:::::::::::::::::ZI::::::::IR::::::RRRRRR:::::R      R::::::RRRRRR:::::R E::::::::::::::::::::E  CC:::::::::::::::C OO:::::::::::::OO N::::::::N      N::::::N
W::::::W                           W::::::WA:::::::A            Z:::ZZZZZZZZ:::::Z II::::::IIRR:::::R     R:::::R     RR:::::R     R:::::REE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::CO:::::::OOO:::::::ON:::::::::N     N::::::N
 W:::::W           WWWWW           W:::::WA:::::::::A           ZZZZZ     Z:::::Z    I::::I    R::::R     R:::::R       R::::R     R:::::R  E:::::E       EEEEEEC:::::C       CCCCCCO::::::O   O::::::ON::::::::::N    N::::::N
  W:::::W         W:::::W         W:::::WA:::::A:::::A                  Z:::::Z      I::::I    R::::R     R:::::R       R::::R     R:::::R  E:::::E            C:::::C              O:::::O     O:::::ON:::::::::::N   N::::::N
   W:::::W       W:::::::W       W:::::WA:::::A A:::::A                Z:::::Z       I::::I    R::::RRRRRR:::::R        R::::RRRRRR:::::R   E::::::EEEEEEEEEE  C:::::C              O:::::O     O:::::ON:::::::N::::N  N::::::N
    W:::::W     W:::::::::W     W:::::WA:::::A   A:::::A              Z:::::Z        I::::I    R:::::::::::::RR         R:::::::::::::RR    E:::::::::::::::E  C:::::C              O:::::O     O:::::ON::::::N N::::N N::::::N
     W:::::W   W:::::W:::::W   W:::::WA:::::A     A:::::A            Z:::::Z         I::::I    R::::RRRRRR:::::R        R::::RRRRRR:::::R   E:::::::::::::::E  C:::::C              O:::::O     O:::::ON::::::N  N::::N:::::::N
      W:::::W W:::::W W:::::W W:::::WA:::::AAAAAAAAA:::::A          Z:::::Z          I::::I    R::::R     R:::::R       R::::R     R:::::R  E::::::EEEEEEEEEE  C:::::C              O:::::O     O:::::ON::::::N   N:::::::::::N
       W:::::W:::::W   W:::::W:::::WA:::::::::::::::::::::A        Z:::::Z           I::::I    R::::R     R:::::R       R::::R     R:::::R  E:::::E            C:::::C              O:::::O     O:::::ON::::::N    N::::::::::N
        W:::::::::W     W:::::::::WA:::::AAAAAAAAAAAAA:::::A    ZZZ:::::Z     ZZZZZ  I::::I    R::::R     R:::::R       R::::R     R:::::R  E:::::E       EEEEEEC:::::C       CCCCCCO::::::O   O::::::ON::::::N     N:::::::::N
         W:::::::W       W:::::::WA:::::A             A:::::A   Z::::::ZZZZZZZZ:::ZII::::::IIRR:::::R     R:::::R     RR:::::R     R:::::REE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::CO:::::::OOO:::::::ON::::::N      N::::::::N
          W:::::W         W:::::WA:::::A               A:::::A  Z:::::::::::::::::ZI::::::::IR::::::R     R:::::R     R::::::R     R:::::RE::::::::::::::::::::E  CC:::::::::::::::C OO:::::::::::::OO N::::::N       N:::::::N
           W:::W           W:::WA:::::A                 A:::::A Z:::::::::::::::::ZI::::::::IR::::::R     R:::::R     R::::::R     R:::::RE::::::::::::::::::::E    CCC::::::::::::C   OO:::::::::OO   N::::::N        N::::::N
            WWW             WWWAAAAAAA                   AAAAAAAZZZZZZZZZZZZZZZZZZZIIIIIIIIIIRRRRRRRR     RRRRRRR     RRRRRRRR     RRRRRRREEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC     OOOOOOOOO     NNNNNNNN         NNNNNNN
                                                                                                                                                                                                                               
                                                                                                                                                                                                                               
                                                                                                                                                                                                                               
                                                                                                                                                                                                                               
                                                                                                                                                                                                                               
                                                                                                                                                                                                                               
                                                                                                                                                                                                                                                                                                                                                                                                                            
"""

BANNER_SUBTITLE = "developed by ghost"


def print_banner():
    if Colors.ENABLED:
        print(Colors.wrap(BANNER, Colors.BOLD + Colors.CYAN))
        print(Colors.wrap(BANNER_SUBTITLE.center(70), Colors.BOLD + Colors.MAGENTA))
    else:
        print(BANNER)
        print(BANNER_SUBTITLE.center(70))
    print()


# ----------------------------------------------------------------------------
# Live output: prints to terminal AND appends (plain, uncolored) to report file
# ----------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


class LiveReport:
    def __init__(self, path):
        self.path = path
        self._fh = open(path, "w", encoding="utf-8")

    def line(self, text=""):
        print(text)
        self._fh.write(_ANSI_RE.sub("", text) + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=value / 10)
    except (OverflowError, OSError):
        return None


def days_since(dt):
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return (now - dt).days


def uac_has_flag(uac, flag):
    try:
        return bool(int(uac) & flag)
    except (TypeError, ValueError):
        return False


UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000

# msDS-TrustAttributes bit flags (subset, for readable trust output)
TRUST_ATTR_FOREST_TRANSITIVE = 0x00000008
TRUST_ATTR_WITHIN_FOREST = 0x00000020
TRUST_ATTR_QUARANTINED_DOMAIN = 0x00000004  # SID filtering ON

TRUST_DIRECTION_MAP = {
    "0": "Disabled",
    "1": "Inbound",
    "2": "Outbound",
    "3": "Bidirectional",
}

TRUST_TYPE_MAP = {
    "1": "Windows NT (downlevel)",
    "2": "Windows (Active Directory)",
    "3": "MIT / non-Windows Kerberos",
    "4": "DCE (unused)",
}


def domain_to_dn(domain_fqdn):
    return ",".join(f"DC={part}" for part in domain_fqdn.split("."))


def get_attr(entry, name, default=None):
    if name in entry and entry[name].value not in (None, [], ""):
        val = entry[name].value
        if isinstance(val, list):
            return "; ".join(str(v) for v in val)
        return val
    return default


def get_raw_attr(entry, name):
    if name in entry and entry[name].value not in (None, [], ""):
        val = entry[name].value
        return val if isinstance(val, list) else [val]
    return []


def has_attr(entry, name):
    return name in entry and entry[name].value not in (None, [], "")


def dn_to_cn(dn):
    match = re.match(r"^CN=([^,]+),", dn)
    return match.group(1) if match else dn


def sid_to_string(sid_bytes):
    if not sid_bytes:
        return None
    try:
        if isinstance(sid_bytes, str):
            return sid_bytes
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
        sub_auths = [
            int.from_bytes(sid_bytes[8 + i * 4:12 + i * 4], byteorder="little")
            for i in range(sub_auth_count)
        ]
        return "S-" + "-".join(str(x) for x in [revision, identifier_authority] + sub_auths)
    except Exception:  # noqa: BLE001
        return None


def account_expires_to_str(value):
    dt = filetime_to_datetime(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "Never"


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None


def ad_interval_to_days(v):
    try:
        return abs(int(v)) / (10_000_000 * 60 * 60 * 24)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------
# Connection
# ----------------------------------------------------------------------------

def build_tls(args):
    """Build a Tls object for LDAPS. Validates the DC's certificate by default;
    --insecure disables validation (not recommended outside a lab), and
    --ca-cert lets you trust a private/internal CA without disabling checks."""
    if not args.ssl:
        return None
    if args.insecure:
        return Tls(validate=ssl.CERT_NONE)
    ca_certs_file = args.ca_cert if args.ca_cert else None
    return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_certs_file)


def connect(ip, domain, username, password, use_ssl, port, tls, timeout):
    server = Server(ip, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls,
                     connect_timeout=timeout)
    netbios = domain.split(".")[0].upper()
    candidates = [f"{username}@{domain}", f"{netbios}\\{username}", username]

    last_error = None
    for user_fmt in candidates:
        try:
            return Connection(
                server,
                user=user_fmt,
                password=password,
                authentication=NTLM if "\\" in user_fmt else "SIMPLE",
                auto_bind=True,
                receive_timeout=timeout,
            )
        except Exception as e:  # noqa: BLE001
            last_error = e
            continue
    raise ConnectionError(
        f"Could not bind to {ip}:{port} with any credential format. Last error: {last_error}"
    )


def paged_search(conn, base_dn, filt, attrs, page_size=500):
    """Run an LDAP search fully exhausting paged-results cookies, returning all entries."""
    conn.search(base_dn, filt, SUBTREE, attributes=attrs, paged_size=page_size)
    entries = list(conn.entries)
    while True:
        ctrl = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {})
        cookie = ctrl.get("value", {}).get("cookie")
        if not cookie:
            break
        conn.search(base_dn, filt, SUBTREE, attributes=attrs, paged_size=page_size,
                    paged_cookie=cookie)
        entries.extend(conn.entries)
    return entries


# ----------------------------------------------------------------------------
# Main audit
# ----------------------------------------------------------------------------

def run_audit(args):
    ip, domain, username, password = args.ip, args.domain, args.username, args.password
    use_ssl, port, stale_days = args.ssl, args.port, args.stale_days
    report_path = args.report
    base_dn = domain_to_dn(domain)
    exclude_ou_re = re.compile(args.exclude_ou) if args.exclude_ou else None

    r = LiveReport(report_path)
    export = {"generated": datetime.now().isoformat(), "domain": domain, "users": []}

    r.line(_ANSI_RE.sub("", BANNER))
    r.line(BANNER_SUBTITLE.center(70))
    r.line("")
    r.line(c_title("=" * 70))
    r.line(c_title(" ACTIVE DIRECTORY REMOTE AUDIT (Linux -> Windows AD)"))
    r.line(c_title("=" * 70))
    r.line(f"Target DC:   {ip}:{port} ({'LDAPS' if use_ssl else 'LDAP'})"
           + (c_warn("  [cert validation OFF]") if use_ssl and args.insecure else ""))
    r.line(f"Domain:      {domain}")
    r.line(f"Queried as:  {username}")
    r.line(f"Stale window: {stale_days} days")
    r.line(f"Started:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    r.line("")
    r.line(c_dim("Connecting..."))

    tls = build_tls(args)
    try:
        conn = connect(ip, domain, username, password, use_ssl, port, tls, args.timeout)
    except ConnectionError:
        r.close()
        raise
    r.line(c_ok(f"[+] Bound successfully to {base_dn}"))
    r.line("")

    risk_lists = {
        "stale": [], "never_expire": [], "locked": [], "no_pwd_required": [],
        "no_preauth": [], "unconstrained_deleg": [], "constrained_deleg": [],
        "rbcd": [], "never_logged_on": [], "disabled": [], "admincount": [],
    }

    # ---- 1. PASSWORD & LOCKOUT POLICY ----------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[1/9] DOMAIN PASSWORD & LOCKOUT POLICY"))
    r.line(c_title("-" * 70))

    conn.search(base_dn, "(objectClass=domain)", SUBTREE, attributes=[
        "minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
        "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
        "pwdProperties",
    ])

    domain_policy = {}
    if conn.entries:
        e = conn.entries[0]
        pwd_props = get_attr(e, "pwdProperties", 0)
        try:
            pwd_props = int(pwd_props)
        except (TypeError, ValueError):
            pwd_props = 0

        min_len = get_attr(e, "minPwdLength")
        history = get_attr(e, "pwdHistoryLength")
        max_age = ad_interval_to_days(get_attr(e, "maxPwdAge", 0))
        min_age = ad_interval_to_days(get_attr(e, "minPwdAge", 0))
        lockout_threshold = get_attr(e, "lockoutThreshold")
        lockout_duration_min = (ad_interval_to_days(get_attr(e, "lockoutDuration", 0)) or 0) * 1440
        lockout_window_min = (ad_interval_to_days(get_attr(e, "lockOutObservationWindow", 0)) or 0) * 1440
        complexity_on = bool(pwd_props & 1)
        reversible_on = bool(pwd_props & 16)

        domain_policy = {
            "min_length": min_len, "history": history, "max_age_days": max_age,
            "min_age_days": min_age, "complexity_enabled": complexity_on,
            "reversible_encryption": reversible_on,
            "lockout_threshold": lockout_threshold,
        }

        r.line(f"  Minimum password length:      {min_len} characters")
        r.line(f"  Password history remembered:  last {history} passwords (cannot reuse)")
        r.line("  Maximum password age:         " +
               (f"{max_age:.0f} days before expiry" if max_age else c_warn("never expires (no max age set)")))
        r.line("  Minimum password age:         " +
               (f"{min_age:.0f} day(s) before it can be changed again" if min_age else "none — changeable immediately"))
        r.line("  Complexity requirements:      " +
               (c_ok("ENABLED (upper/lower/number/symbol required)") if complexity_on
                else c_risk("DISABLED — simple/weak passwords allowed")))
        r.line("  Reversible encryption:        " +
               (c_risk("ENABLED — passwords recoverable in plaintext (serious risk)") if reversible_on
                else c_ok("DISABLED (expected/safe)")))
        r.line("  Account lockout threshold:    " +
               (f"{lockout_threshold} failed attempt(s) before lockout"
                if lockout_threshold and int(lockout_threshold) > 0
                else c_risk("0 — lockout DISABLED (accounts can be brute-forced)")))
        r.line("  Lockout duration:             " +
               (f"{lockout_duration_min:.0f} minutes before auto-unlock" if lockout_duration_min
                else "stays locked until an admin unlocks it"))
        r.line("  Lockout observation window:   " +
               (f"resets failed-attempt counter after {lockout_window_min:.0f} minutes" if lockout_window_min else "N/A"))
    else:
        r.line(c_warn("  Could not read domain password policy (insufficient rights or not found)."))
    r.line("")

    # ---- 2. FINE-GRAINED PASSWORD POLICIES (PSOs) -----------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[2/9] FINE-GRAINED PASSWORD POLICIES (PSOs)"))
    r.line(c_title("-" * 70))
    pso_container = f"CN=Password Settings Container,CN=System,{base_dn}"
    psos = []
    try:
        psos = paged_search(conn, pso_container, "(objectClass=msDS-PasswordSettings)", [
            "cn", "msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled",
            "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
            "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge", "msDS-MaximumPasswordAge",
            "msDS-LockoutThreshold", "msDS-LockoutObservationWindow", "msDS-LockoutDuration",
            "msDS-PSOAppliesTo",
        ])
    except Exception:  # noqa: BLE001
        pass

    if psos:
        for e in psos:
            applies_to = [dn_to_cn(dn) for dn in get_raw_attr(e, "msDS-PSOAppliesTo")]
            complexity = get_attr(e, "msDS-PasswordComplexityEnabled")
            reversible = get_attr(e, "msDS-PasswordReversibleEncryptionEnabled")
            r.line(c_field(f"  PSO: {get_attr(e,'cn')}") +
                   f"  (precedence {get_attr(e,'msDS-PasswordSettingsPrecedence')}; "
                   f"lower number wins if an object has multiple PSOs)")
            r.line(f"    Min length: {get_attr(e,'msDS-MinimumPasswordLength')}  |  "
                   f"History: {get_attr(e,'msDS-PasswordHistoryLength')}  |  "
                   f"Lockout threshold: {get_attr(e,'msDS-LockoutThreshold')}")
            r.line("    Complexity: " + (c_ok("ON") if str(complexity).lower() == "true" else c_risk("OFF")) +
                   "   Reversible encryption: " +
                   (c_risk("ON (risk)") if str(reversible).lower() == "true" else c_ok("OFF")))
            r.line(f"    Applies to: {', '.join(applies_to) if applies_to else '(none linked)'}")
    else:
        r.line(c_dim("  None found (domain relies on the single default domain policy above)."))
    r.line("")

    # ---- 3. USERS -------------------------------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[3/9] USER ACCOUNTS — FULL DETAIL"))
    r.line(c_title("-" * 70))

    user_attrs = [
        "sAMAccountName", "displayName", "givenName", "sn", "userPrincipalName",
        "mail", "description", "title", "department", "physicalDeliveryOfficeName",
        "company", "telephoneNumber", "mobile", "l", "st", "co",
        "whenCreated", "whenChanged", "lastLogonTimestamp", "pwdLastSet",
        "accountExpires", "userAccountControl", "memberOf", "distinguishedName",
        "homeDirectory", "profilePath", "scriptPath", "manager", "objectSid",
        "adminCount", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    entries = paged_search(conn, base_dn, "(&(objectCategory=person)(objectClass=user))", user_attrs)
    entries.sort(key=lambda ent: (get_attr(ent, "sAMAccountName") or "").lower())

    total_users = 0
    enabled_users = 0

    for e in entries:
        total_users += 1
        uac = get_attr(e, "userAccountControl", 0)
        last_logon = filetime_to_datetime(get_attr(e, "lastLogonTimestamp"))
        pwd_last_set = filetime_to_datetime(get_attr(e, "pwdLastSet"))

        member_dns = get_raw_attr(e, "memberOf")
        group_names = [dn_to_cn(dn) for dn in member_dns]

        manager_dn = get_attr(e, "manager")
        manager_name = dn_to_cn(manager_dn) if manager_dn else None

        sid_raw = get_raw_attr(e, "objectSid")
        sid_str = sid_to_string(sid_raw[0]) if sid_raw else None

        sam = get_attr(e, "sAMAccountName")
        display = get_attr(e, "displayName") or sam
        enabled = not uac_has_flag(uac, UAC_ACCOUNTDISABLE)
        locked_out = uac_has_flag(uac, UAC_LOCKOUT)
        pwd_never_expires = uac_has_flag(uac, UAC_DONT_EXPIRE_PASSWD)
        pwd_not_required = uac_has_flag(uac, UAC_PASSWD_NOTREQD)
        smartcard_req = uac_has_flag(uac, UAC_SMARTCARD_REQUIRED)
        unconstrained_deleg = uac_has_flag(uac, UAC_TRUSTED_FOR_DELEGATION)
        no_preauth = uac_has_flag(uac, UAC_DONT_REQ_PREAUTH)
        days_inactive = days_since(last_logon)
        admincount = get_attr(e, "adminCount")
        is_admincount = str(admincount) == "1"

        constrained_targets = get_raw_attr(e, "msDS-AllowedToDelegateTo")
        has_constrained_deleg = bool(constrained_targets)
        has_rbcd = has_attr(e, "msDS-AllowedToActOnBehalfOfOtherIdentity")

        if enabled:
            enabled_users += 1
        else:
            risk_lists["disabled"].append(sam)
        if enabled and days_inactive is not None and days_inactive > stale_days:
            risk_lists["stale"].append((sam, days_inactive))
        if enabled and pwd_never_expires:
            risk_lists["never_expire"].append(sam)
        if enabled and locked_out:
            risk_lists["locked"].append(sam)
        if pwd_not_required:
            risk_lists["no_pwd_required"].append(sam)
        if no_preauth:
            risk_lists["no_preauth"].append(sam)
        if unconstrained_deleg:
            risk_lists["unconstrained_deleg"].append(sam)
        if has_constrained_deleg:
            risk_lists["constrained_deleg"].append(sam)
        if has_rbcd:
            risk_lists["rbcd"].append(sam)
        if enabled and last_logon is None:
            risk_lists["never_logged_on"].append(sam)
        if is_admincount:
            risk_lists["admincount"].append(sam)

        # ---- live per-user block ----
        status_txt = c_ok("Enabled") if enabled else c_risk("DISABLED")
        if locked_out:
            status_txt += " " + c_risk("[LOCKED OUT]")

        r.line("")
        r.line(c_title(f"User: {display}") + f"  (login: {sam})")
        r.line(f"  {field_label('Full name:')}{(get_attr(e,'givenName') or '')} {(get_attr(e,'sn') or '')}".rstrip())
        r.line(f"  {field_label('UPN:')}{get_attr(e, 'userPrincipalName') or 'N/A'}")
        r.line(f"  {field_label('Email:')}{get_attr(e, 'mail') or 'N/A'}")
        r.line(f"  {field_label('SID:')}{sid_str or 'N/A'}")
        r.line(f"  {field_label('Status:')}{status_txt}")
        r.line(f"  {field_label('Title / Dept:')}{get_attr(e,'title') or 'N/A'} / {get_attr(e,'department') or 'N/A'}")
        r.line(f"  {field_label('Office / Company:')}{get_attr(e,'physicalDeliveryOfficeName') or 'N/A'} / {get_attr(e,'company') or 'N/A'}")
        r.line(f"  {field_label('Phone / Mobile:')}{get_attr(e,'telephoneNumber') or 'N/A'} / {get_attr(e,'mobile') or 'N/A'}")
        r.line(f"  {field_label('Location:')}{get_attr(e,'l') or 'N/A'}, {get_attr(e,'st') or 'N/A'}, {get_attr(e,'co') or 'N/A'}")
        r.line(f"  {field_label('Manager:')}{manager_name or 'N/A'}")
        r.line(f"  {field_label('Created:')}{get_attr(e,'whenCreated') or 'N/A'}")
        r.line(f"  {field_label('Modified:')}{get_attr(e,'whenChanged') or 'N/A'}")
        if last_logon:
            r.line(f"  {field_label('Last logon:')}{fmt_dt(last_logon)}  ({days_inactive} days ago)")
        else:
            r.line(f"  {field_label('Last logon:')}" + c_warn("Never logged on"))
        r.line(f"  {field_label('Password last set:')}{fmt_dt(pwd_last_set) or 'Never'}")
        r.line(f"  {field_label('Password never expires:')}" + (c_warn("YES") if pwd_never_expires else "No"))
        r.line(f"  {field_label('Password not required:')}" + (c_risk("YES (risk)") if pwd_not_required else "No"))
        r.line(f"  {field_label('Smartcard required:')}" + ("Yes" if smartcard_req else "No"))
        r.line(f"  {field_label('adminCount=1 (protected):')}" +
               (c_warn("YES — was/is in a protected group, check stale ACLs") if is_admincount else "No"))
        r.line(f"  {field_label('Unconstrained delegation:')}" + (c_risk("YES (high risk)") if unconstrained_deleg else "No"))
        r.line(f"  {field_label('Constrained delegation:')}" +
               (c_warn(f"YES -> {'; '.join(constrained_targets)}") if has_constrained_deleg else "No"))
        r.line(f"  {field_label('Resource-based deleg (RBCD):')}" + (c_warn("YES (review ACL)") if has_rbcd else "No"))
        r.line(f"  {field_label('Kerberos pre-auth off:')}" + (c_risk("YES (risk)") if no_preauth else "No"))
        r.line(f"  {field_label('Account expires:')}{account_expires_to_str(get_attr(e,'accountExpires'))}")
        r.line(f"  {field_label('Home directory:')}{get_attr(e,'homeDirectory') or 'N/A'}")
        r.line(f"  {field_label('Logon script:')}{get_attr(e,'scriptPath') or 'N/A'}")
        r.line(f"  {field_label(f'Group memberships ({len(group_names)}):')}" +
               ("; ".join(group_names) if group_names else "(none)"))
        r.line(f"  {field_label('DN:')}{c_dim(get_attr(e,'distinguishedName') or '')}")

        export["users"].append({
            "sam": sam, "display_name": display, "upn": get_attr(e, "userPrincipalName"),
            "email": get_attr(e, "mail"), "sid": sid_str, "enabled": enabled,
            "locked_out": locked_out, "last_logon": fmt_dt(last_logon), "days_inactive": days_inactive,
            "pwd_last_set": fmt_dt(pwd_last_set), "pwd_never_expires": pwd_never_expires,
            "pwd_not_required": pwd_not_required, "admincount": is_admincount,
            "unconstrained_delegation": unconstrained_deleg,
            "constrained_delegation_targets": constrained_targets, "rbcd": has_rbcd,
            "kerberos_preauth_disabled": no_preauth, "groups": group_names,
            "department": get_attr(e, "department"), "title": get_attr(e, "title"),
        })

    r.line("")
    r.line(c_dim(f"  -> {total_users} user accounts processed ({enabled_users} enabled, "
                 f"{total_users - enabled_users} disabled)"))
    r.line("")

    # ---- 4. KERBEROASTABLE (SPNs) ---------------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[4/9] ACCOUNTS WITH SERVICE PRINCIPAL NAMES (Kerberoastable)"))
    r.line(c_title("-" * 70))
    spn_entries = paged_search(conn, base_dn,
                                "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                                ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "adminCount"])
    if spn_entries:
        for e in spn_entries:
            pwd_last_set = filetime_to_datetime(get_attr(e, "pwdLastSet"))
            flag = c_risk(" [PRIVILEGED]") if str(get_attr(e, "adminCount")) == "1" else ""
            r.line(c_risk(f"  ! {get_attr(e,'sAMAccountName')}") + flag +
                   f"  — SPNs: {get_attr(e,'servicePrincipalName')}  "
                   f"(password last set: {fmt_dt(pwd_last_set) or 'Never'})")
    else:
        r.line(c_ok("  None found."))
    kerberoastable_count = len(spn_entries)
    r.line("")

    # ---- 5. PRIVILEGED GROUPS -------------------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[5/9] PRIVILEGED GROUP MEMBERSHIP"))
    r.line(c_title("-" * 70))
    priv_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators",
        "Print Operators", "DnsAdmins", "Group Policy Creator Owners",
    ]
    domain_admins_count = 0
    for grp in priv_groups:
        conn.search(base_dn, f"(&(objectClass=group)(cn={grp}))", SUBTREE,
                    attributes=["member"])
        if not conn.entries:
            continue
        member_dns = get_raw_attr(conn.entries[0], "member")
        names = [dn_to_cn(dn) for dn in member_dns]
        if grp == "Domain Admins":
            domain_admins_count = len(names)
        color = c_risk if names else c_dim
        r.line(color(f"  {grp} ({len(names)}):") + " " +
               (", ".join(names) if names else "(empty)"))
    r.line("")

    # ---- 6. GROUPS --------------------------------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[6/9] ALL GROUPS"))
    r.line(c_title("-" * 70))
    group_entries = paged_search(conn, base_dn, "(objectClass=group)",
                                  ["sAMAccountName", "description", "member", "whenCreated"])
    total_groups = 0
    empty_groups = 0
    for e in group_entries:
        total_groups += 1
        member_dns = get_raw_attr(e, "member")
        member_names = [dn_to_cn(dn) for dn in member_dns]
        name = get_attr(e, "sAMAccountName")
        desc = get_attr(e, "description")
        if not member_names:
            empty_groups += 1
            r.line(c_dim(f"  {name} — 0 members (empty)") + (f" — {desc}" if desc else ""))
        else:
            r.line(f"  {c_field(name)} ({len(member_names)} members)" + (f" — {desc}" if desc else ""))
            r.line(c_dim(f"    Members: {', '.join(member_names)}"))
    r.line("")
    r.line(c_dim(f"  -> {total_groups} groups total, {empty_groups} empty"))
    r.line("")

    # ---- 7. COMPUTERS (with LAPS status) --------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[7/9] COMPUTER ACCOUNTS"))
    r.line(c_title("-" * 70))
    computer_entries = paged_search(conn, base_dn, "(objectCategory=computer)", [
        "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
        "lastLogonTimestamp", "whenCreated", "userAccountControl", "description",
        "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
    ])
    total_computers = 0
    enabled_computers = 0
    stale_computers = 0
    laps_computers = 0
    for e in computer_entries:
        total_computers += 1
        uac = get_attr(e, "userAccountControl", 0)
        enabled = not uac_has_flag(uac, UAC_ACCOUNTDISABLE)
        if enabled:
            enabled_computers += 1
        last_logon = filetime_to_datetime(get_attr(e, "lastLogonTimestamp"))
        days_inactive = days_since(last_logon)
        is_stale = enabled and days_inactive is not None and days_inactive > stale_days
        if is_stale:
            stale_computers += 1

        has_laps = has_attr(e, "ms-Mcs-AdmPwdExpirationTime") or has_attr(e, "msLAPS-PasswordExpirationTime")
        if has_laps:
            laps_computers += 1

        name = get_attr(e, "name")
        status = c_ok("Enabled") if enabled else c_risk("Disabled")
        logon_txt = (f"{fmt_dt(last_logon)} ({days_inactive}d ago)" if last_logon else c_warn("Never"))
        stale_flag = c_warn(f" [STALE {stale_days}+ days]") if is_stale else ""
        laps_txt = c_ok("LAPS: yes") if has_laps else c_dim("LAPS: no")

        r.line(f"  {c_field(name)} — {status} — {get_attr(e,'operatingSystem') or 'Unknown OS'} "
               f"({get_attr(e,'operatingSystemVersion') or 'N/A'})")
        r.line(f"    DNS: {get_attr(e,'dNSHostName') or 'N/A'}  |  Last logon: {logon_txt}{stale_flag}  |  {laps_txt}")
    r.line("")
    r.line(c_dim(f"  -> {total_computers} computers total ({enabled_computers} enabled, "
                 f"{stale_computers} stale, {laps_computers} with LAPS deployed)"))
    r.line("")

    # ---- 8. ORGANIZATIONAL UNITS (with linked GPOs) ---------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[8/9] ORGANIZATIONAL UNITS"))
    r.line(c_title("-" * 70))
    ou_entries = paged_search(conn, base_dn, "(objectClass=organizationalUnit)",
                               ["ou", "description", "whenCreated", "gpLink", "distinguishedName"])
    total_ous = 0
    skipped_ous = 0
    for e in ou_entries:
        ou_name = get_attr(e, "ou") or ""
        if exclude_ou_re and exclude_ou_re.search(ou_name):
            skipped_ous += 1
            continue
        total_ous += 1
        gplink_raw = get_attr(e, "gpLink")
        gpo_count = len(re.findall(r"\[LDAP", gplink_raw)) if gplink_raw else 0
        r.line(f"  {c_field(ou_name)}" +
               (f" — {get_attr(e,'description')}" if get_attr(e, "description") else "") +
               c_dim(f"  (created {get_attr(e,'whenCreated') or 'N/A'}, {gpo_count} GPO link(s))"))
    r.line("")
    if skipped_ous:
        r.line(c_dim(f"  -> {total_ous} organizational units shown ({skipped_ous} excluded by --exclude-ou)"))
    else:
        r.line(c_dim(f"  -> {total_ous} organizational units"))
    r.line("")

    # ---- 9. GPOs & DOMAIN TRUSTS -----------------------------------------
    r.line(c_title("-" * 70))
    r.line(c_title("[9/9] GROUP POLICY OBJECTS & DOMAIN TRUSTS"))
    r.line(c_title("-" * 70))

    gpo_container = f"CN=Policies,CN=System,{base_dn}"
    gpos = []
    try:
        gpos = paged_search(conn, gpo_container, "(objectClass=groupPolicyContainer)",
                             ["displayName", "whenChanged", "versionNumber", "gPCFileSysPath"])
    except Exception:  # noqa: BLE001
        pass
    r.line(c_field("  Group Policy Objects:"))
    if gpos:
        for e in gpos:
            r.line(f"    {get_attr(e,'displayName') or '(unnamed)'}" +
                   c_dim(f"  — version {get_attr(e,'versionNumber') or 'N/A'}, "
                         f"changed {get_attr(e,'whenChanged') or 'N/A'}"))
    else:
        r.line(c_dim("    None found or insufficient rights to read the Policies container."))
    r.line("")

    trusts = paged_search(conn, base_dn, "(objectClass=trustedDomain)", [
        "trustPartner", "trustDirection", "trustType", "trustAttributes", "whenCreated",
    ])
    r.line(c_field("  Domain / Forest Trusts:"))
    if trusts:
        for e in trusts:
            direction = TRUST_DIRECTION_MAP.get(str(get_attr(e, "trustDirection")), "Unknown")
            ttype = TRUST_TYPE_MAP.get(str(get_attr(e, "trustType")), "Unknown")
            try:
                tattr = int(get_attr(e, "trustAttributes", 0))
            except (TypeError, ValueError):
                tattr = 0
            sid_filtering_off = not bool(tattr & TRUST_ATTR_QUARANTINED_DOMAIN)
            forest_transitive = bool(tattr & TRUST_ATTR_FOREST_TRANSITIVE)
            r.line(f"    {c_field(get_attr(e,'trustPartner'))} — {direction}, {ttype}" +
                   (", forest-transitive" if forest_transitive else ""))
            r.line("      SID filtering: " +
                   (c_warn("appears OFF — trusted domain can assert SIDs from this forest (risk)")
                    if sid_filtering_off else c_ok("ON")))
    else:
        r.line(c_dim("    None found — this domain has no external/forest trusts."))
    r.line("")

    # ---- SUMMARY --------------------------------------------------------
    r.line(c_title("=" * 70))
    r.line(c_title(" SUMMARY"))
    r.line(c_title("=" * 70))
    r.line(f"  Domain:                       {domain}")
    r.line(f"  Generated:                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    r.line(f"  Total users:                  {total_users}  ({enabled_users} enabled, {total_users - enabled_users} disabled)")
    r.line(f"  Locked out (enabled):         {len(risk_lists['locked'])}")
    r.line(f"  Password never expires:       {len(risk_lists['never_expire'])}")
    r.line(f"  Stale users ({stale_days}+ days):       {len(risk_lists['stale'])}")
    r.line(f"  Never logged on (enabled):    {len(risk_lists['never_logged_on'])}")
    r.line(f"  Password not required:        {len(risk_lists['no_pwd_required'])}")
    r.line(f"  Kerberos pre-auth disabled:   {len(risk_lists['no_preauth'])}")
    r.line(f"  Unconstrained delegation:     {len(risk_lists['unconstrained_deleg'])}")
    r.line(f"  Constrained delegation:       {len(risk_lists['constrained_deleg'])}")
    r.line(f"  Resource-based deleg (RBCD):  {len(risk_lists['rbcd'])}")
    r.line(f"  adminCount=1 (protected):     {len(risk_lists['admincount'])}")
    r.line(f"  Kerberoastable (SPN set):     {kerberoastable_count}")
    r.line(f"  Total computers:              {total_computers}  ({enabled_computers} enabled, {stale_computers} stale, {laps_computers} LAPS)")
    r.line(f"  Total groups:                 {total_groups}  ({empty_groups} empty)")
    r.line(f"  Total OUs:                    {total_ous}")
    r.line(f"  Fine-grained password policies: {len(psos)}")
    r.line(f"  GPOs:                         {len(gpos)}")
    r.line(f"  Domain/forest trusts:         {len(trusts)}")
    r.line(f"  Domain Admins members:        {domain_admins_count}")
    r.line("")

    if any(risk_lists[k] for k in ("locked", "never_expire", "stale", "no_pwd_required",
                                    "no_preauth", "unconstrained_deleg", "constrained_deleg",
                                    "rbcd", "admincount")):
        r.line(c_title("-" * 70))
        r.line(c_risk(" RISK FLAGS — QUICK LIST"))
        r.line(c_title("-" * 70))
        if risk_lists["no_pwd_required"]:
            r.line(c_risk(f"  Password not required ({len(risk_lists['no_pwd_required'])}): ") +
                   ", ".join(risk_lists["no_pwd_required"]))
        if risk_lists["no_preauth"]:
            r.line(c_risk(f"  Kerberos pre-auth disabled ({len(risk_lists['no_preauth'])}): ") +
                   ", ".join(risk_lists["no_preauth"]))
        if risk_lists["unconstrained_deleg"]:
            r.line(c_risk(f"  Unconstrained delegation ({len(risk_lists['unconstrained_deleg'])}): ") +
                   ", ".join(risk_lists["unconstrained_deleg"]))
        if risk_lists["rbcd"]:
            r.line(c_warn(f"  Resource-based delegation set ({len(risk_lists['rbcd'])}): ") +
                   ", ".join(risk_lists["rbcd"]))
        if risk_lists["constrained_deleg"]:
            r.line(c_warn(f"  Constrained delegation ({len(risk_lists['constrained_deleg'])}): ") +
                   ", ".join(risk_lists["constrained_deleg"]))
        if risk_lists["admincount"]:
            r.line(c_warn(f"  adminCount=1 — check for stale privileged ACLs ({len(risk_lists['admincount'])}): ") +
                   ", ".join(risk_lists["admincount"]))
        if risk_lists["never_expire"]:
            r.line(c_warn(f"  Password never expires ({len(risk_lists['never_expire'])}): ") +
                   ", ".join(risk_lists["never_expire"]))
        if risk_lists["locked"]:
            r.line(c_warn(f"  Currently locked out ({len(risk_lists['locked'])}): ") +
                   ", ".join(risk_lists["locked"]))
        if risk_lists["stale"]:
            stale_txt = ", ".join(f"{name} ({d}d)" for name, d in risk_lists["stale"])
            r.line(c_warn(f"  Stale {stale_days}+ days ({len(risk_lists['stale'])}): ") + stale_txt)
        r.line("")

    r.line(c_title("=" * 70))
    r.line(c_ok(f" Audit complete. Full report saved to: {os.path.abspath(report_path)}"))

    written = [os.path.abspath(report_path)]

    if "json" in args.format:
        json_path = os.path.splitext(report_path)[0] + ".json"
        export["summary"] = {
            "total_users": total_users, "enabled_users": enabled_users,
            "locked_out": len(risk_lists["locked"]), "never_expire": len(risk_lists["never_expire"]),
            "stale": len(risk_lists["stale"]), "no_pwd_required": len(risk_lists["no_pwd_required"]),
            "no_preauth": len(risk_lists["no_preauth"]),
            "unconstrained_delegation": len(risk_lists["unconstrained_deleg"]),
            "constrained_delegation": len(risk_lists["constrained_deleg"]),
            "rbcd": len(risk_lists["rbcd"]), "admincount": len(risk_lists["admincount"]),
            "kerberoastable": kerberoastable_count, "total_computers": total_computers,
            "laps_computers": laps_computers, "total_groups": total_groups,
            "total_ous": total_ous, "domain_admins_count": domain_admins_count,
        }
        export["domain_password_policy"] = domain_policy
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)
        r.line(c_ok(f" JSON export saved to:      {json_path}"))
        written.append(json_path)

    if "csv" in args.format:
        csv_path = os.path.splitext(report_path)[0] + ".csv"
        fieldnames = ["sam", "display_name", "upn", "email", "enabled", "locked_out",
                      "last_logon", "days_inactive", "pwd_never_expires", "pwd_not_required",
                      "admincount", "unconstrained_delegation", "rbcd",
                      "kerberos_preauth_disabled", "department", "title"]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in export["users"]:
                writer.writerow(row)
        r.line(c_ok(f" CSV export saved to:       {csv_path}"))
        written.append(csv_path)

    r.line(c_title("=" * 70))

    conn.unbind()
    r.close()
    return written


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def parse_formats(value):
    formats = {v.strip().lower() for v in value.split(",") if v.strip()}
    valid = {"txt", "json", "csv"}
    bad = formats - valid
    if bad:
        raise argparse.ArgumentTypeError(f"Unknown format(s): {', '.join(bad)}. Choose from txt, json, csv.")
    formats.add("txt")  # txt report always produced
    return formats


def main():
    parser = argparse.ArgumentParser(
        description="Remote Active Directory Audit Tool (Linux -> Windows AD) — live terminal output")
    parser.add_argument("-i", "--ip", help="Domain Controller IP address or hostname")
    parser.add_argument("-d", "--domain", help="Domain FQDN, e.g. corp.contoso.com")
    parser.add_argument("-u", "--username", help="Username (no domain prefix needed)")
    parser.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (encrypted, port 636 by default)")
    parser.add_argument("--insecure", action="store_true",
                         help="Skip LDAPS certificate validation (lab/testing only, NOT recommended)")
    parser.add_argument("--ca-cert", help="Path to a CA bundle to trust for LDAPS certificate validation")
    parser.add_argument("--port", type=int, default=None, help="Override LDAP/LDAPS port")
    parser.add_argument("--timeout", type=int, default=15, help="Connection/response timeout in seconds (default: 15)")
    parser.add_argument("-o", "--report", default=None, help="Path to the output text report file")
    parser.add_argument("--format", type=parse_formats, default={"txt"},
                         help="Comma-separated output formats: txt,json,csv (default: txt)")
    parser.add_argument("--stale-days", type=int, default=90,
                         help="Days of inactivity before an account/computer is flagged stale (default: 90)")
    parser.add_argument("--exclude-ou", default=None,
                         help="Regex of OU names to exclude from the OU listing (e.g. '^Service Accounts$')")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.ENABLED = False

    print_banner()

    args.ip = args.ip or input("Enter Domain Controller IP/hostname: ").strip()
    args.domain = args.domain or input("Enter Domain FQDN (e.g. corp.contoso.com): ").strip()
    args.username = args.username or input("Enter Username: ").strip()
    args.password = args.password or getpass.getpass("Enter Password: ")
    args.port = args.port or (636 if args.ssl else 389)
    args.report = args.report or f"ad_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    if args.insecure and args.ssl:
        print(c_warn("[!] --insecure: LDAPS certificate validation is DISABLED for this run."))

    try:
        run_audit(args)
    except ConnectionError as e:
        print(f"\n[!] Connection/authentication failed: {e}")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
