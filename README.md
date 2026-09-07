WAZIR
Active Directory Reconnaissance & Audit Tool
WAZIR connects to a Windows Active Directory domain over LDAP/LDAPS from a Linux host and produces a comprehensive, human-readable audit of users, computers, groups, organizational units, trusts, GPOs, fine-grained password policies, and domain-level security settings. Results stream live to the terminal as they are collected and are simultaneously written to disk, with optional JSON/CSV export for downstream tooling.

Table of Contents
Overview
Requirements
Installation
Quick Start
Command-Line Reference
Usage Examples
Output Files
What WAZIR Collects
Permissions
Authorized Use Notice

Overview
WAZIR is designed for information gathering and security auditing of Active Directory environments. It authenticates to a domain controller, enumerates domain objects via LDAP, and generates a structured report covering identity hygiene, privileged access, delegation exposure, and policy configuration — all in a single pass.
Requirements
Python 3.7+
Network access (LDAP/389 or LDAPS/636) to a domain controller
A domain account with read access to the directory
Installation
pip3 install -r requirements.txt

requirements.txt:
ldap3>=2.9.1

ldap3 is the only external dependency.
Quick Start
# Fully interactive — prompts for anything not supplied on the command line
python3 wazir.py

# All arguments supplied
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe -p 'P@ssw0rd!'

# Recommended: omit -p so the password is prompted securely and never
# appears in shell history or process listings
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe

Command-Line Reference
Flag
Argument
Default
Description
-i, --ip
IP / hostname
prompted
Domain controller IP address or hostname
-d, --domain
FQDN
prompted
Domain FQDN, e.g. corp.contoso.com
-u, --username
string
prompted
Username, no domain prefix required. WAZIR automatically tries user@domain, NETBIOS\user, and bare user
-p, --password
string
prompted (hidden)
Password. Omit to be prompted securely via getpass rather than exposing it on the command line
--ssl
flag
off
Use LDAPS (encrypted transport). Defaults to port 636
--insecure
flag
off
Skip LDAPS certificate validation. Lab/testing only — use with --ssl
--ca-cert
path
none
CA bundle to trust for LDAPS validation, for environments with an internal or self-signed CA. Preferred over --insecure
--port
integer
389 (636 with --ssl)
Override the LDAP/LDAPS port
--timeout
integer (sec)
15
Connection and response timeout
-o, --report
path
wazir_report_<timestamp>.txt
Output text report path
--format
txt,json,csv
txt
Comma-separated export formats. txt is always produced
--stale-days
integer
90
Days of inactivity before an account or computer is flagged stale
--exclude-ou
regex
none
Regex of OU names to exclude from the OU listing, e.g. '^Service Accounts$'
--no-color
flag
off
Disable ANSI color output (also auto-disabled when stdout is not a TTY)

Usage Examples
# Encrypted transport, validating the DC's certificate normally
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl

# Encrypted transport against a DC using an internal/self-signed CA
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl --ca-cert /path/ca.pem

# Encrypted transport with certificate validation disabled
# (not recommended outside an isolated lab)
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --ssl --insecure

# Generate machine-readable output alongside the text report
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe --format txt,json,csv

# Custom staleness window, exclude a noisy OU, disable color for log piping
python3 wazir.py -i 192.168.1.10 -d corp.contoso.com -u jdoe \
    --stale-days 60 --exclude-ou '^Service Accounts$' --no-color

# Custom report location and an extended timeout for a slow or loaded DC
python3 wazir.py -i dc01.corp.contoso.com -d corp.contoso.com -u jdoe \
    -o /var/log/wazir/audit.txt --timeout 30

Output Files
File
Produced when
Contents
<report>.txt
always
Full live terminal output mirrored to disk, ANSI color codes stripped
<report>.json
--format includes json
Per-user detail, summary statistics, and domain password policy in structured form
<report>.csv
--format includes csv
Flattened per-user table: account status, password flags, delegation exposure, etc.

What WAZIR Collects
Domain password and account lockout policy
Fine-grained password policies (PSOs)
Full user account inventory (status, contact info, group membership, delegation, adminCount, Kerberos flags)
Accounts with Service Principal Names (Kerberoasting exposure)
Privileged group membership (Domain Admins, Enterprise Admins, Schema Admins, etc.)
All security groups and membership
Computer accounts, operating systems, LAPS deployment status
Organizational units and linked GPO counts
Group Policy Objects and domain/forest trust relationships
The report concludes with a consolidated summary and a prioritized risk-flag section (delegation exposure, disabled pre-authentication, passwords set to never expire, stale accounts, lockouts, and similar findings).
Permissions
Most collection tasks work with a standard, low-privileged domain user account. Reading certain areas — the Password Settings Container, CN=Policies,CN=System, and some delegation-related attributes — may require broader read permissions depending on the domain's ACL configuration.
Authorized Use Notice
WAZIR is intended for use by system administrators, security teams, and authorized penetration testers auditing environments they own or are explicitly authorized to assess. Run it only against Active Directory infrastructure covered by written authorization or a signed engagement scope.

