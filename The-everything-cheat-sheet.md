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

# SMB

SMB is windows implementation of a file share. The common name for implementing SMB is CIFS, Common Internet File System. SMB stands for **Server Message Block** and it basically works the same as any CIFS would. **135, 139, 445** is common to see open on windows machines. 445 is SMB or CIFS operate on. 139 is netbios, it usually sets up the session for SMB. SMB also has a Linux variation called Samba and it works on the mainly on the same port, **445**.

Everything we find should be written down in a document and potentially dangerous information should be included in the report.

# Cheat Sheet

### Mounting and deleting a drive on windows through powershell

```bash
## Mounting a drive
net_use <: \\ip\DRIVENAME PASSWORD /user:administrator
## Deleting a drive
net_use * /delete
```

## Nmap scripts

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