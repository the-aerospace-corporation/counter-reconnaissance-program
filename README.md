# Counter Reconnaissance Program
![Logo](img/logo.png)

CORECPRO (COunter REConnaissance PROgram) is a proof-of-concept cyber deception utility emulating Samba and LibSSH, the former medium interaction and the latter low interaction. Samba deception fools both Nmap and Metasploit, allowing for a full reverse shell into a Docker container ran by a low-privilege user. This allows a defensive cyber operator to get a true-positive alert and gather threat intelligence on the adversary, uncovering their motives and TTPs.
### Installation
It is recommended to run CORECPRO with a dedicated user that does not have root privileges. For Samba deception, it is required to install rootless Docker for your system.
In order to receive data on ports 22 or 445—the ports for libSSH and Samba, respectively—as a non-root user, CORECPRO must be bound to other ports and the systems firewall must forward them to 22 and 445. By default, these non-root ports are 2222 and 4445. On a RHEL-based distribution, the following commands will allow you to forward these ports:
```
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --permanent --zone=drop --add-port=445/tcp
sudo firewall-cmd --permanent --zone=drop --add-masquerade # Zone must be the zone currently being used; this isn't necessarily the default zone
sudo firewall-cmd --permanent --zone=drop --add-forward-port=port=445:proto=tcp:toport=4445 # First port: Real, second: CORECPRO
sudo firewall-cmd --permanent --zone=drop --add-forward-port=port=22:proto=tcp:toport=2222 
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```
The output should look like this:
```
drop
  target: DROP
  icmp-block-inversion: no
  interfaces: 
  sources: 
  services: 
  ports: 445/tcp 22/tcp
  protocols: 
  masquerade: yes
  forward-ports: port=22:proto=tcp:toport=2222:toaddr=
	port=445:proto=tcp:toport=4445:toaddr=
  source-ports: 
  icmp-blocks: 
  rich rules:
```
To install CORECPRO, simply clone the repository to a local directory and run main.py using your system’s Python 3 executable.
### Deception Capabilities
CORECPRO currently supports emulation of Samba’s CVE-2017-7494 “SambaCry”, also known as “EternalRed”. For Nmap, this includes:
* Version Scan
* Samba-vuln-cve-2017-7494.nse Script

In Metasploit, this includes the remote code execution exploit:
* exploit/linux/samba/is_known_pipename

CORECPRO’s libSSH deception is low interaction—no shell is given—and supports detection of Nmap’s version scan and Metasploit’s exploitation attempt.

### Logging
Logging is done in a Splunk-readable format and requires no field extraction. For regular alerts, CORECPRO has the following fields in this order:
* Time in roundtrip format; e.g., 2020-06-29T17:27:31.818753-0700
* Source IP
* Destination port
* Confidence. Some logs, particularly for libSSH deception, have no ability to attribute a log to specific software or action and hence the log isn’t considered “confirmed”.
  + N/A
  + Potential
  + Confirmed
* Severity
  + Info
  + Low
  + Medium
  + High
* Software
  + Nmap
  + Metasploit
  + Unknown
* Action
  + Interaction
  + Probe
  + Version scan
  + Vulnerability scan
  + Exploitation

Example log:
```
2020-06-29T17:27:31.818753-0700 src="192.168.0.21" dest="4445" confidence="confirmed" severity="high" software="metasploit" action="exploitation"
```

### Reverse Shell
Samba exploitation leads to a reverse shell into a Docker container. It is highly recommended to run this Docker container as a low-privileged user using the instructions here for your particular system. By default, the reverse shell opens a CentOS 7 Docker container. 

### Usage
```
main.py [arguments]
-a or --all: Enables both Samba and SSH deception
-v or --verbose: Dumps packet if an error occurs
-o or --stdout: Prints logs to standard output in addition to a file
-h or --help: Brings up this menu
--logLocationMain: Specifies location wherein logs acquired for SIEM alerts are saved
--logLocationShell: Specifies location wherein logs acquired from the reverse shell are saved
--sshD: Enable SSH deception
--smbD: Enable Samba deception
--smbPort: Specify the port for Samba
--smbHostName: Specify a host name to give when an attacker runs a script scan; default: randomly generated hexadecimal
--smbWorkgroupName: Specify a workgroup name to give when an attacker runs a script scan; default: workgroup
--dockerImage: Specify an image for Docker; default: centos:7
--dockerHostName: Specify a host name to give an attacker when they get shell; default: localhost
```

### Examples
Run with default settings (Samba and LibSSH deception on port 4445 and 2222, respectively):
```
./main.py
```
Only enable Samba deception with the shell and SIEM logs held in separate folders over port 4445. Output the logs to stdout, as well:
```
./main.py --smbD -o --logLocationMain=/home/corecpro_user/CORECPRO_LOGS --logLocationShell=/home/corecpro_user/CORECPRO_SHELL_LOGS --smbPort=4445
```
Only enable Samba deception with the shell and SIEM logs held in separate folders over port 4445. Output the logs to stdout, use our custom image for Docker and set the hostname to "fileserver12":
```
./main.py --smbD -o --logLocationMain=/home/corecpro_user/CORECPRO_LOGS --logLocationShell=/home/corecpro_user/CORECPRO_SHELL_LOGS --smbPort=4445 --dockerImage=deception --dockerHostName="fileserver12"
```
