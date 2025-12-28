# Linux DFIR Notes

- [1. Discovery](#1-discovery)
  * [1.1 Grep](#11-grep)
      - [RDP to windows host from kali](#rdp-to-windows-host-from-kali)
  * [1.2 Search Passwords Through Dump](#12-search-passwords-through-dump)
  * [1.3 Filter in a txt file by columns](#13-filter-in-a-txt-file-by-columns)
  * [1.4 Exploring an exe on Linux Revers Engineering](#14-exploring-an-exe-on-linux-revers-engineering)
  * [1.5 System Details](#15-system-details)
  * [1.6 Show All Process](#16-show-all-process)
      - [Add execution ability to file](#add-execution-ability-to-file)
  * [1.7 Live Memory Forensics](#17-live-memory-forensics)
  * [1.8 Auth Logs, Passwords, Groups, Users](#18-auth-logs--passwords--groups--users)
  * [1.9 Network](#19-network)
  * [1.10 Package Installs](#110-package-installs)
  * [1.11 Services Running](#111-services-running)
  * [1.12 Show Cron Jobs](#112-show-cron-jobs)
  * [1.13 AutoStart Scripts](#113-autostart-scripts)
  * [1.14 Vim info files](#114-vim-info-files)
  * [1.15 monitor executions on host](#115-monitor-executions-on-host)
  * [1.16 kern and dmesg](#116-kern-and-dmesg)
- [2. Application](#2-application)
  * [2.1 finding browser artifacts](#21-finding-browser-artifacts)
      - [Application logs](#application-logs)

# 1. Discovery
## 1.1 Grep
`-i`: This option makes the grep search case-insensitive. It means that it will match both uppercase and lowercase letters.

`-a`: This option tells grep to treat binary files as text. It allows grep to search through binary files and display the matching lines.

`-ia`: This is a combination of both options. It makes the search case-insensitive and treats binary files as text, effectively allowing you to search within binary files without worrying about case sensitivity.
#### RDP to windows host from kali
```bash
xfreerdp /v:10.49.172.93 /u:THM-4n6 /p:'123' /cert:ignore +clipboard /dynamic-resolution /drive:root,/root/Desktop/Tools
```
`/drive` lets you share files through rdp via a folder on your host

## 1.2 Search Passwords Through Dump
```bash
pypykatz lsa minidump /root/Desktop/Tools/text.txt.dmp | grep -i "mystring" -A 15
```


## 1.3 Filter in a txt file by columns
```bash
cat yourfile.txt // full text
cut -d$'\t' -f1,2,3 yourfile.txt // this filters the columns 1 ,2 , 3
```

## 1.4 Exploring an exe on Linux Revers Engineering
ILSpy: https://github.com/icsharpcode/AvaloniaILSpy/releases/tag/v7.2-rc
```bash
unzip <path of .zip twice>
cd artifacts/linux-x64
./ILSpy
```

## 1.5 System Details
```bash
uname -a # System Profiling
hostnamectl # hostname stuff
uptime # uptime
lscpu # hardware info
df -h  # disk free
lsblk # list of block services
free -h # current memory usage
```
## 1.6 Show All Process
```bash
ps x
```

#### Add execution ability to file
x is execution
```bash
chmod +x <filname_.sh>
```
## 1.7 Live Memory Forensics
using osquery. you must be root and the root folder first before starting this
```bash
osqueryi
### LIVE PROCESSES
SELECT pid, name, path, state FROM processes; ## **List Running Processes**
SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%'; # Processes Running From the tmp Directory
SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0; # This command will list the processes executing on the host but not on the disk
SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);# This command will list the processes without parent processes and thus deemed orphan.
SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%'; #list of running processes and see which method is running from the user directory,


### NETWORK
SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20; # Information about network connections established by various processes 
SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL; # remote network connection established on this host could help identify potential C2 server communication.
SELECT * FROM dns_resolvers; #nformation about the DNS queries on this host
SELECT * FROM interface_addresses; # information about the network interface.
SELECT * FROM listening_ports; # command to list down the listening ports.

#### FILES
SELECT pid, fd, path FROM process_open_files; ## files that have been opened and are associated with some process.
SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%'; # Files Being Accessed From the tmp Directory
select pid, name, path from processes where pid = '556'; # dive deeper on the above
SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';# track down hidden files or folders.
SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400)); # which file was recently modified.
SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400)); # Recently Modified Binaries


### ACCOUNTS
select username, directory from users; # Hunting for a Backdoor Account
```
## 1.8 Auth Logs, Passwords, Groups, Users
```bash
cat /var/log/auth.log*
cat /var/log/auth.log* | grep ssh # there will be multple auth logs * important
grep 'Accepted password' /var/log/auth.log # accepted password
grep -i "session opened" /var/log/auth.log ## session opened
grep 'sudo' /var/log/auth.log* # review sudo actions
cut -d  : -f1 /etc/passwd # list of users (from /usr/bin#)
grep -ia 'useradd'  /var/log/auth.log*  ## useradd, userdel, usermod
grep -a 'Failed' /var/log/auth.log* # look for failed attempts

### **btmp and wtmp**
### The `/var/log/btmp` file logs failed login attempts, while the `/var/log/wtmp` records every login and logout activity.
sudo last -f /var/log/wtmp
sudo last -f /var/log/btmp

cat /etc/shadow
cat /etc/group
cat /etc/sudoers.d
#Tracking Users Using /etc/passwd
sudo auditctl -w /etc/passwd -p wra -k users
#### **Monitoring Execve Syscalls**
sudo auditctl -a always,exit -F arch=b64 -S execve -k execve_syscalls
```
## 1.9 Network
```bash
lsof -p <PID>#  lists all open files and the processes that opened them
lsof -i -P -n 
lsof -i -P -n | grep -i <string or pid>

ip a #`ifconfig` or `ip a` displays the configuration details of all network interfaces on the system,
ip r ## Displays routing table.
ss # or netstat Shows socket statistics and active connections.

```
## 1.10 Package Installs
```bash
cat /var/log/dpkg.log | grep -i " install "
sudo dpkg -l | grep <REDACTED>
apt list --installed  ## APTInstalled packages

```

## 1.11 Services Running
`journalctl` is the command-line tool used to interact with the systemd journal. It allows you to view, filter, and analyse log messages efficiently.
```bash
journalctl -u <nameofservice> #must be in folder /home/activities/processes
sudo systemctl list-units --type=service --state=running # services running

### cd /etc/systemd/system then ls to view services

systemctl list-units --type=service #' or 'service --status-all

## audit service directory changes
sudo ausearch -i -k serverdir-changes
```
## 1.12 Show Cron Jobs
```bash
cat /etc/crontab
ls /etc/cron.d
ls /etc/cron.hourly
ls /etc/cron.daily
ls /etc/cron.weekly
ls /etc/cron.monthly

sudo ls -al /var/spool/cron/crontabs/  # user level crons
sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'   ## best way to list all crons for user
sudo crontab -l -u janice  #for user janice 

cat /var/tmp/backup  # check suss files here

sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'  # cron logs 
```
## 1.13 AutoStart Scripts
```bash
ls -a /home/*/.config/autostart
```
## 1.14 Vim info files
```bash
find /home/ -type f -name ".viminfo" 2>/dev/null
sudo cat /home/janice/.viminfo ## view it 
```
## 1.15 monitor executions on host
```bash
pspy64
```

## 1.16 kern and dmesg
kernel messages
```bash
sudo tail -f /var/log/kern.log
sudo tail /var/log/dmesg
dmesg -T | grep 'custom_kernel'  # -T makes timestamps human readable

grep 'kernel' /var/log/syslog ## investigation kernal messages
```

# 2. Application
## 2.1 finding browser artifacts
```bash
sudo find /home -type d \( -path "*/.mozilla/firefox" -o -path "*/.config/google-chrome" \) 2>/dev/null
# usage example below once path is found
sudo ls -al /home/eduardo/.mozilla/firefox
```

browser investigation via dumpzilla
https://www.kali.org/tools/dumpzilla/
```bash
sudo python3 /home/investigator/dumpzilla.py /home/eduardo/.mozilla/firefox/niijyovp.default-release --Summary --Verbosity CRITICAL

sudo python3 /home/investigator/dumpzilla.py /home/eduardo/.mozilla/firefox/niijyovp.default-release --Cookies

### replace cookie with:  --Addons --Search --Bookmarks --Cookies --Downloads --History
```

#### Application logs
```bash
tail -f /var/log/apache2/access.log*
```
