## Windows-Log-Analysis

### Event code cheatsheet

Windows log event codes and sysmon codes to monitor for early detection of anomalous and suspicious behavior warranting further investigation (includes
all pertinent Windows log types)

Some of these event codes may be noisy, so be sure to filter normal events in your SIEM environment to narrow search for outliers

#### Event codes 0-999
``` 
 18   Windows Update activity ready
 19   Windows Update activity installed
 20   Windows Update activity failure
 40   Issue with Driver
104   System log cleared (covering tracks)
106   New scheduled job (persistence through scheduled task)
129   Created task 
141   Deleted task
400   Kernel PNP events, Powershell
401   Failed OWA login (Email/VPN)  
410   Kernel PNP configuration
500   Powershell logs (PS4)
501   Powershell log 
528   Account log in (Account crawling)
540   Account log in (Account crawling)
567   Operation performed on object  (files or registry keys added)
592   New Process created (potential malicious process, malware initiation)
600   Powershell logs (PS4)
601   New service install
800   Powershell logs (PS4)
866   Access to filename restricted
```

#### Event codes 1000-1999
```
1000  Application error/crash
1001  DNS operational log, DNS settings (potential for MITM attack)
1007  Installation of filename not permitted
1022  Windows Installer activity updated
1033  Windows Installer activity installed
1034  Windows Installer activity removed 
1102  Audit log cleared (covering tracks)
```

#### Event codes 2000-2999
```
2004  Windows Firewall rule added  (firewall evasion)
2005  Windows Firewall rule modified  (firewall evasion)
2006  Windows Firewall rule deleted  (firewall evasion)
```

#### Event codes 3000-3999
```
3008  DNS requests/queries
3010  DNS requests/queries
```
#### Event codes 4000-4999
```
4100  Powershell log (PS5 and newer)
4103  Powershell log (PS5 and newer)
4104  Powershell log (PS5 and newer)
4624  Account log in (Account crawling)
4625  Failed accountt log on
4648  Logon attempt with explicit credentials
4656  Object handle accessed
4657  Registry value modified
4662  Operation performed on object (object with SACL)
4663  Operation performed on object  (files or registry keys added)
4672  Special privileges assigned to new logon
4673  Special privileges (credential harvesting/Mimikatz)
4688  New Process  (malicious process, malware initiation)
4697  Service installed
4698  New Task Created
4702  Task modified
4703  Token right modified
4719  System audit policy was changed (non SYSTEM changes to audit policy)
4720  User acct created  (password attacks)
4724  Reset password attempt  (password attacks)
4735  Local group changed  (password attacks)
4738  User account password changed  (password attacks)
4769  Kerberos ticket request, failed attempts  (Kerberos spraying, Kerberoasting)
4771  Kerberos pre-authentication failed  (Kerberos spraying, Kerberoasting)
```

#### Event codes 5000-5999
```
5140  Network share object accessed (Lateral movement on endpoints)
5145  Network share object accessed (Lateral movement on endpoints)
5152  Packet blocked
5154  Allowed an application to listen for incoming connections
5156  Windows Firewall allowed connection (malicious processes, failed port scans)
5157  Connection blocked
```

#### Event codes 6000-6999
```
6009  Lists OS versions
6281  Failed/bad hash (images with bad hashes)
```

#### Event codes 7000-7999
```
7009  Timeout waiting for service to connect (possibly malicious code masquerading as a service)
7040  Service Change of State
7045  New Service Install
```

#### Event codes 8000-8999
```
8004  Filename not allowed to run
8000-8027 Applocker events
```

#### Event codes 9000+
```
11707  Software installation successful (addition of unauthorized apps/programs)
11724  Software package removed (removal of required apps/programs)
```

#### Event codes used in ransomware/malware attacks
```
4688/592      New Process (Malware dropper, initial installation)
7045/601      New Service Install (Service added to endpoint) 
4624/528/540  Account log in 
4663/567      File & registry auditing (Files or registry new keys added, CryptoWare and malware drops)
5156          Windows Firewall Network allowed connection by process
7040          Service Change of State 
5140/560      Share accessed (crawling shares on different systems)
4657          Registry value modified
4698          New Task Created 
4769/4771     Kerberos failed attempts (Kerberos spraying, Kerberoasting)
```
 
#### Sysmon event codes for more granular investigation
```
  1   Provides hash of the process/file (4688)  (identify known malicious hash)
  3   Provides some name resolution of IP (5156)
  7   Image Loaded  (unsigned malware)
 15   File create stream hash
 17   Pipe event created
 18   Pipe event connected
 22   Provides process that made DNS query
255   Sysmon error
```
