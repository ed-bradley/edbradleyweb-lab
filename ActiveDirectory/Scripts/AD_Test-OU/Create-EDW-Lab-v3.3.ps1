<#
.SYNOPSIS
  Create EDW lab scaffold (v3.3, PowerShell 5.1 compatible, idempotent/re-run-safe).
  - OUs: EDW root, per-dept, Users/Computers/Laptops children
  - Groups: per-dept (GG-<Dept>-Users/Computers), Wi-Fi groups at EDW\Groups
  - Users: 100 random users evenly distributed, random strong passwords, CSV manifest
  - UPN format: First.Last@<UPNSuffix> with AD-aware uniqueness (First.Last2, First.Last3, ...)
  - sAMAccountName: Firstname.Lastname (lowercase) with AD-aware uniqueness and <=20 char enforcement
  - GPOs: create and link baseline GPOs (Enforced Yes/No)

.NOTES
  Run elevated as a member of Domain Admins + Group Policy Creator Owners.
  Requires modules: ActiveDirectory, GroupPolicy.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [int]$UserCount = 100,
  [string]$RootOuName = "EDW",
  [string]$GpoPrefix = "EDW - ",
  [string]$UPNSuffix = "edbradleyweb.local"   # Change if you add more UPN suffixes
)

function Ensure-Module { param([string]$Name) if (-not (Get-Module -ListAvailable -Name $Name)) { throw "Required module '$Name' not available." } Import-Module $Name -ErrorAction Stop }
function Get-DomainDN { (Get-ADDomain -ErrorAction Stop).DistinguishedName }
function Require-AdminGroups {
  $who=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  $groups=(whoami /groups) -join "`n"
  $need=@('Domain Admins','Group Policy Creator Owners')
  $missing=$need | Where-Object { $groups -notmatch [regex]::Escape($_) }
  if($missing){ throw ("Preflight failed for {0}. Missing: {1}. Log off/on or run as 'edbradleyweb\\Administrator'." -f $who, ($missing -join ', ')) }
}

function New-SafeOU([string]$Name,[string]$ParentDN,[bool]$Protect=$true){
  $exists=Get-ADOrganizationalUnit -LDAPFilter ("(ou={0})" -f $Name) -SearchBase $ParentDN -SearchScope OneLevel -ErrorAction SilentlyContinue
  if(-not $exists){
    Write-Host ("Creating OU: OU={0},{1}" -f $Name,$ParentDN) -ForegroundColor Cyan
    New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion:$Protect -ErrorAction Stop | Out-Null
  } else { Write-Host ("OU exists: OU={0},{1}" -f $Name,$ParentDN) }
  "OU={0},{1}" -f $Name,$ParentDN
}
function New-SafeGroup([string]$Name,[string]$Path,[ValidateSet('Global','DomainLocal','Universal')][string]$Scope='Global'){
  $exists=Get-ADGroup -LDAPFilter ("(cn={0})" -f $Name) -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue
  if(-not $exists){
    Write-Host ("Creating Group: CN={0} in {1}" -f $Name,$Path) -ForegroundColor Cyan
    New-ADGroup -Name $Name -GroupScope $Scope -Path $Path -GroupCategory Security -ErrorAction Stop | Out-Null
  } else { Write-Host ("Group exists: {0}" -f $Name) }
}
function Ensure-GPO([string]$Name){
  $g=Get-GPO -All -ErrorAction Stop | Where-Object { $_.DisplayName -eq $Name }
  if(-not $g){ Write-Host ("Creating GPO: {0}" -f $Name) -ForegroundColor Cyan; $g=New-GPO -Name $Name -ErrorAction Stop }
  else{ Write-Host ("GPO exists: {0}" -f $Name) }
  $g
}
function Ensure-GPLink([string]$GpoName,[string]$TargetDn,[ValidateSet('Yes','No')][string]$Enforced='No'){
  $ou=Get-ADOrganizationalUnit -Identity $TargetDn -ErrorAction SilentlyContinue
  if(-not $ou){ throw ("GPLink target not found: {0}" -f $TargetDn) }
  $inherit=Get-GPInheritance -Target $TargetDn -ErrorAction Stop
  $existing=$inherit.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
  if(-not $existing){
    Write-Host ("Linking GPO '{0}' to {1} (Enforced={2})" -f $GpoName,$TargetDn,$Enforced) -ForegroundColor Cyan
    New-GPLink -Name $GpoName -Target $TargetDn -Enforced $Enforced -ErrorAction Stop | Out-Null
  }
  elseif($existing.Enforced -ne $Enforced){
    Write-Host ("Updating link enforcement on '{0}' at {1} -> {2}" -f $GpoName,$TargetDn,$Enforced) -ForegroundColor Cyan
    Set-GPLink -Name $GpoName -Target $TargetDn -Enforced $Enforced -ErrorAction Stop
  }
  else{ Write-Host ("GPO link already present: '{0}' @ {1} (Enforced={2})" -f $GpoName,$TargetDn,$Enforced) }
}

# Random names & password helpers
$FirstNames='Liam','Olivia','Noah','Emma','Oliver','Ava','Elijah','Sophia','James','Isabella','William','Mia','Benjamin','Charlotte','Lucas','Amelia','Henry','Harper','Alexander','Evelyn','Michael','Abigail','Daniel','Emily','Logan','Elizabeth','Jackson','Avery','Sebastian','Sofia','Jack','Scarlett','Owen','Chloe','Theodore','Ella','Aiden','Grace','Samuel','Victoria','Joseph','Riley','John','Zoey','David','Nora','Wyatt','Lily','Matthew','Hannah'
$LastNames='Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez','Hernandez','Lopez','Gonzalez','Wilson','Anderson','Thomas','Taylor','Moore','Jackson','Martin','Lee','Perez','Thompson','White','Harris','Sanchez','Clark','Ramirez','Lewis','Robinson','Walker','Young','Allen','King','Wright','Scott','Torres','Nguyen','Hill','Flores','Green','Adams','Nelson','Baker','Hall','Rivera','Campbell','Mitchell','Carter','Roberts'

function New-RandomPassword([int]$Length=14){
  $sets=@(
    { [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ' | Get-Random },
    { [char[]]'abcdefghijklmnopqrstuvwxyz' | Get-Random },
    { [char[]]'0123456789' | Get-Random },
    { [char[]]'!@#$%^&*_-+=?' | Get-Random }
  )
  $pwd=@(); foreach($s in $sets){ $pwd += (& $s) }
  $all=([char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=?')
  for($i=$pwd.Count; $i -lt $Length; $i++){ $pwd += ($all | Get-Random) }
  -join ($pwd | Get-Random -Count $pwd.Count)
}

function Sanitize-Token([string]$s){
  if([string]::IsNullOrWhiteSpace($s)){ return "" }
  return ($s -replace "[^A-Za-z0-9]", "")
}

# sAMAccountName base: Firstname.Lastname (lowercase), AD-aware uniqueness with numeric suffix
# sAMAccountName max length is 20 chars. We trim the base to leave room for a numeric suffix when needed.
function New-UniqueSamAD([string]$Given,[string]$Surname,[object]$Taken){
  $g = Sanitize-Token $Given
  $sn = Sanitize-Token $Surname
  if([string]::IsNullOrWhiteSpace($g)){ $g = "User" }
  if([string]::IsNullOrWhiteSpace($sn)){ $sn = "Person" }

  $base = ("{0}.{1}" -f $g.ToLower(), $sn.ToLower())

  function Trim-ForSuffix([string]$b, [int]$suffixLen){
    $maxBase = 20 - $suffixLen
    if($maxBase -lt 1){ $maxBase = 1 }
    if($b.Length -gt $maxBase){ return $b.Substring(0, $maxBase) }
    return $b
  }

  $sam = Trim-ForSuffix -b $base -suffixLen 0
  $i = 1
  while($Taken.Contains($sam) -or (Get-ADUser -LDAPFilter ("(sAMAccountName={0})" -f $sam) -ErrorAction SilentlyContinue)){
    $sfx = $i.ToString()
    $sam = (Trim-ForSuffix -b $base -suffixLen $sfx.Length) + $sfx
    $i++
  }
  [void]$Taken.Add($sam)
  return $sam
}

# UPN base: First.Last (preserve capitalization), AD-aware uniqueness with numeric suffix
function New-UniqueUpnAD([string]$Given,[string]$Surname,[string]$Suffix){
  $g=Sanitize-Token $Given; $sn=Sanitize-Token $Surname
  if($g -eq ""){ $g="User" }
  if($sn -eq ""){ $sn="Person" }
  $base=("{0}.{1}" -f $g,$sn)
  $candidate=("{0}@{1}" -f $base,$Suffix)
  $i=2
  while(Get-ADUser -LDAPFilter ("(userPrincipalName={0})" -f $candidate) -ErrorAction SilentlyContinue){
    $candidate=("{0}{1}@{2}" -f $base,$i,$Suffix)
    $i++
  }
  $candidate
}

# ==== Main ====
try{ Ensure-Module ActiveDirectory; Ensure-Module GroupPolicy; Require-AdminGroups } catch { Write-Error $_; exit 1 }

$DomainDN=Get-DomainDN
$RootDN=("OU={0},{1}" -f $RootOuName,$DomainDN)

$Departments='Accounting','Sales','Human Resources','Information Technology','Research & Development','Shipping & Receiving','Marketing','Customer Service'

# OUs
$null=New-SafeOU -Name $RootOuName -ParentDN $DomainDN -Protect:$true
$GroupsDN=New-SafeOU -Name 'Groups' -ParentDN $RootDN -Protect:$true

foreach($dept in $Departments){
  $deptDn=New-SafeOU -Name $dept -ParentDN $RootDN -Protect:$true
  $usersDn=New-SafeOU -Name 'Users' -ParentDN $deptDn -Protect:$false
  $computersDn=New-SafeOU -Name 'Computers' -ParentDN $deptDn -Protect:$false
  $laptopsDn=New-SafeOU -Name 'Laptops' -ParentDN $deptDn -Protect:$false

  New-SafeGroup -Name ("GG-{0}-Users" -f $dept) -Path $deptDn -Scope Global
  New-SafeGroup -Name ("GG-{0}-Computers" -f $dept) -Path $deptDn -Scope Global
}

# Wi-Fi / NPS groups
$WifiGroups='GG-WiFi-Employees','GG-WiFi-Contractors','GG-WiFi-Devices'
foreach($g in $WifiGroups){ New-SafeGroup -Name $g -Path $GroupsDN -Scope Global }

# GPO Scaffold
$GpoNames=@(
  ("{0}Windows Baseline - Computers" -f $GpoPrefix),
  ("{0}Windows Baseline - Users" -f $GpoPrefix),
  ("{0}LAPS - Computers" -f $GpoPrefix)
)
$Gpos=@{}; foreach($n in $GpoNames){ $Gpos[$n]=Ensure-GPO $n }

foreach($dept in $Departments){
  Ensure-GPLink -GpoName $GpoNames[0] -TargetDn ("OU=Computers,OU={0},{1}" -f $dept,$RootDN) -Enforced No
  Ensure-GPLink -GpoName $GpoNames[0] -TargetDn ("OU=Laptops,OU={0},{1}"   -f $dept,$RootDN) -Enforced No
  Ensure-GPLink -GpoName $GpoNames[1] -TargetDn ("OU=Users,OU={0},{1}"      -f $dept,$RootDN) -Enforced No
}

# Users: even distribution
$basePer=[math]::Floor($UserCount / $Departments.Count)
$rem=$UserCount % $Departments.Count
$quota=@{}
for($i=0; $i -lt $Departments.Count; $i++){ $q=$basePer; if($i -lt $rem){ $q = $q + 1 }; $quota[$Departments[$i]] = $q }

$created=0
$TakenSam=[System.Collections.Generic.HashSet[string]]::new()
$rows=@()
Write-Host ("Creating {0} users across {1} departments..." -f $UserCount,$Departments.Count) -ForegroundColor Cyan

foreach($dept in $Departments){
  $targetOu=("OU=Users,OU={0},{1}" -f $dept,$RootDN)
  for($n=0;$n -lt $quota[$dept];$n++){
    $given=$FirstNames | Get-Random; $sur=$LastNames | Get-Random
    $display=("{0} {1}" -f $given,$sur)
    $sam=New-UniqueSamAD -Given $given -Surname $sur -Taken $TakenSam
    $upn=New-UniqueUpnAD -Given $given -Surname $sur -Suffix $UPNSuffix
    $pwd=New-RandomPassword
    try{
      Write-Host (" -> {0} -> {1}" -f $display,$targetOu)
      New-ADUser -Name $display -GivenName $given -Surname $sur -SamAccountName $sam -UserPrincipalName $upn -DisplayName $display `
        -EmailAddress $upn -Department $dept -Enabled $true -Path $targetOu `
        -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) -ChangePasswordAtLogon $true -ErrorAction Stop
      Add-ADGroupMember -Identity ("GG-{0}-Users" -f $dept) -Members $sam -ErrorAction Stop
      $rows += [pscustomobject]@{GivenName=$given;Surname=$sur;DisplayName=$display;SamAccount=$sam;UPN=$upn;Department=$dept;OU=$targetOu;Password=$pwd}
      $created++
    } catch { Write-Warning ("Failed to create user {0} in {1}: {2}" -f $display,$dept,$_.Exception.Message) }
  }
}

# Output / artifacts (Reports folder next to script)
$scriptDir = Split-Path -Path $PSCommandPath -Parent
$reportDir = Join-Path -Path $scriptDir -ChildPath "Reports"
if(-not (Test-Path $reportDir)){ New-Item -ItemType Directory -Path $reportDir | Out-Null }
$csvPath = Join-Path $reportDir "EDW_Lab_Users.csv"
$rows | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8

Write-Host ("Created/verified {0} users. CSV: {1}" -f $created,$csvPath) -ForegroundColor Green
Write-Host "All done." -ForegroundColor Green