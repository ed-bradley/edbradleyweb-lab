
<#
.SYNOPSIS
  Remove EDW lab scaffold (v3). Exports inventory/backup to the local Reports folder (same pattern as Create script),
  removes GPOs by prefix, and deletes the EDW OU subtree.

.NOTES
  Run elevated. Requires: ActiveDirectory, GroupPolicy modules.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [string]$RootOuName = "EDW",
  [string]$GpoPrefix  = "EDW - ",
  [switch]$Force
)

function Ensure-Module { param([string]$Name) if (-not (Get-Module -ListAvailable -Name $Name)) { throw "Required module '$Name' not available." } Import-Module $Name -ErrorAction Stop }
function Get-DomainDN { (Get-ADDomain -ErrorAction Stop).DistinguishedName }

function Get-ReportsPath {
  # Mirror the Create script: drop artifacts under a local "Reports" folder next to the script
  $base = Split-Path -Path $PSCommandPath -Parent
  $rep  = Join-Path $base 'Reports'
  if (-not (Test-Path $rep)) { New-Item -ItemType Directory -Path $rep | Out-Null }
  return $rep
}

function Export-Inventory([string]$RootDn,[string]$ReportsPath){
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $outDir = Join-Path $ReportsPath ("EDW_Teardown_{0}" -f $stamp)
  New-Item -ItemType Directory -Path $outDir | Out-Null
  Write-Host ("Exporting inventory to {0} ..." -f $outDir) -ForegroundColor Cyan

  Get-ADUser -Filter * -SearchBase $RootDn -SearchScope Subtree -Properties * |
    Select-Object Name,SamAccountName,DistinguishedName,Enabled,Department,mail |
    Export-Csv -NoTypeInformation -Path (Join-Path $outDir "users.csv")

  Get-ADComputer -Filter * -SearchBase $RootDn -SearchScope Subtree -Properties * |
    Select-Object Name,DistinguishedName,Enabled,OperatingSystem |
    Export-Csv -NoTypeInformation -Path (Join-Path $outDir "computers.csv")

  Get-ADGroup -Filter * -SearchBase $RootDn -SearchScope Subtree -Properties * |
    Select-Object Name,DistinguishedName,GroupScope,GroupCategory |
    Export-Csv -NoTypeInformation -Path (Join-Path $outDir "groups.csv")

  Get-ADOrganizationalUnit -Filter * -SearchBase $RootDn -SearchScope Subtree -Properties * |
    Select-Object Name,DistinguishedName,ProtectedFromAccidentalDeletion |
    Export-Csv -NoTypeInformation -Path (Join-Path $outDir "ous.csv")

  $gpos = Get-GPO -All | Where-Object { $_.DisplayName -like "$GpoPrefix*" }
  $gpos | Select-Object DisplayName,Id |
    Export-Csv -NoTypeInformation -Path (Join-Path $outDir "gpos.csv")

  Write-Host "Inventory export complete." -ForegroundColor Green
  return $outDir
}

function Clear-OUProtectionRecursively([string]$RootDn){
  Write-Host "Clearing 'Protect from accidental deletion' on OU subtree..." -ForegroundColor Cyan
  $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $RootDn -SearchScope Subtree -Properties ProtectedFromAccidentalDeletion
  foreach ($ou in $ous) {
    if ($ou.ProtectedFromAccidentalDeletion) {
      try {
        Set-ADOrganizationalUnit -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion:$false -ErrorAction Stop
      } catch {
        Write-Warning ("Failed to clear protection on: {0} -> {1}" -f $ou.DistinguishedName, $_.Exception.Message)
      }
    }
  }
  try { Set-ADOrganizationalUnit -Identity $RootDn -ProtectedFromAccidentalDeletion:$false -ErrorAction Stop } catch {}
}

function Remove-EDWGPOs([string]$Prefix,[switch]$ForceLocal){
  $gpos = Get-GPO -All | Where-Object { $_.DisplayName -like "$Prefix*" }
  if (-not $gpos) { Write-Host ("No GPOs found with prefix '{0}'." -f $Prefix) -ForegroundColor Yellow; return }
  Write-Host ("Found {0} GPO(s) with prefix '{1}'" -f $gpos.Count,$Prefix) -ForegroundColor Cyan
  foreach ($gpo in $gpos) {
    if ($PSCmdlet.ShouldProcess(("GPO '{0}'" -f $gpo.DisplayName),"Remove-GPO")) {
      try {
        Remove-GPO -Guid $gpo.Id -Confirm:(!$ForceLocal) -ErrorAction Stop
        Write-Host ("Removed GPO: {0}" -f $gpo.DisplayName) -ForegroundColor Green
      } catch { Write-Warning ("Failed to remove GPO '{0}': {1}" -f $gpo.DisplayName, $_.Exception.Message) }
    }
  }
}

try { Ensure-Module ActiveDirectory; Ensure-Module GroupPolicy } catch { Write-Error $_; exit 1 }

$domainDN = Get-DomainDN
$rootDN   = "OU=$RootOuName,$domainDN"
$rootOu = Get-ADOrganizationalUnit -LDAPFilter "(ou=$RootOuName)" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue
if (-not $rootOu) { Write-Error ("Root OU '{0}' not found under {1}. Nothing to remove." -f $RootOuName, $domainDN); exit 1 }

if (-not $Force) {
  Write-Warning ("You are about to DELETE everything under: {0}" -f $rootDN)
  $confirm = Read-Host "Type YES to continue"
  if ($confirm -ne "YES") { Write-Host "Aborted." -ForegroundColor Yellow; exit 0 }
}

$reports = Get-ReportsPath
$backupDir = Export-Inventory -RootDn $rootDN -ReportsPath $reports

Remove-EDWGPOs -Prefix $GpoPrefix -ForceLocal:$Force
Clear-OUProtectionRecursively -RootDn $rootDN

if ($PSCmdlet.ShouldProcess($rootDN,"Remove-ADOrganizationalUnit -Recursive")) {
  try {
    Remove-ADOrganizationalUnit -Identity $rootDN -Recursive -Confirm:(!$Force) -ErrorAction Stop
    Write-Host ("Deleted OU subtree: {0}" -f $rootDN) -ForegroundColor Green
  } catch { Write-Error ("Failed to delete OU subtree: {0}" -f $_.Exception.Message) }
}

Write-Host ("Teardown complete. Inventory saved to: {0}" -f $backupDir) -ForegroundColor Green
