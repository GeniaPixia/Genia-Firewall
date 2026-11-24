#Requires -Version 7.0
<#
.SYNOPSIS
    Read-only comparison of Windows Defender Firewall rule metadata before and after
    launching the independent GeniaFirewall Intelligence test GUI.

.NOTES
    Does NOT inspect native WFP filters installed directly through WFP API.
    Does NOT verify packet routes, protection effectiveness, DNS or VPN leaks.
    Does NOT modify firewall policy, system services, registry or event logs.
    Records only counts and SHA-256 digests in this PowerShell session; no file output.
    Run without elevation unless local policy requires read permissions.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RuleFingerprint {
    param([Parameter(Mandatory)][string]$Store)

    $rules = @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop |
        Sort-Object -Property Name, PolicyStoreSource, DisplayName |
        ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name
                DisplayName = [string]$_.DisplayName
                Enabled = [string]$_.Enabled
                Direction = [string]$_.Direction
                Action = [string]$_.Action
                Profile = [string]$_.Profile
                PolicyStoreSource = [string]$_.PolicyStoreSource
                PolicyStoreSourceType = [string]$_.PolicyStoreSourceType
            }
        })

    $json = ConvertTo-Json -InputObject $rules -Depth 3 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $digest = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes))

    return [pscustomobject]@{ Store = $Store; Count = $rules.Count; Sha256 = $digest }
}

try {
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'Get-NetFirewallRule is unavailable. Cannot compare Windows Firewall rules.'
    }

    Write-Host '=== GeniaFirewall Intelligence: firewall-rule snapshot (READ ONLY) ==='
    Write-Host 'Do not change firewall settings or install applications during this check.'
    Write-Host 'Note: this does NOT inspect direct WFP API filters.'
    $before = @(
        Get-RuleFingerprint -Store 'ActiveStore'
        Get-RuleFingerprint -Store 'PersistentStore'
    )
    foreach ($record in $before) {
        Write-Host ("BEFORE {0}: rules={1}, sha256={2}" -f
            $record.Store, $record.Count, $record.Sha256)
    }

    Read-Host 'Now open the standalone Intelligence Smoke EXE, click Refresh, close it; press Enter here afterward' | Out-Null

    $after = @(
        Get-RuleFingerprint -Store 'ActiveStore'
        Get-RuleFingerprint -Store 'PersistentStore'
    )
    $changed = $false
    foreach ($old in $before) {
        $new = $after | Where-Object Store -EQ $old.Store | Select-Object -First 1
        if ($null -eq $new) { throw ('Missing second snapshot: ' + $old.Store) }
        $same = $old.Count -eq $new.Count -and $old.Sha256 -eq $new.Sha256
        if (-not $same) { $changed = $true }
        Write-Host ("AFTER {0}: rules={1}, sha256={2}" -f
            $new.Store, $new.Count, $new.Sha256)
        Write-Host ("{0}={1}" -f
            $old.Store.ToUpperInvariant(),
            $(if ($same) { 'UNCHANGED' } else { 'CHANGED_REVIEW_REQUIRED' }))
    }

    if ($changed) {
        Write-Warning 'Windows Firewall rule metadata changed; this does not identify which process changed it.'
        Write-Host 'DIRECT_WFP_FILTERS=NOT_CHECKED'
        exit 3
    }

    Write-Host 'WINDOWS_FIREWALL_RULE_METADATA=UNCHANGED_PASS'
    Write-Host 'DIRECT_WFP_FILTERS=NOT_CHECKED'
    exit 0
}
catch {
    Write-Warning ('Unable to complete read-only comparison: ' + $_.Exception.Message)
    Write-Host 'WINDOWS_FIREWALL_RULE_METADATA=INCONCLUSIVE'
    Write-Host 'DIRECT_WFP_FILTERS=NOT_CHECKED'
    exit 2
}
