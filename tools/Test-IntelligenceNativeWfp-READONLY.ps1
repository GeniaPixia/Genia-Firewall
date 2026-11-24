#Requires -Version 7.0
<#
Read-only WFP filter-export comparison; no policy writes or capture sessions.
Raw XML is temporarily stored under the current user's TEMP and removed after reading.
No XML, filter names, application paths, IPs or individual keys are printed.
Requires an elevated PowerShell for WFP enumeration, NOT for the standalone test GUI.
Three snapshots do not detect transient changes between snapshots, or verify enforcement.
#>
[CmdletBinding()]
param([switch]$SelfTest, [switch]$SnapshotOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Provider = [guid]'A6EE1C6D-0D49-4B3F-B240-98ED3FFBB1C3'
$SubLayer = [guid]'DC5AE30A-AC35-4A21-A730-340BC721A3A9'

function Get-Digest([string]$Text) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($Text)))
}

function Get-SetDigest([System.Collections.Generic.List[string]]$Hashes) {
    $a = $Hashes.ToArray()
    [Array]::Sort($a, [StringComparer]::Ordinal)
    Get-Digest ($a -join "\n")
}

function Get-Inventory([System.Xml.XmlDocument]$Document) {
    $root = $Document.SelectSingleNode("/*[local-name()='wfpdiag']/*[local-name()='filters']")
    if ($null -eq $root) { throw 'Unrecognized WFP filters XML layout' }
    $items = $root.SelectNodes("./*[local-name()='item']")
    if ($items.Count -eq 0) { throw 'Empty WFP export: cannot establish a baseline' }
    if ($root.HasAttribute('numItems')) {
        $declared = 0
        if (-not [int]::TryParse($root.GetAttribute('numItems'), [ref]$declared) -or $declared -ne $items.Count) {
            throw 'Export count mismatch'
        }
    }
    $all = [System.Collections.Generic.List[string]]::new()
    $owned = [System.Collections.Generic.List[string]]::new()
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $items) {
        $id = $item.SelectSingleNode("./*[local-name()='filterId']")
        $layer = $item.SelectSingleNode("./*[local-name()='layerKey']")
        $sub = $item.SelectSingleNode("./*[local-name()='subLayerKey']")
        $action = $item.SelectSingleNode("./*[local-name()='action']")
        if ($null -eq $id -or $null -eq $layer -or $null -eq $sub -or $null -eq $action -or
            [string]::IsNullOrWhiteSpace($id.InnerText) -or
            -not $ids.Add($id.InnerText.Trim())) {
            throw 'Invalid or duplicate WFP filter record'
        }
        $providerNode = $item.SelectSingleNode("./*[local-name()='providerKey']")
        $p = [guid]::Empty
        $s = [guid]::Empty
        $byProvider = $null -ne $providerNode -and
            [guid]::TryParse($providerNode.InnerText.Trim(), [ref]$p) -and $p -eq $Provider
        $bySubLayer = [guid]::TryParse($sub.InnerText.Trim(), [ref]$s) -and $s -eq $SubLayer
        # Hash the complete exported filter record, including IDs, conditions,
        # weights, flags and action. Reordering whole filter records is ignored.
        $hash = Get-Digest $item.OuterXml
        $all.Add($hash)
        if ($byProvider -or $bySubLayer) { $owned.Add($hash) }
    }
    [pscustomobject]@{
        AllCount = $all.Count
        AllSha256 = Get-SetDigest $all
        OwnedCount = $owned.Count
        OwnedSha256 = Get-SetDigest $owned
    }
}

function Read-Inventory {
    $directory = [IO.Directory]::CreateTempSubdirectory('GeniaWfpAudit-')
    $path = Join-Path $directory.FullName 'filters.xml'
    try {
        $netsh = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
        & $netsh wfp show filters "file=$path" verbose=on | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "netsh WFP filter export failed (exit $LASTEXITCODE)"
        }
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 128MB
        $reader = [Xml.XmlReader]::Create($path, $settings)
        try {
            $doc = [Xml.XmlDocument]::new()
            $doc.XmlResolver = $null
            $doc.PreserveWhitespace = $false
            $doc.Load($reader)
        }
        finally { $reader.Dispose() }
        Get-Inventory $doc
    }
    finally {
        # Delete only the exact file and uniquely allocated directory.
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
        }
        [IO.Directory]::Delete($directory.FullName, $false)
    }
}

function Show-Inventory([string]$Phase, $Inventory) {
    Write-Host ("{0} ALL_FILTERS={1} SHA256={2}" -f $Phase, $Inventory.AllCount, $Inventory.AllSha256)
    Write-Host ("{0} GENIA_FILTERS={1} SHA256={2}" -f $Phase, $Inventory.OwnedCount, $Inventory.OwnedSha256)
}

function Test-Equal($A, $B, [switch]$Owned) {
    if ($Owned) {
        return $A.OwnedCount -eq $B.OwnedCount -and $A.OwnedSha256 -eq $B.OwnedSha256
    }
    return $A.AllCount -eq $B.AllCount -and $A.AllSha256 -eq $B.AllSha256
}

function Invoke-SelfTest {
    $one = "<item><filterId>1</filterId><providerKey>{$Provider}</providerKey><layerKey>L</layerKey><subLayerKey>{$SubLayer}</subLayerKey><action><type>BLOCK</type></action></item>"
    $two = '<item><filterId>2</filterId><providerKey/><layerKey>L</layerKey><subLayerKey>Other</subLayerKey><action><type>PERMIT</type></action></item>'
    $a = Get-Inventory ([xml]"<wfpdiag><filters numItems='2'>$one$two</filters></wfpdiag>")
    $b = Get-Inventory ([xml]"<wfpdiag><filters numItems='2'>$two$one</filters></wfpdiag>")
    if ($a.AllCount -ne 2 -or $a.OwnedCount -ne 1 -or
        -not (Test-Equal $a $b) -or -not (Test-Equal $a $b -Owned)) { throw 'Reordering self-test failed' }
    $changed = $one.Replace('BLOCK','PERMIT')
    $c = Get-Inventory ([xml]"<wfpdiag><filters numItems='2'>$changed$two</filters></wfpdiag>")
    if ((Test-Equal $a $c) -or (Test-Equal $a $c -Owned)) { throw 'Mutation detection self-test failed' }
    $d = Get-Inventory ([xml]"<wfpdiag><filters numItems='1'>$two</filters></wfpdiag>")
    if ($d.OwnedCount -ne 0 -or (Test-Equal $a $d -Owned)) { throw 'Missing owner self-test failed' }
    foreach ($invalid in @('<wfpdiag/>', '<wfpdiag><filters/></wfpdiag>',
        "<wfpdiag><filters numItems='3'>$one$two</filters></wfpdiag>",
        "<wfpdiag><filters>$one$one</filters></wfpdiag>")) {
        $rejected = $false
        try { $null = Get-Inventory ([xml]$invalid) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Malformed/empty/duplicate input accepted' }
    }
    Write-Host 'WFP_AUDIT_SELFTEST=PASS'
}

try {
    if ($SelfTest) { Invoke-SelfTest; exit 0 }
    if (-not $IsWindows) { throw 'Windows is required' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Open PowerShell 7 as Administrator for the WFP read-only export'
        }
    } finally { $identity.Dispose() }

    Write-Host '=== Native WFP exported filter audit (READ ONLY) ==='
    Write-Host 'Keep production firewall, VPN, policy and services unchanged.'
    $before = Read-Inventory
    Show-Inventory 'BEFORE' $before
    if ($SnapshotOnly) {
        Write-Host 'WFP_EXPORT_READ=PASS'
        Write-Host 'NATIVE_WFP_FILTER_SNAPSHOT_GATE=NOT_RUN'
        exit 0
    }
    if ($before.OwnedCount -eq 0) {
        Write-Host 'GENIA_BASELINE=NO_OWNED_FILTERS'
        Write-Host 'NATIVE_WFP_FILTER_SNAPSHOT_GATE=INCONCLUSIVE'
        exit 2
    }

    Read-Host 'Open standalone Intelligence from Explorer (normal user), click Refresh, KEEP it open, then press Enter here' | Out-Null
    $during = Read-Inventory
    Show-Inventory 'DURING' $during
    Read-Host 'Close the standalone Intelligence GUI, then press Enter here' | Out-Null
    $after = Read-Inventory
    Show-Inventory 'AFTER' $after

    $allSame = (Test-Equal $before $during) -and (Test-Equal $before $after)
    $ownedSame = (Test-Equal $before $during -Owned) -and (Test-Equal $before $after -Owned)
    Write-Host ('ALL_EXPORTED_FILTERS=' + $(if ($allSame) {'UNCHANGED'} else {'CHANGED_REVIEW_REQUIRED'}))
    Write-Host ('GENIA_EXPORTED_FILTERS=' + $(if ($ownedSame) {'UNCHANGED'} else {'CHANGED_REVIEW_REQUIRED'}))
    Write-Host 'CONTINUOUS_MUTATION_MONITOR=NOT_CHECKED'
    Write-Host 'WFP_ENFORCEMENT=NOT_CHECKED'
    if (-not ($allSame -and $ownedSame)) {
        Write-Host 'NATIVE_WFP_FILTER_SNAPSHOT_GATE=CHANGED_REVIEW_REQUIRED'
        exit 3
    }
    Write-Host 'NATIVE_WFP_FILTER_SNAPSHOT_GATE=UNCHANGED_PASS'
    exit 0
}
catch {
    Write-Warning ('Read-only audit incomplete: ' + $_.Exception.Message)
    Write-Host 'NATIVE_WFP_FILTER_SNAPSHOT_GATE=INCONCLUSIVE'
    exit 2
}
