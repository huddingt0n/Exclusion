[CmdletBinding()]
param(
    [string]$Directory,

    [ValidateRange(1, 4)]
    [int]$Depth = 1,

    [ValidateRange(0, 5000)]
    [int]$ThrottleMs = 100,

    [string]$Output,

    [switch]$Help
)

function Show-Banner {
    $art = @'
 _____         _           _             
|  ___|       | |         (_)            
| |____  _____| |_   _ ___ _  ___  _ __  
|  __\ \/ / __| | | | / __| |/ _ \| '_ \ 
| |___>  < (__| | |_| \__ \ | (_) | | | |
\____/_/\_\___|_|\__,_|___/_|\___/|_| |_|
'@

    Write-Host $art
}

function Show-BannerSpacer {
    $art = @'
_,.-'~'-.,__,.-'~'-.,__,.-'~'-.,__,.-'~'-.,__,.-'~'-.,_
'@

    Write-Host $art
}

function Show-Help {
    Write-Host
    Write-Host "USAGE"
    Write-Host "  .\exclusion.ps1 -Directory <path> [-Depth <1-4>] [-ThrottleMs <0-5000>] [-Output <file>]"
    Write-Host "  .\exclusion.ps1 -Help"
    Write-Host
    Write-Host "PARAMETERS"
    Write-Host "  -Directory <string>"
    Write-Host "      Root directory to inspect. Required for a scan."
    Write-Host "      The root and its subdirectories (up to -Depth) are probed"
    Write-Host "      for effective Microsoft Defender exclusions."
    Write-Host
    Write-Host "  -Depth <int>   (default: 1, range: 1-4)"
    Write-Host "      Recursion depth below the root. Depth 1 checks the root plus"
    Write-Host "      its immediate children. Higher values recurse further."
    Write-Host
    Write-Host "  -ThrottleMs <int>   (default: 100, range: 0-5000)"
    Write-Host "      Milliseconds to sleep between MpCmdRun invocations. Increase"
    Write-Host "      this if your EDR flags rapid process creation."
    Write-Host
    Write-Host "  -Output <string>"
    Write-Host "      Optional file path to save the scan results. Format is chosen"
    Write-Host "      from the extension: .csv, .json, or plain-text table otherwise."
    Write-Host "      Parent directory must already exist."
    Write-Host
    Write-Host "  -Help"
    Write-Host "      Show this help text and exit."
    Write-Host
}

function Get-UserPermission {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch {
        return 'Unknown'
    }

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid   = $identity.User.Value
    $groupSids = @($identity.Groups | ForEach-Object { $_.Value })

    $allowRead  = $false
    $allowWrite = $false
    $denyRead   = $false
    $denyWrite  = $false

    foreach ($rule in $acl.Access) {
        try {
            $ruleSid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        } catch {
            continue
        }

        if ($ruleSid -ne $userSid -and $groupSids -notcontains $ruleSid) {
            continue
        }

        $rights   = $rule.FileSystemRights
        $hasRead  = ($rights -band [Security.AccessControl.FileSystemRights]::ReadData)   -ne 0
        $hasWrite = (($rights -band [Security.AccessControl.FileSystemRights]::WriteData) -ne 0) -or
                    (($rights -band [Security.AccessControl.FileSystemRights]::AppendData) -ne 0)

        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            if ($hasRead)  { $denyRead  = $true }
            if ($hasWrite) { $denyWrite = $true }
        } else {
            if ($hasRead)  { $allowRead  = $true }
            if ($hasWrite) { $allowWrite = $true }
        }
    }

    $canRead  = $allowRead  -and -not $denyRead
    $canWrite = $allowWrite -and -not $denyWrite

    if ($canRead -and $canWrite) { return 'Read/Write' }
    if ($canRead)                { return 'Read' }
    if ($canWrite)               { return 'Write' }
    return 'None'
}

if ($Help -or -not $Directory) {
    Write-Host
    Show-Banner
    Write-Host
    Show-BannerSpacer
    Show-Help
    return
}

$outputFullPath = $null
$outputFormat   = $null

if ($Output) {
    if ([System.IO.Path]::IsPathRooted($Output)) {
        $outputFullPath = $Output
    } else {
        $outputFullPath = Join-Path -Path (Get-Location).ProviderPath -ChildPath $Output
    }

    $outputParent = Split-Path -Path $outputFullPath -Parent

    if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
        throw "Output directory does not exist: $outputParent"
    }

    switch -Regex ([System.IO.Path]::GetExtension($outputFullPath).ToLower()) {
        '^\.csv$'  { $outputFormat = 'Csv'  }
        '^\.json$' { $outputFormat = 'Json' }
        default    { $outputFormat = 'Text' }
    }
}

$rootItem = Get-Item -LiteralPath $Directory -ErrorAction Stop

if (-not $rootItem.PSIsContainer) {
    throw "Not a directory: $Directory"
}

$root = $rootItem.FullName

$mp = Get-ChildItem `
    "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" `
    -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $mp) {
    $mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
}

if (-not (Test-Path -LiteralPath $mp -PathType Leaf)) {
    throw "MpCmdRun.exe could not be found."
}

$notifKey        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.Defender.SecurityCenter'
$notifKeyExisted = Test-Path -LiteralPath $notifKey

$notifValueExisted = $false
$notifPrevValue    = $null

if ($notifKeyExisted) {
    $existing = Get-ItemProperty -LiteralPath $notifKey -Name Enabled -ErrorAction SilentlyContinue
    if ($null -ne $existing -and $null -ne $existing.Enabled) {
        $notifValueExisted = $true
        $notifPrevValue    = $existing.Enabled
    }
} else {
    New-Item -Path $notifKey -Force | Out-Null
}

Set-ItemProperty -LiteralPath $notifKey -Name Enabled -Value 0 -Type DWord -Force

try {
    Write-Host
    Show-Banner
    Write-Host
    Show-BannerSpacer
    Write-Host

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    Write-Host "(*) Current user : $currentUser"
    Write-Host "(+) Host         : $env:COMPUTERNAME"
    Write-Host "(*) Target       : $root"
    Write-Host "(+) Depth        : $Depth"
    Write-Host "(*) Throttle     : $ThrottleMs ms"
    Write-Host "(+) Defender     : $mp"
    if ($outputFullPath) {
        Write-Host "(+) Save to      : $outputFullPath ($outputFormat)"
    }
    Write-Host
    Write-Host "-={           OUTPUT BELOW           }=-"

    $enumerationErrors = @()

    $targets = @($root) + @(
        Get-ChildItem -LiteralPath $root `
            -Directory `
            -Recurse `
            -Depth $Depth `
            -ErrorAction SilentlyContinue `
            -ErrorVariable +enumerationErrors |
        Select-Object -ExpandProperty FullName
    )

    $targets = @($targets | Sort-Object -Unique)

    if ($enumerationErrors.Count -gt 0) {
        Write-Warning "Skipped $($enumerationErrors.Count) inaccessible locations."
    }

    try {
        $maxLen = ($targets | Measure-Object -Property Length -Maximum).Maximum
        if ($null -eq $maxLen) { $maxLen = 0 }

        $needed = [int]($maxLen + 40)
        if ($needed -lt 120) { $needed = 120 }

        $raw = $Host.UI.RawUI
        if ($needed -gt $raw.BufferSize.Width) {
            $raw.BufferSize = New-Object Management.Automation.Host.Size(
                $needed, $raw.BufferSize.Height
            )
        }
    } catch {
        Write-Verbose "Could not widen console buffer: $_"
    }

    $processed  = 0
    $firstProbe = $true
    $results    = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $targets) {
        $processed++

        Write-Progress `
            -Activity "Checking Defender exclusion status" `
            -Status   $target `
            -PercentComplete (($processed / $targets.Count) * 100)

        $probePath = "$target\|*"

        $message = & $mp -Scan -ScanType 3 -File $probePath 2>&1
        $text    = ($message -join ' ').Trim()

        if ($text -match '(?i)was skipped') {
            $results.Add(
                [pscustomobject]@{
                    Path        = $target
                    Excluded    = $true
                    Permissions = Get-UserPermission -Path $target
                }
            )
        }
        elseif ($text -match '0x80508023' -or $text -match '(?i)Failed with hr') {
        }
        else {
            if ($firstProbe) {
                throw "MpCmdRun probe returned an unexpected response for '$target': $text"
            }
            Write-Warning "Unexpected response for '$target': $text"
        }

        $firstProbe = $false

        if ($ThrottleMs -gt 0) {
            Start-Sleep -Milliseconds $ThrottleMs
        }
    }

    Write-Progress -Activity "Checking Defender exclusion status" -Completed

    if ($outputFullPath) {
        try {
            switch ($outputFormat) {
                'Csv' {
                    $results | Export-Csv -LiteralPath $outputFullPath -NoTypeInformation -Encoding UTF8 -Force
                }
                'Json' {
                    $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $outputFullPath -Encoding UTF8 -Force
                }
                'Text' {
                    # Match what the console shows, without the banner.
                    if ($results.Count -gt 0) {
                        $table = $results | Format-Table -AutoSize | Out-String -Width 4096
                    } else {
                        $table = "(no exclusions found)`r`n"
                    }
                    Set-Content -LiteralPath $outputFullPath -Value $table -Encoding UTF8 -Force
                }
            }
        } catch {
            Write-Warning "Failed to write output file '$outputFullPath': $_"
        }
    }

    $results
}
finally {
    if ($notifValueExisted) {
        Set-ItemProperty -LiteralPath $notifKey -Name Enabled -Value $notifPrevValue -Type DWord -Force
    } else {
        Remove-ItemProperty -LiteralPath $notifKey -Name Enabled -ErrorAction SilentlyContinue
    }

    if (-not $notifKeyExisted) {
        $remaining = Get-Item -LiteralPath $notifKey -ErrorAction SilentlyContinue
        if ($remaining -and $remaining.Property.Count -eq 0) {
            Remove-Item -LiteralPath $notifKey -Force -ErrorAction SilentlyContinue
        }
    }
}