<#
.SYNOPSIS
    Lists the Scheduled Tasks on a Windows host, or only the ones that look suspicious, and exports them to CSV.

.DESCRIPTION
    Option 1 - List all Scheduled Tasks (no filtering).
    Option 2 - Tasks that run or reference a file outside the Windows and Program Files directories,
               plus everything option 3 finds.
    Option 3 - Tasks that run or reference a file in a suspicious directory, run a script interpreter or
               LOLBin with a suspicious command line, use a COM handler overridden in a user's registry
               hive, or are hidden from Task Scheduler.

    The MatchReason column says why each task was listed. Run elevated for complete results: hidden-task
    detection (deleting a task's SD registry value, as the "Tarrask" malware does) only works as Administrator.

.PARAMETER Mode
    1, 2 or 3. You're prompted if it's left out, so always pass it when running through an EDR remote shell.

.PARAMETER OutputPath
    Where to write the CSV. Defaults to ScheduledTaskResults_<host>_<timestamp>.csv in the current directory.

.PARAMETER AllowlistPath
    CSV of expected tasks to leave out of the results. It needs a FullTaskPath column (* and ? wildcards
    allowed) and can have TargetSHA256 and TargetSigner columns. An entry with a hash only applies while the
    task's target file still has that hash; one with a signer only applies while the file has a valid
    signature from that signer, which survives updates (e.g. "Microsoft Windows Publisher" for Defender's
    tasks in ProgramData). A results CSV from a known-good host, trimmed to the rows you trust, works as-is.
    Hidden tasks are always reported.

.PARAMETER FileExtensions
    Extensions to look for in task arguments.

.PARAMETER SuspiciousDirectories
    Directory names, or partial paths like "Users\Public", matched against whole path segments.

.PARAMETER SkipFileInfo
    Skip hashing and signature checks. Faster, but allowlist entries with a TargetSHA256 or TargetSigner won't match.

.PARAMETER PassThru
    Also return the results as objects, e.g. to collect them from several hosts with Invoke-Command.

.EXAMPLE
    .\ScheduledTaskChecker.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\ScheduledTaskChecker.ps1 -Mode 3 -OutputPath C:\IR\tasks.csv

.EXAMPLE
    .\ScheduledTaskChecker.ps1 -Mode 2 -AllowlistPath .\GoldImageTasks.csv
#>
[CmdletBinding()]
param (
    [ValidateSet("1", "2", "3")]
    [string]$Mode,

    [string]$OutputPath,

    [string]$AllowlistPath,

    # Editable Filters
    [string[]]$FileExtensions = @(".exe", ".dll", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".pyw", ".scr", ".cpl", ".msi", ".lnk"),

    [string[]]$SuspiciousDirectories = @("ProgramData", "Temp", "Tmp", "Users\Public", "AppData", "Downloads", "PerfLogs", '$Recycle.Bin', "Windows\Tasks", "Windows\Tracing", "Windows\Debug", "spool\drivers\color"),

    [switch]$SkipFileInfo,

    [switch]$PassThru
)

# Script interpreters and LOLBins whose arguments are checked for the patterns below
$interpreterNames = @("powershell", "pwsh", "cmd", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil", "bitsadmin", "msiexec", "curl", "wmic", "forfiles", "conhost")
$suspiciousCommandPatterns = [ordered]@{
    "encoded command"   = '(^|\s)[-/\u2013\u2014\u2015]e(c|n[a-z]*)?\s+["'']?[a-z0-9+/=]{20,}'  # PowerShell also accepts dashes like an en dash
    "download cradle"   = 'downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\b(iwr|irm|wget)\b|net\.webclient|start-bitstransfer|/transfer\b|-urlcache'
    "Invoke-Expression" = '\b(iex|invoke-expression)\b'
    "base64 decoding"   = 'frombase64string|(^|\s)[-/]decode\b'
    "remote URL"        = '\b(https?|ftp)://'
    "script protocol"   = '\b(javascript|vbscript):'
}

# Functions
function Test-SuspiciousPath {
    param (
        [string]$Path
    )
    return [bool]($Path -and $suspiciousDirectoryRegex.IsMatch($Path))
}

function Test-TrustedLocation {
    # True for paths under the Windows or Program Files directories, unless they're in a suspicious
    # subdirectory such as C:\Windows\Temp
    param (
        [string]$Path
    )
    if (-not $Path -or (Test-SuspiciousPath -Path $Path)) {
        return $false
    }
    foreach ($root in $trustedRoots) {
        if ($Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Resolve-TaskFilePath {
    # Strips quotes, expands environment variables and resolves relative paths the way Windows would
    param (
        [string]$Path,
        [string]$WorkingDirectory,
        [switch]$IsExecutable
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    $resolved = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).Replace("/", "\")
    try {
        # CreateProcess adds .exe to an executable name that has no extension
        if ($IsExecutable -and -not [IO.Path]::HasExtension($resolved)) {
            $resolved += ".exe"
        }

        if (-not [IO.Path]::IsPathRooted($resolved)) {
            # Same search order Windows uses: working directory, system directories, then PATH
            $searchDirectories = @($WorkingDirectory, "$env:SystemRoot\System32", $env:SystemRoot) + ($env:Path -split ";")
            foreach ($directory in $searchDirectories) {
                if ([string]::IsNullOrWhiteSpace($directory)) {
                    continue
                }
                try {
                    $candidate = [IO.Path]::Combine([Environment]::ExpandEnvironmentVariables($directory.Trim().Trim('"')), $resolved)
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                        $resolved = $candidate
                        break
                    }
                } catch { }
            }
            # Not found (or not readable): assume the working directory, which Windows checks first
            if (-not [IO.Path]::IsPathRooted($resolved) -and $WorkingDirectory) {
                $resolved = [IO.Path]::Combine([Environment]::ExpandEnvironmentVariables($WorkingDirectory.Trim().Trim('"')), $resolved)
            }
        }

        # Collapse "..\" so a path like C:\Windows\..\Users\Public can't pass as a Windows path
        if ([IO.Path]::IsPathRooted($resolved)) {
            $resolved = [IO.Path]::GetFullPath($resolved)
        }
    } catch { }
    return $resolved
}

function Get-ArgumentFile {
    # Finds files with one of the watched extensions in a task's arguments: quoted paths (which may
    # contain spaces), unquoted paths starting with a drive, UNC share or %VARIABLE%, and bare file names
    param (
        [string]$Arguments,
        [string]$WorkingDirectory
    )
    if ([string]::IsNullOrWhiteSpace($Arguments)) {
        return @()
    }
    $files = foreach ($match in $argumentFileRegex.Matches($Arguments)) {
        foreach ($group in "quoted", "unquoted", "bare") {
            if ($match.Groups[$group].Success) {
                Resolve-TaskFilePath -Path $match.Groups[$group].Value -WorkingDirectory $WorkingDirectory
            }
        }
    }
    return @($files | Select-Object -Unique)
}

function Get-SuspiciousCommandLine {
    # Names the suspicious patterns in the arguments when a script interpreter or LOLBin is run
    param (
        [string]$Executable,
        [string]$Arguments
    )
    if (-not $Executable -or -not $Arguments) {
        return @()
    }
    if ($interpreterNames -notcontains [IO.Path]::GetFileNameWithoutExtension($Executable)) {
        return @()
    }
    $labels = foreach ($pattern in $suspiciousCommandPatterns.GetEnumerator()) {
        if ($Arguments -match $pattern.Value) {
            $pattern.Key
        }
    }
    return @($labels)
}

function Get-ComHandlerServer {
    # Finds the DLLs a COM handler's CLSID is registered to, machine-wide and in each loaded user hive
    param (
        [string]$ClassId
    )
    $locations = @([PSCustomObject]@{ Hive = "HKLM"; Key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$ClassId\InprocServer32" })
    foreach ($userHive in $userClassHives) {
        $locations += [PSCustomObject]@{ Hive = ($userHive.PSChildName -replace "_Classes$", ""); Key = "Registry::$($userHive.Name)\CLSID\$ClassId\InprocServer32" }
    }
    foreach ($location in $locations) {
        $server = (Get-ItemProperty -LiteralPath $location.Key -ErrorAction SilentlyContinue).'(default)'
        if ($server) {
            [PSCustomObject]@{ Hive = $location.Hive; Path = (Resolve-TaskFilePath -Path $server) }
        }
    }
}

function Get-ActionAnalysis {
    # Works out what a task action runs and why it might be suspicious. Strong reasons are reported in
    # modes 2 and 3, weak reasons only in mode 2.
    param (
        $Action
    )
    $strongReasons = New-Object Collections.Generic.List[string]
    $weakReasons = New-Object Collections.Generic.List[string]
    $argumentFiles = @()
    $comServer = $null

    if ($Action.ClassId) {
        $servers = @(Get-ComHandlerServer -ClassId $Action.ClassId)
        $machineServer = $servers | Where-Object { $_.Hive -eq "HKLM" } | Select-Object -First 1
        $userServer = $servers | Where-Object { $_.Hive -ne "HKLM" } | Select-Object -First 1
        if ($userServer -and $machineServer -and $userServer.Path -ne $machineServer.Path) {
            # A user-hive registration overrides HKLM for that user, which is how COM hijacking works
            $strongReasons.Add("COM handler overridden in user hive $($userServer.Hive)")
        } elseif ($userServer -and -not $machineServer) {
            $weakReasons.Add("COM handler registered only in user hive $($userServer.Hive)")
        }
        # No registration at all is normal: many Windows tasks use classes that services register at runtime
        $comServer = if ($userServer) { $userServer } else { $machineServer }
        $executable = $comServer.Path
    } else {
        $executable = Resolve-TaskFilePath -Path $Action.Execute -WorkingDirectory $Action.WorkingDirectory -IsExecutable
        $argumentFiles = @(Get-ArgumentFile -Arguments $Action.Arguments -WorkingDirectory $Action.WorkingDirectory)
        $commandLabels = @(Get-SuspiciousCommandLine -Executable $executable -Arguments $Action.Arguments)
        if ($commandLabels.Count -gt 0) {
            $strongReasons.Add("Suspicious command line: " + ($commandLabels -join ", "))
        }
    }

    if ($executable) {
        if (Test-SuspiciousPath -Path $executable) {
            $strongReasons.Add("Runs from suspicious directory")
        } elseif (-not (Test-TrustedLocation -Path $executable)) {
            $weakReasons.Add("Runs from outside Windows/Program Files")
        }
    }
    foreach ($file in $argumentFiles) {
        if (Test-SuspiciousPath -Path $file) {
            $strongReasons.Add("Argument file in suspicious directory")
        } elseif (-not (Test-TrustedLocation -Path $file)) {
            $weakReasons.Add("Argument file outside Windows/Program Files")
        }
    }

    # The file worth hashing is the most suspicious one: usually the script or DLL in the arguments
    # rather than the interpreter that runs it
    $candidates = @(@($argumentFiles) + @($executable) | Where-Object { $_ })
    $targetFile = $candidates | Where-Object { Test-SuspiciousPath -Path $_ } | Select-Object -First 1
    if (-not $targetFile) {
        $targetFile = $candidates | Where-Object { -not (Test-TrustedLocation -Path $_) } | Select-Object -First 1
    }
    if (-not $targetFile) {
        $targetFile = $candidates | Select-Object -First 1
    }

    return [PSCustomObject]@{
        Executable    = $executable
        ArgumentFiles = $argumentFiles
        TargetFile    = $targetFile
        StrongReasons = @($strongReasons | Select-Object -Unique)
        WeakReasons   = @($weakReasons | Select-Object -Unique)
    }
}

function Get-TargetFileInfo {
    param (
        [string]$Path
    )
    $info = [PSCustomObject]@{ Exists = $false; SHA256 = ""; Signer = ""; SignatureStatus = "" }
    if (-not $Path) {
        return $info
    }
    if ($fileInfoCache.ContainsKey($Path)) {
        return $fileInfoCache[$Path]
    }
    try {
        if ([IO.Path]::IsPathRooted($Path) -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $info.Exists = $true
            if (-not $SkipFileInfo) {
                $info.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
                if ($signature) {
                    $info.SignatureStatus = [string]$signature.Status
                    if ($signature.SignerCertificate) {
                        $info.Signer = $signature.SignerCertificate.GetNameInfo("SimpleName", $false)
                    }
                }
            }
        }
    } catch { }
    $fileInfoCache[$Path] = $info
    return $info
}

function Get-TriggerSummary {
    param (
        $Triggers
    )
    $summary = foreach ($trigger in $Triggers) {
        $type = $trigger.CimClass.CimClassName -replace "^MSFT_Task", "" -replace "Trigger$", ""
        if (-not $type) {
            $type = "Custom"
        }
        if ($trigger.Enabled -eq $false) {
            $type += " (disabled)"
        }
        $type
    }
    return ($summary -join ", ")
}

function Get-HiddenTask {
    # Finds tasks registered in the TaskCache that Get-ScheduledTask doesn't return, for example because
    # their SD (security descriptor) value was deleted to hide them. Needs Administrator rights.
    param (
        [string[]]$VisibleTaskPaths,
        [string]$TaskCacheRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        [string]$TasksFolder = "$env:SystemRoot\System32\Tasks"
    )
    $visible = New-Object "Collections.Generic.HashSet[string]" ([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $VisibleTaskPaths) {
        [void]$visible.Add($path)
    }

    try {
        $treeRoot = Get-Item -LiteralPath "$TaskCacheRoot\Tree" -ErrorAction Stop
        $treeKeys = @(Get-ChildItem -LiteralPath $treeRoot.PSPath -Recurse -ErrorAction SilentlyContinue)
    } catch {
        Write-Warning "Couldn't read the TaskCache registry key, so hidden tasks weren't checked: $($_.Exception.Message)"
        return
    }

    foreach ($key in $treeKeys) {
        $valueNames = $key.GetValueNames()
        if ($valueNames -notcontains "Id") {
            continue  # folders have no Id
        }
        $fullTaskPath = $key.Name.Substring($treeRoot.Name.Length)
        $missingSd = $valueNames -notcontains "SD"
        if (-not $missingSd -and $visible.Contains($fullTaskPath)) {
            continue
        }

        $hiddenTask = [PSCustomObject]@{
            FullTaskPath = $fullTaskPath
            Reason       = if ($missingSd) { "Hidden task: SD registry value deleted" } else { "Hidden task: in TaskCache but not returned by Get-ScheduledTask" }
            Author       = ""
            Created      = ""
            RunAs        = ""
            RunLevel     = ""
            Triggers     = ""
            Actions      = @()
        }

        # The task's XML definition, if it's still on disk
        $xmlPath = Join-Path $TasksFolder $fullTaskPath.TrimStart("\")
        if (Test-Path -LiteralPath $xmlPath -PathType Leaf) {
            try {
                [xml]$taskXml = Get-Content -LiteralPath $xmlPath -Raw -ErrorAction Stop
                $definition = $taskXml.Task
                $principal = @($definition.Principals.Principal)[0]
                $hiddenTask.Author = $definition.RegistrationInfo.Author
                $hiddenTask.Created = $definition.RegistrationInfo.Date
                $hiddenTask.RunAs = if ($principal.UserId) { $principal.UserId } else { $principal.GroupId }
                $hiddenTask.RunLevel = $principal.RunLevel
                $hiddenTask.Triggers = (@($definition.Triggers.ChildNodes) | Where-Object { $_.NodeType -eq "Element" } | ForEach-Object { $_.LocalName -replace "Trigger$", "" }) -join ", "
                $hiddenTask.Actions = @(
                    foreach ($exec in @($definition.Actions.Exec)) {
                        if ($exec) {
                            [PSCustomObject]@{ Execute = $exec.Command; Arguments = $exec.Arguments; WorkingDirectory = $exec.WorkingDirectory; ClassId = $null; Data = $null }
                        }
                    }
                    foreach ($comHandler in @($definition.Actions.ComHandler)) {
                        if ($comHandler) {
                            [PSCustomObject]@{ Execute = $null; Arguments = $null; WorkingDirectory = $null; ClassId = $comHandler.ClassId; Data = $comHandler.Data }
                        }
                    }
                )
            } catch { }
        }

        # Otherwise pull the readable strings out of the binary Actions value in the TaskCache
        if ($hiddenTask.Actions.Count -eq 0) {
            $taskId = $key.GetValue("Id")
            $blob = (Get-ItemProperty -LiteralPath "$TaskCacheRoot\Tasks\$taskId" -ErrorAction SilentlyContinue).Actions
            if ($blob) {
                $text = [Text.Encoding]::Unicode.GetString($blob) + "`n" + [Text.Encoding]::Unicode.GetString($blob, 1, $blob.Length - 1)
                $strings = @([regex]::Matches($text, "[\x20-\x7E]{3,}") | ForEach-Object { $_.Value } | Select-Object -Unique)
                $hiddenTask.Actions = @([PSCustomObject]@{
                    Execute          = $strings | Where-Object { $_ -match '\.exe"?$' -or $interpreterNames -contains $_ } | Select-Object -First 1
                    Arguments        = "(from TaskCache Actions value) " + ($strings -join " | ")
                    WorkingDirectory = $null
                    ClassId          = $null
                    Data             = $null
                })
            }
        }

        if ($hiddenTask.Actions.Count -eq 0) {
            $hiddenTask.Actions = @([PSCustomObject]@{ Execute = $null; Arguments = "(actions not found)"; WorkingDirectory = $null; ClassId = $null; Data = $null })
        }
        $hiddenTask
    }
}

function New-ResultRow {
    # Returns the result row for one task action, or nothing if it doesn't match the selected mode
    param (
        $TaskInfo,
        $Action,
        [string[]]$ExtraStrongReasons = @()
    )
    $analysis = Get-ActionAnalysis -Action $Action
    $strongReasons = @($ExtraStrongReasons) + @($analysis.StrongReasons)
    $weakReasons = @($analysis.WeakReasons)

    $isMatch = switch ($Mode) {
        "1" { $true }
        "2" { ($strongReasons.Count + $weakReasons.Count) -gt 0 }
        "3" { $strongReasons.Count -gt 0 }
    }
    if (-not $isMatch) {
        return
    }

    $lastRunTime = ""
    $lastResult = ""
    if ($TaskInfo.Task) {
        $runInfo = $TaskInfo.Task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($runInfo) {
            $lastRunTime = if ($runInfo.LastRunTime -and $runInfo.LastRunTime.Year -gt 2000) { $runInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            $lastResult = "0x{0:X}" -f $runInfo.LastTaskResult
        }
    }
    $targetInfo = Get-TargetFileInfo -Path $analysis.TargetFile

    return [PSCustomObject][ordered]@{
        ComputerName          = $env:COMPUTERNAME
        FullTaskPath          = $TaskInfo.FullTaskPath
        MatchReason           = (@($strongReasons) + @($weakReasons)) -join "; "
        State                 = $TaskInfo.State
        Author                = $TaskInfo.Author
        Created               = $TaskInfo.Created
        RunAs                 = $TaskInfo.RunAs
        RunLevel              = $TaskInfo.RunLevel
        Triggers              = $TaskInfo.Triggers
        LastRunTime           = $lastRunTime
        LastResult            = $lastResult
        HiddenSetting         = $TaskInfo.HiddenSetting
        ActionType            = if ($Action.ClassId) { "ComHandler" } else { "Exec" }
        Execute               = $Action.Execute
        Arguments             = $Action.Arguments
        WorkingDirectory      = $Action.WorkingDirectory
        ComClassId            = $Action.ClassId
        ComData               = $Action.Data
        ResolvedExecutable    = $analysis.Executable
        ArgumentFiles         = $analysis.ArgumentFiles -join "; "
        TargetFile            = $analysis.TargetFile
        TargetExists          = $targetInfo.Exists
        TargetSHA256          = $targetInfo.SHA256
        TargetSigner          = $targetInfo.Signer
        TargetSignatureStatus = $targetInfo.SignatureStatus
    }
}

function Test-Allowlisted {
    param (
        $Row
    )
    foreach ($entry in $allowlist) {
        $pathMatches = if ($entry.FullTaskPath -match "[*?]") { $Row.FullTaskPath -like $entry.FullTaskPath } else { $Row.FullTaskPath -eq $entry.FullTaskPath }
        $hashMatches = -not $entry.TargetSHA256 -or $entry.TargetSHA256 -eq $Row.TargetSHA256
        $signerMatches = -not $entry.TargetSigner -or ($entry.TargetSigner -eq $Row.TargetSigner -and $Row.TargetSignatureStatus -eq "Valid")
        if ($pathMatches -and $hashMatches -and $signerMatches) {
            return $true
        }
    }
    return $false
}

function ConvertTo-CsvSafeValue {
    # Excel runs cells starting with = + - @ (or a tab or carriage return) as formulas; a leading ' keeps them as text
    param (
        $Value
    )
    $text = [string]$Value
    if ($text -match "^[=+\-@`t`r]") {
        return "'" + $text
    }
    return $text
}

# User Prompt
if (-not $Mode) {
    Write-Host "`nSelect an option:`n"
    Write-Host "1. List all Scheduled Tasks (no filtering)."
    Write-Host "2. Only list Scheduled Tasks that run or reference files outside the Windows and Program Files directories."
    Write-Host "3. Only list Scheduled Tasks with high-fidelity indicators (suspicious directories or command lines, COM hijacks, hidden tasks).`n"
    do {
        $selection = ([string](Read-Host "Enter your preferred option")).Trim()
    } until ($selection -in "1", "2", "3")
    $Mode = $selection
}

# Setup
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator: some tasks, files and other users' registry hives can't be read, and hidden tasks aren't checked."
}

$extensionPattern = ($FileExtensions | ForEach-Object { [regex]::Escape($_.Trim().TrimStart(".")) }) -join "|"
$pathRoot = '(?:[a-z]:\\|\\\\|%[^%\s"]+%)'
$argumentFilePattern = '"(?<quoted>' + $pathRoot + '[^"]*?\.(?:' + $extensionPattern + '))(?=["\s,;]|$)' +
    '|(?<unquoted>' + $pathRoot + '[^\s"'',;<>|&]*?\.(?:' + $extensionPattern + '))(?=$|[\s"'',;<>|&])' +
    '|(?<=^|[\s=])(?<bare>[^\s"''\\/:%,;=<>|&]+\.(?:' + $extensionPattern + '))(?=$|[\s"'',;<>|&])'
$argumentFileRegex = New-Object regex -ArgumentList $argumentFilePattern, "IgnoreCase"

$directoryPattern = '(?:^|\\)(?:' + (($SuspiciousDirectories | ForEach-Object { [regex]::Escape($_.Trim().Trim("\")) }) -join "|") + ')(?:\\|$)'
$suspiciousDirectoryRegex = New-Object regex -ArgumentList $directoryPattern, "IgnoreCase"

$trustedRoots = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd("\") + "\" } | Select-Object -Unique

$userClassHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "*_Classes" })
$fileInfoCache = @{}

$allowlist = @()
if ($AllowlistPath) {
    $allowlist = @(Import-Csv -LiteralPath $AllowlistPath | ForEach-Object {
        [PSCustomObject]@{
            FullTaskPath = ([string]$_.FullTaskPath).Trim().TrimStart("'")
            TargetSHA256 = ([string]$_.TargetSHA256).Trim().TrimStart("'")
            TargetSigner = ([string]$_.TargetSigner).Trim().TrimStart("'")
        }
    } | Where-Object { $_.FullTaskPath })
    if ($allowlist.Count -eq 0) {
        Write-Warning "No entries with a FullTaskPath were found in $AllowlistPath."
    }
}

if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location -PSProvider FileSystem).Path "ScheduledTaskResults_$($env:COMPUTERNAME)_$timestamp.csv"
}

# Main Script
$tasks = @(Get-ScheduledTask)
$results = New-Object Collections.Generic.List[object]
$allowlistedCount = 0

foreach ($task in $tasks) {
    $taskInfo = [PSCustomObject]@{
        Task          = $task
        FullTaskPath  = $task.TaskPath + $task.TaskName
        State         = $task.State
        Author        = $task.Author
        Created       = $task.Date
        RunAs         = if ($task.Principal.UserId) { $task.Principal.UserId } else { $task.Principal.GroupId }
        RunLevel      = $task.Principal.RunLevel
        Triggers      = Get-TriggerSummary -Triggers $task.Triggers
        HiddenSetting = $task.Settings.Hidden
    }

    foreach ($action in $task.Actions) {
        $row = New-ResultRow -TaskInfo $taskInfo -Action $action
        if (-not $row) {
            continue
        }
        if ($allowlist.Count -gt 0 -and (Test-Allowlisted -Row $row)) {
            $allowlistedCount++
            continue
        }
        $results.Add($row)
    }
}

if ($isAdmin) {
    $visibleTaskPaths = @($tasks | ForEach-Object { $_.TaskPath + $_.TaskName })
    foreach ($hiddenTask in Get-HiddenTask -VisibleTaskPaths $visibleTaskPaths) {
        $taskInfo = [PSCustomObject]@{
            Task          = $null
            FullTaskPath  = $hiddenTask.FullTaskPath
            State         = "Hidden"
            Author        = $hiddenTask.Author
            Created       = $hiddenTask.Created
            RunAs         = $hiddenTask.RunAs
            RunLevel      = $hiddenTask.RunLevel
            Triggers      = $hiddenTask.Triggers
            HiddenSetting = ""
        }
        foreach ($action in $hiddenTask.Actions) {
            $results.Add((New-ResultRow -TaskInfo $taskInfo -Action $action -ExtraStrongReasons $hiddenTask.Reason))
        }
    }
}

# Show Results
if ($results.Count -gt 0) {
    Write-Host "`n Matching scheduled task actions found: $($results.Count)`n"
    $results | Format-Table -Property FullTaskPath, MatchReason, RunAs, TargetFile -AutoSize | Out-Host

    # Export to CSV
    $csvRows = foreach ($row in $results) {
        $safeRow = [ordered]@{}
        foreach ($property in $row.PSObject.Properties) {
            $safeRow[$property.Name] = ConvertTo-CsvSafeValue -Value $property.Value
        }
        [PSCustomObject]$safeRow
    }
    $csvRows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n Exported to: $OutputPath`n"
} else {
    Write-Host "`n No matching tasks found for the selected mode. No CSV was created.`n"
}
if ($allowlistedCount -gt 0) {
    Write-Host " $allowlistedCount task action(s) were left out because they're in the allowlist.`n"
}

if ($PassThru) {
    $results
}
