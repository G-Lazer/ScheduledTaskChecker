# Editable Filters
$fileExtensionsToSearch = @(".exe", ".ps1", ".bat", ".vbs", ".js", ".py", ".pyw", ".jse", ".dll")  # Customize your extensions
$suspiciousDirectoryKeywords = @("ProgramData", "Temp", "Tmp", "Users\Public", "AppData")  # Customize your suspicious directories

# User Prompt
Write-Host "`nSelect an option:`n"
Write-Host "1. List all Scheduled Tasks (no filtering)"
Write-Host "2. Only list Scheduled Tasks with the predefined file extensions."
Write-Host "3. Only list Scheduled Tasks with the predefined file extensions that are also in the predefined suspicious directory list.`n"

$mode = Read-Host "Enter your preferred option"

# Result Array
$results = @()

# Functions
function Is-AllowedExtension {
    param (
        [string]$filePath
    )
    foreach ($ext in $fileExtensionsToSearch) {
        if ($filePath.ToLower().EndsWith($ext)) {
            return $true
        }
    }
    return $false
}

function Is-SuspiciousPath {
    param (
        [string]$filePath
    )
    foreach ($keyword in $suspiciousDirectoryKeywords) {
        if ($filePath.ToLower() -like "*$($keyword.ToLower())*") {
            return $true
        }
    }
    return $false
}

function Get-MatchingFilesFromArguments {
    param (
        [string]$arguments
    )
    $matches = @()

    # Build regex from allowed extensions
    $extPattern = ($fileExtensionsToSearch -replace '^\.', '') -join '|'
    $regex = [regex]::Escape("C:\") + '[^\s\"'']+\.(' + $extPattern + ')'

    $allMatches = [regex]::Matches($arguments, $regex)

    foreach ($match in $allMatches) {
        $filePath = $match.Value
        if (Is-AllowedExtension -filePath $filePath) {
            $matches += $filePath
        }
    }
    return $matches
}

# Main Script
$tasks = Get-ScheduledTask

foreach ($task in $tasks) {
    $taskName = $task.TaskName
    $taskPath = $task.TaskPath
    $actions = (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath).Actions

    foreach ($action in $actions) {
        $exePath = $action.Execute
        $arguments = $action.Arguments
        $workingDir = $action.WorkingDirectory
        $hasMatch = $false
        $argMatches = @()

        switch ($mode) {
            "1" {
                $hasMatch = $true
            }

            "2" {
                if (Is-AllowedExtension -filePath $exePath) {
                    $hasMatch = $true
                }

                $argMatches = Get-MatchingFilesFromArguments -arguments $arguments
                if ($argMatches.Count -gt 0) {
                    $hasMatch = $true
                }
            }

            "3" {
                if ((Is-AllowedExtension -filePath $exePath) -and (Is-SuspiciousPath -filePath $exePath)) {
                    $hasMatch = $true
                }

                $argMatches = Get-MatchingFilesFromArguments -arguments $arguments
                foreach ($match in $argMatches) {
                    if (Is-SuspiciousPath -filePath $match) {
                        $hasMatch = $true
                        break
                    }
                }
            }

            default {
                Write-Host "Invalid option selected. Exiting script."
                exit
            }
        }

        if ($hasMatch) {
            $results += [PSCustomObject]@{
                TaskName         = $taskName
                TaskPath         = $taskPath
                Execute          = $exePath
                Arguments        = $arguments
                WorkingDirectory = $workingDir
            }
        }
    }
}

# Show Results
if ($results.Count -gt 0) {
    Write-Host "`n Matching scheduled tasks found: $($results.Count)`n"
    $results | Format-Table -AutoSize

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = "ScheduledTaskResults_$timestamp.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation
    Write-Host "`n Exported to: $outputPath`n"
} else {
    Write-Host "`n No matching tasks found for the selected mode. No CSV was created.`n"
}