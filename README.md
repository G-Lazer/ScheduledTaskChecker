# ScheduledTaskChecker

The default list of file extensions and directories included in this script are ones I've seen commonly abused during my time threat hunting. Use the default checks, or customize them for your own IoC search on the host.

**Script Options**

Option 1 - List all Scheduled Tasks (no filtering).
- Allows for a full review.

Option 2 - Only list Scheduled Tasks that run, or reference in their arguments, a file outside the Windows and Program Files directories, plus everything option 3 finds.
- Allows for a more refined review. Tasks that only run built-in Windows or installed-program binaries are left out.

Option 3 - Only list Scheduled Tasks with high-fidelity indicators:
- Runs or references a file (with one of the predefined extensions) in one of the predefined suspicious directories.
- Runs a script interpreter or LOLBin (PowerShell, cmd, mshta, rundll32, regsvr32, certutil, etc.) with a suspicious command line: encoded commands, download cradles, `IEX`, base64 decoding, remote URLs, or `javascript:`/`vbscript:`.
- Uses a COM handler whose CLSID is overridden in a user's registry hive (COM hijacking).
- Is hidden from Task Scheduler, e.g. by deleting its `SD` registry value as the Tarrask malware does (Administrator only).

False positives are possible depending on installed software (OneDrive and Defender both run tasks from directories on the suspicious list), but generally, any findings when using this option should be highly scrutinized. The `MatchReason` column says why each task was listed.

# Usage

Run from an elevated PowerShell prompt for complete results. Without Administrator rights some tasks, files and other users' registry hives can't be read, and hidden tasks aren't checked.

```powershell
# Prompts for an option
.\ScheduledTaskChecker.ps1

# Non-interactive, e.g. through an EDR remote shell
powershell.exe -ExecutionPolicy Bypass -File .\ScheduledTaskChecker.ps1 -Mode 3 -OutputPath C:\IR\tasks.csv

# Leave out expected tasks
.\ScheduledTaskChecker.ps1 -Mode 2 -AllowlistPath .\GoldImageTasks.csv

# Collect results from several hosts (each host also writes its own CSV)
$results = Invoke-Command -ComputerName HOST1, HOST2 -ArgumentList (Get-Content .\ScheduledTaskChecker.ps1 -Raw) -ScriptBlock {
    param ($code)
    & ([scriptblock]::Create($code)) -Mode 3 -PassThru
}
```

| Parameter | Description |
|---|---|
| `-Mode` | `1`, `2` or `3`. You're prompted if it's left out, so always pass it when running remotely. |
| `-OutputPath` | Where to write the CSV. Defaults to `ScheduledTaskResults_<host>_<timestamp>.csv` in the current directory. |
| `-AllowlistPath` | CSV of expected tasks to leave out (see below). |
| `-FileExtensions` | Extensions to look for in task arguments. |
| `-SuspiciousDirectories` | Directory names, or partial paths like `Users\Public`, matched against whole path segments. |
| `-SkipFileInfo` | Skip hashing and signature checks. |
| `-PassThru` | Also return the results as objects. |

Run `Get-Help .\ScheduledTaskChecker.ps1 -Full` for the details.

# Output

Results are printed to the console and exported to CSV, one row per task action. Alongside the task's name, path, action and arguments, each row includes the host name, match reason, author, creation date, run-as account and run level, triggers, last run time and result, and the path, SHA256 and Authenticode signer of the task's target file. The target file is the most relevant file the task runs: for `powershell.exe -File C:\Users\Public\x.ps1` that's the script, not PowerShell.

Cells that Excel would treat as a formula (starting with `=`, `+`, `-` or `@`) are prefixed with `'` so they open as text.

# Allowlist

The allowlist is a CSV with a `FullTaskPath` column (`*` and `?` wildcards allowed) and optional `TargetSHA256` and `TargetSigner` columns:

- An entry with a hash only applies while the task's target file still has that hash.
- An entry with a signer only applies while the target file has a valid signature from that signer, which keeps working across updates.

```csv
FullTaskPath,TargetSHA256,TargetSigner
\Microsoft\Windows\Windows Defender\*,,Microsoft Windows Publisher
\Vendor\Updater,3F2A...,
```

A results CSV from a known-good host, trimmed to the rows you trust, works as an allowlist as-is. Hidden tasks are always reported.

# Planned Updates

- Optional hash lookup of each identified file through VirusTotal's API.
