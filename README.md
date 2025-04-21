# ScheduledTaskChecker

The default list of file extensions and directories included in this script are ones I've seen commonly abused during my time threat hunting. Use the default file extension and directory checks, or customize for your own IoC search on the host.

**Script Options**

Option 1 - List all Scheduled Tasks (no filtering).
- Allows for a full review.

Option 2 - Only list Scheduled Tasks with the predefined file extensions.
- Allows for a more refined review.

Option 3 - Only list Scheduled Tasks with the predefined file extensions that are also in the predefined suspicious directory list.
- The highest fidelity option. False positives are possible depending on installed software, but generally, any findings when using this option (when using the default extensions/directories) should be highly scrutinized.

# Planned Updates

- Adding the hash of each file identified to a column in the .csv output file.
- Optional hash lookup of each identified file through VirusTotal's API.
- Reading a secondary text file that acts as an "allowlist" of expected Scheduled Tasks that won't be added to the resulting .csv file.
