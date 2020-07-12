# ELK cheatsheet

## Misc notes

1. Unlike Splunk, ELK default operator is **OR** not **AND**.
2. To see nearby events, expand one and look for surrounding documents on right
<img src="Pics\ELK_see_nearby_events.png" width=400>
3. Similar to Splunk try to set columns *ProcessId*, *ParentProcessId*, *CommandLine*, *ParentCommandLine*
4. Ref for search syntax: [Lucene query syntax](https://lucene.apache.org/core/2_9_4/queryparsersyntax.html)
5. Filter out CommandLine which starts with **C:\Windows\System32**: 
```NOT event_data.CommandLine:"C:\\Windows\\system32\*"```
6. Like Splunk, note ELK fields are case sensitive while field contents are case-insensitive.
7. `event_id:("4697" "7045")` - Search for ID 4697 or 7045

## Map out the available sources

1. `log_name:*` or `source_name:*`

### Search for UAC bypasses

1. `event_data.ParentIntegrityLevel:Medium AND event_data.IntegrityLevel:High`

### Guide for post-exploitation

1. Try to filter by user, and (ParentCommandLine:* OR CommandLine:*)
2. Sort by time (highest is earliest)

### To check account logons

These fields help us to threat-hunt if a login was interactive, went through 4648, 4624, 4672 on source, 4768,4769 and 4776 on DC. Typically 4768, 4769 missing on DC.

Search query
```
(event_id:4648 OR event_id:4672 OR event_id:4624 OR event_id:4768 OR event_id:4769 OR event_id:4776 OR event_id:4770)
```

1. Time
2. computer_name
3. event_id
4. event_data.SubjectUserName
5. event_data.TargetUserName	
6. event_data.LogonType
7. event_data.SubjectLogonId
8. event_data.TargetLogonId

### To trace command execution

1. Time
2. computer_name
3. event_data.ParentProcessId
4. event_data.ProcessId
5. event_data.ParentCommandLine
6. event_data.CommandLine
7. event_data.User

Search for 

1. `cmd`
2. `powershell`

### misc

1. `event_id:7045 AND (event_data.CommandLine:"%systemroot%*" OR event_data.CommandLine:"C:\\Windows*")` - Checks for new service installed where .exe is in C:\Windows.

2. `event_id:8` - Look for winlogon.exe and lsass.exe in TargetImage and wce, mimikatz in SourceImage.

3. `"sc start"` and `"sc sdshow"` - Latter displays security descriptor or permissions of service to be modified by current user.

4. `tscon` - Search for RDP session hijacking by SYSTEM user.

5. `event_id:7 AND event_data.Image:"*\\lsass.exe" AND -event_data.Signature:*Microsoft*` - Check for image loading DLLs not signed by Microsoft.

6. From lab 9, detecting Windows binaries that look out of place
```
( event_data.Image:("*\\rundll32.exe" "*\\svchost.exe" "*\\wmiprvse.exe" "*\\wmiadap.exe" "*\\smss.exe" "*\\wininit.exe" "*\\taskhost.exe" "*\\lsass.exe" "*\\winlogon.exe" "*\\csrss.exe" "*\\services.exe" "*\\svchost.exe" "*\\lsm.exe" "*\\conhost.exe" "*\\dllhost.exe" "*\\dwm.exe" "*\\spoolsv.exe" "*\\wuauclt.exe" "*\\taskhost.exe" "*\\taskhostw.exe" "*\\fontdrvhost.exe" "*\\searchindexer.exe" "*\\searchprotocolhost.exe" "*\\searchfilterhost.exe" "*\\sihost.exe") AND -event_data.Image:("*\\system32\\*" "*\\syswow64\\*" "*\\winsxs\\*") ) OR ( event_data.TargetFilename:("*\\rundll32.exe" "*\\svchost.exe" "*\\wmiprvse.exe" "*\\wmiadap.exe" "*\\smss.exe" "*\\wininit.exe" "*\\taskhost.exe" "*\\lsass.exe" "*\\winlogon.exe" "*\\csrss.exe" "*\\services.exe" "*\\svchost.exe" "*\\lsm.exe" "*\\conhost.exe" "*\\dllhost.exe" "*\\dwm.exe" "*\\spoolsv.exe" "*\\wuauclt.exe" "*\\taskhost.exe" "*\\taskhostw.exe" "*\\fontdrvhost.exe" "*\\searchindexer.exe" "*\\searchprotocolhost.exe" "*\\searchfilterhost.exe" "*\\sihost.exe") AND -event_data.TargetFilename:("*\\system32\\*" "*\\syswow64\\*" "*\\winsxs\\*") )
```

7. `AND -event_data.CommandLine:(*paexe*  *psexesvc* *winexesvc* *remcomsvc*)` - Excludes these services found in CommandLine