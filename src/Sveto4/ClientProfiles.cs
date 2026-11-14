using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Sveto4
{
    /// <summary>
    /// Describes a VPN client: how to recognize its tunnel adapters and where its executables live.
    /// Plain data, so profiles can later be imported from files.
    /// </summary>
    internal sealed class ClientProfile
    {
        /// <summary>Short id used in rule names: KS-App-{Id}-{exe}.</summary>
        public string Id;
        public string Name;
        /// <summary>Adapter description equals one of these (case-insensitive).</summary>
        public string[] AdapterDescriptions = new string[0];
        /// <summary>Adapter name starts with one of these (case-insensitive).</summary>
        public string[] AdapterNamePrefixes = new string[0];
        /// <summary>Running processes used to locate the install folder (file names).</summary>
        public string[] MainProcesses = new string[0];
        /// <summary>Install folders to try when the client is not running; environment variables allowed.</summary>
        public string[] DefaultInstallDirs = new string[0];
        /// <summary>Executables never allowed (installers etc.), wildcard patterns.</summary>
        public string[] ExcludeExe = new string[0];
        /// <summary>
        /// If not empty, only these executables are allowed (wildcard patterns on the file name).
        /// Needed for clients in user-writable folders (e.g. %APPDATA%), where any program could drop an exe.
        /// </summary>
        public string[] AllowExe = new string[0];
        /// <summary>Built into the app; cannot be removed.</summary>
        public bool BuiltIn;

        public bool MatchesAdapter(string name, string description) =>
            AdapterDescriptions.Any(d => string.Equals(BaseDescription(d), BaseDescription(description), StringComparison.OrdinalIgnoreCase))
            || AdapterNamePrefixes.Any(p => name != null && name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        private static readonly Regex InstanceSuffix = new Regex(@"\s+#\d+$");

        /// <summary>
        /// Windows appends " #N" to the description of the second and later adapters with the same
        /// driver description (e.g. "WireGuard Tunnel #57"); profiles match the description without it.
        /// </summary>
        public static string BaseDescription(string description) =>
            description == null ? null : InstanceSuffix.Replace(description.Trim(), "");

        public bool IsExcluded(string exePath)
        {
            var file = Path.GetFileName(exePath);
            return ExcludeExe.Any(pattern => Wildcard(file, pattern))
                   || (AllowExe.Length > 0 && !AllowExe.Any(pattern => Wildcard(file, pattern)));
        }

        private static bool Wildcard(string file, string pattern) =>
            Regex.IsMatch(file, "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase);
    }

    /// <summary>Client state shown in the menu.</summary>
    internal sealed class ClientStatus
    {
        public ClientStatus(ClientProfile profile, bool enabled, string installDir, IEnumerable<string> knownAdapters = null)
        {
            Profile = profile;
            Enabled = enabled;
            InstallDir = installDir;
            KnownAdapters = new HashSet<string>(knownAdapters ?? new string[0], StringComparer.OrdinalIgnoreCase);
        }

        public ClientProfile Profile { get; }
        public bool Enabled { get; }
        /// <summary>Null when the client is not found on this machine.</summary>
        public string InstallDir { get; }
        /// <summary>Adapters selected on behalf of this client (recognized even after they vanish).</summary>
        public HashSet<string> KnownAdapters { get; }
    }

    /// <summary>Access to processes and files, replaced in tests.</summary>
    internal sealed class ClientEnvironment
    {
        public Func<IEnumerable<ProcessEntry>> Processes;
        public Func<string, bool> DirectoryExists;
        /// <summary>All *.exe files in the folder and its subfolders.</summary>
        public Func<string, IEnumerable<string>> ListExe;
        /// <summary>Network adapters (excluding loopback).</summary>
        public Func<List<AdapterInfo>> Adapters;
        /// <summary>The folder and the folders above it can be changed by administrators only.</summary>
        public Func<string, bool> IsAdminOnlyFolder;
        /// <summary>The file or folder itself can be changed by administrators only; false if unreadable.</summary>
        public Func<string, bool> IsAdminOnlyItem;
    }

    /// <summary>Adapter changes needed to keep a client's tunnel adapters allowed.</summary>
    internal sealed class ClientAdapterPlan
    {
        public List<string> ToSelect = new List<string>();
        public List<string> ToDeselect = new List<string>();
        public bool IsEmpty => ToSelect.Count == 0 && ToDeselect.Count == 0;
    }

    internal static class ClientProfiles
    {
        public static readonly ClientProfile Happ = new ClientProfile
        {
            Id = "happ",
            Name = "Happ",
            AdapterDescriptions = new[] { "Happ Tunnel" },
            AdapterNamePrefixes = new[] { "happ-" },
            MainProcesses = new[] { "Happ.exe", "happd.exe" },
            DefaultInstallDirs = new[] { @"%ProgramFiles%\FlyFrogLLC\Happ" },
            ExcludeExe = new[] { "unins*.exe", "vc_redist*.exe" },
            BuiltIn = true,
        };

        public static readonly IReadOnlyList<ClientProfile> BuiltIn = new[] { Happ };

        /// <summary>
        /// First acceptable folder among the profile's default folders, then folders of running main processes;
        /// null if none. Shared system folders are never accepted (see <see cref="IsUnsafeInstallDir"/>).
        /// A folder that non-administrators can change is accepted only from the profile's own list and only
        /// with "allowExe": otherwise any program named like the client could get network access.
        /// </summary>
        public static string ResolveInstallDir(ClientProfile profile, ClientEnvironment env)
        {
            var defaults = profile.DefaultInstallDirs.Select(Environment.ExpandEnvironmentVariables)
                .Where(env.DirectoryExists)
                .Select(dir => (Dir: dir, FromProcess: false));
            var running = env.Processes()
                .Where(p => !string.IsNullOrEmpty(p.ExePath)
                            && profile.MainProcesses.Any(m => string.Equals(m, p.Name, StringComparison.OrdinalIgnoreCase)))
                .Select(p => (Dir: Path.GetDirectoryName(p.ExePath), FromProcess: true));

            foreach (var c in defaults.Concat(running))
            {
                var reason = RejectInstallDir(profile, c.Dir, c.FromProcess, env.IsAdminOnlyFolder);
                if (reason == null) return c.Dir;
                LogOnce($"{profile.Name}: install folder rejected ({reason}): {c.Dir}");
            }
            return null;
        }

        private static readonly HashSet<string> Logged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The folder is resolved on every full read (~30 s): log each rejection once.</summary>
        private static void LogOnce(string message)
        {
            lock (Logged)
                if (!Logged.Add(message)) return;
            Log.Info(message);
        }

        /// <summary>Why the folder cannot be the client's install folder, or null if it can.</summary>
        public static string RejectInstallDir(ClientProfile profile, string dir, bool fromProcess, Func<string, bool> isAdminOnly)
        {
            if (IsUnsafeInstallDir(dir)) return "shared system folder";
            if (isAdminOnly(dir)) return null;
            if (fromProcess) return "found by a running process, but writable without administrator rights";
            if (profile.AllowExe.Length == 0) return "writable without administrator rights; the profile needs \"allowExe\"";
            return null;
        }

        /// <summary>
        /// Folders whose executables must not be allowed as a whole: drive roots, Windows,
        /// Program Files, ProgramData and user profile roots. A client must live in its own subfolder.
        /// </summary>
        public static bool IsUnsafeInstallDir(string dir)
        {
            string full;
            try
            {
                full = Path.GetFullPath(dir).TrimEnd('\\');
            }
            catch (Exception)
            {
                return true;
            }
            if (full.Length <= 2 || string.Equals(full + "\\", Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase))
                return true; // drive root

            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            if (Under(full, windows)) return true;

            var roots = new[]
            {
                Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86,
                Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolder.UserProfile,
                Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolder.Desktop, Environment.SpecialFolder.MyDocuments,
            }.Select(Environment.GetFolderPath)
             .Concat(new[] { Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) }) // C:\Users
             .Where(r => !string.IsNullOrEmpty(r))
             .Select(r => r.TrimEnd('\\'));
            return roots.Any(r => string.Equals(full, r, StringComparison.OrdinalIgnoreCase))
                   || string.Equals(full, Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\Downloads").TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        private static bool Under(string path, string root) =>
            !string.IsNullOrEmpty(root) &&
            (string.Equals(path, root, StringComparison.OrdinalIgnoreCase)
             || path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Executables to allow: everything in the install folder except excluded ones. In an administrators-only
        /// folder, an exe that itself, or a subfolder on the way to it, can be changed without administrator rights
        /// is skipped: otherwise any program could replace it and get network access.
        /// </summary>
        public static List<string> ExecutablesToAllow(ClientProfile profile, string installDir, ClientEnvironment env)
        {
            if (installDir == null) return new List<string>();
            var candidates = env.ListExe(installDir).Where(p => !profile.IsExcluded(p))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
            // A user-writable folder is accepted only with "allowExe"; its files are writable anyway.
            if (!env.IsAdminOnlyFolder(installDir)) return candidates;

            var checkedItems = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            Func<string, bool> isAdminOnly = path =>
                checkedItems.TryGetValue(path, out var ok) ? ok : checkedItems[path] = env.IsAdminOnlyItem(path);

            var result = new List<string>();
            foreach (var exe in candidates)
            {
                var writable = WritableOnTheWay(installDir, exe, isAdminOnly);
                if (writable == null) result.Add(exe);
                else LogOnce($"{profile.Name}: not allowed, {writable} can be changed without administrator rights: {exe}");
            }
            return result;
        }

        /// <summary>
        /// "the file" or "folder X" when the exe or a folder between it and <paramref name="installDir"/>
        /// (the install folder itself is checked separately) is not administrators-only; null otherwise.
        /// </summary>
        public static string WritableOnTheWay(string installDir, string exe, Func<string, bool> isAdminOnlyItem)
        {
            if (!isAdminOnlyItem(exe)) return "the file";
            for (var dir = Path.GetDirectoryName(exe);
                 dir != null && dir.Length > installDir.Length && Under(dir, installDir);
                 dir = Path.GetDirectoryName(dir))
                if (!isAdminOnlyItem(dir)) return "folder " + dir;
            return null;
        }

        /// <summary>
        /// Every present adapter of the client must be selected; selected client adapters that
        /// disappeared are removed (removing an allow rule only narrows access).
        /// </summary>
        public static ClientAdapterPlan PlanAdapters(ClientProfile profile, KsState s)
        {
            var plan = new ClientAdapterPlan();
            var present = s.Adapters.Where(a => profile.MatchesAdapter(a.Name, a.Description)).ToList();
            plan.ToSelect.AddRange(present.Select(a => a.Name).Where(n => !s.Interfaces.Contains(n)));

            var presentNames = new HashSet<string>(present.Select(a => a.Name), StringComparer.OrdinalIgnoreCase);
            plan.ToDeselect.AddRange(s.Interfaces.Where(i => !presentNames.Contains(i) && IsClientAdapterName(profile, i, s)));
            return plan;
        }

        /// <summary>
        /// A selected interface belongs to the client if it matches by name, by description when present,
        /// or was selected on behalf of the client earlier (a vanished adapter has no description).
        /// </summary>
        public static bool IsClientAdapterName(ClientProfile profile, string iface, KsState s)
        {
            var adapter = s.Adapters.FirstOrDefault(a => string.Equals(a.Name, iface, StringComparison.OrdinalIgnoreCase));
            return profile.MatchesAdapter(iface, adapter?.Description)
                   || s.Clients.Any(c => c.Profile.Id == profile.Id && c.KnownAdapters.Contains(iface));
        }

        public static ClientEnvironment CreateDefaultEnvironment(Func<IEnumerable<ProcessEntry>> processes) => new ClientEnvironment
        {
            Processes = processes,
            DirectoryExists = Directory.Exists,
            ListExe = dir => Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories),
            Adapters = SystemAdapters,
            IsAdminOnlyFolder = FolderSecurity.IsAdminOnlyFolder,
            IsAdminOnlyItem = path =>
            {
                try
                {
                    return FolderSecurity.IsAdminOnlyItem(path);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "read permissions of " + path);
                    return false;
                }
            },
        };

        private static List<AdapterInfo> SystemAdapters() =>
            System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                .Select(n => new AdapterInfo(n.Name, n.Description ?? "",
                    n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up,
                    KillSwitch.IsSystemAdapter(n.Name, n.Description)))
                .ToList();
    }
}
