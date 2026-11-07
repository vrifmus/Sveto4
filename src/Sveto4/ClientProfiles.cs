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

        public bool MatchesAdapter(string name, string description) =>
            AdapterDescriptions.Any(d => string.Equals(d, description, StringComparison.OrdinalIgnoreCase))
            || AdapterNamePrefixes.Any(p => name != null && name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        public bool IsExcluded(string exePath)
        {
            var file = Path.GetFileName(exePath);
            return ExcludeExe.Any(pattern => Regex.IsMatch(file,
                "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase));
        }
    }

    /// <summary>Client state shown in the menu.</summary>
    internal sealed class ClientStatus
    {
        public ClientStatus(ClientProfile profile, bool enabled, string installDir)
        {
            Profile = profile;
            Enabled = enabled;
            InstallDir = installDir;
        }

        public ClientProfile Profile { get; }
        public bool Enabled { get; }
        /// <summary>Null when the client is not found on this machine.</summary>
        public string InstallDir { get; }
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
        };

        public static readonly IReadOnlyList<ClientProfile> All = new[] { Happ };

        /// <summary>Folder of a running main process, otherwise the first existing default folder, otherwise null.</summary>
        public static string ResolveInstallDir(ClientProfile profile, ClientEnvironment env)
        {
            var running = env.Processes()
                .Where(p => !string.IsNullOrEmpty(p.ExePath)
                            && profile.MainProcesses.Any(m => string.Equals(m, p.Name, StringComparison.OrdinalIgnoreCase)))
                .Select(p => Path.GetDirectoryName(p.ExePath))
                .FirstOrDefault();
            if (running != null) return running;

            return profile.DefaultInstallDirs
                .Select(Environment.ExpandEnvironmentVariables)
                .FirstOrDefault(env.DirectoryExists);
        }

        /// <summary>Executables to allow: everything in the install folder except excluded ones.</summary>
        public static List<string> ExecutablesToAllow(ClientProfile profile, string installDir, ClientEnvironment env) =>
            installDir == null
                ? new List<string>()
                : env.ListExe(installDir).Where(p => !profile.IsExcluded(p))
                     .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

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

        /// <summary>A selected interface belongs to the client if it matches by name, or by description when present.</summary>
        public static bool IsClientAdapterName(ClientProfile profile, string iface, KsState s)
        {
            var adapter = s.Adapters.FirstOrDefault(a => string.Equals(a.Name, iface, StringComparison.OrdinalIgnoreCase));
            return profile.MatchesAdapter(iface, adapter?.Description);
        }

        public static ClientEnvironment CreateDefaultEnvironment(Func<IEnumerable<ProcessEntry>> processes) => new ClientEnvironment
        {
            Processes = processes,
            DirectoryExists = Directory.Exists,
            ListExe = dir => Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories),
            Adapters = SystemAdapters,
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
