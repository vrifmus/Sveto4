using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Sveto4
{
    /// <summary>Persistent app data. Replaced by a fake in tests.</summary>
    internal interface IStateStore
    {
        /// <summary>System rules disabled by the app, to be re-enabled on Turn OFF.</summary>
        List<LeakInfo> LoadDisabledRules();
        void SaveDisabledRules(List<LeakInfo> rules);
        bool BlockSystemLeaks { get; set; }
        /// <summary>Null when never set (then it is inferred from existing rules).</summary>
        bool? GetClientEnabled(string clientId);
        void SetClientEnabled(string clientId, bool enabled);
        /// <summary>
        /// Adapters selected on behalf of a client. Needed to remove a vanished adapter when the profile
        /// recognizes adapters only by description (unknown once the adapter is gone).
        /// </summary>
        List<string> GetClientAdapters(string clientId);
        void SetClientAdapters(string clientId, IEnumerable<string> adapters);
    }

    /// <summary>Imported client profiles. Replaced by a fake in tests.</summary>
    internal interface IProfileStore
    {
        /// <summary>Valid imported profiles; invalid files are skipped and logged.</summary>
        List<ClientProfile> LoadImported();
        void Save(string id, string json);
        void Delete(string id);
    }

    /// <summary>%ProgramData%\Sveto4\profiles\&lt;id&gt;.json (administrators only, see <see cref="AppDataDir"/>).</summary>
    internal sealed class FileProfileStore : IProfileStore
    {
        private static string Dir => System.IO.Path.Combine(AppDataDir.Path, "profiles");

        public List<ClientProfile> LoadImported()
        {
            var result = new List<ClientProfile>();
            if (!Directory.Exists(Dir)) return result;
            AppDataDir.Ensure(); // re-apply permissions before trusting the files

            foreach (var file in Directory.GetFiles(Dir, "*.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var ids = ClientProfiles.BuiltIn.Select(p => p.Id).Concat(result.Select(p => p.Id));
                    result.Add(ProfileFile.Parse(File.ReadAllText(file), ids));
                }
                catch (Exception ex)
                {
                    Log.Info($"Profile skipped: {file}: {ex.Message}");
                }
            }
            return result;
        }

        public void Save(string id, string json)
        {
            AppDataDir.Ensure();
            Directory.CreateDirectory(Dir);
            File.WriteAllText(System.IO.Path.Combine(Dir, id + ".json"), json);
        }

        public void Delete(string id)
        {
            var file = System.IO.Path.Combine(Dir, id + ".json");
            if (File.Exists(file)) File.Delete(file);
        }
    }

    /// <summary>
    /// %ProgramData%\Sveto4. Writable by administrators only: settings and imported profiles decide
    /// which programs get network access past the kill switch, so a non-elevated program must not change them.
    /// (By default ProgramData subfolders let any user create files.)
    /// </summary>
    internal static class AppDataDir
    {
        public static readonly string Path = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sveto4");

        private static bool secured;

        public static string Ensure()
        {
            Directory.CreateDirectory(Path);
            if (secured) return Path;
            try
            {
                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(true, false); // no inherited (user-writable) entries
                const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(Path, security);
                secured = true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "secure " + Path);
            }
            return Path;
        }
    }

    /// <summary>Files in %ProgramData%\Sveto4 (machine-wide, the app always runs elevated).</summary>
    internal sealed class FileStateStore : IStateStore
    {
        private static readonly string Dir = AppDataDir.Path;
        private static readonly string DisabledFile = Path.Combine(Dir, "disabled-rules.txt");
        private static readonly string SettingsFile = Path.Combine(Dir, "settings.txt");
        private const string BlockLeaksKey = "BlockSystemLeaks";

        public List<LeakInfo> LoadDisabledRules()
        {
            if (!File.Exists(DisabledFile)) return new List<LeakInfo>();
            return File.ReadAllLines(DisabledFile)
                .Select(line => line.Split(new[] { '\t' }, 2))
                .Where(parts => parts.Length == 2)
                .Select(parts => new LeakInfo(parts[0], parts[1]))
                .ToList();
        }

        public void SaveDisabledRules(List<LeakInfo> rules)
        {
            if (rules.Count == 0)
            {
                if (File.Exists(DisabledFile)) File.Delete(DisabledFile);
                return;
            }
            AppDataDir.Ensure();
            File.WriteAllLines(DisabledFile, rules.Select(r => r.Kind + "\t" + r.RuleName));
        }

        public bool BlockSystemLeaks
        {
            get => ReadSetting(BlockLeaksKey) != "0"; // on by default
            set => WriteSetting(BlockLeaksKey, value ? "1" : "0");
        }

        public bool? GetClientEnabled(string clientId)
        {
            var value = ReadSetting("Client." + clientId);
            return value == null ? (bool?)null : value == "1";
        }

        public void SetClientEnabled(string clientId, bool enabled) =>
            WriteSetting("Client." + clientId, enabled ? "1" : "0");

        public List<string> GetClientAdapters(string clientId) =>
            (ReadSetting("ClientAdapters." + clientId) ?? "")
                .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).ToList();

        public void SetClientAdapters(string clientId, IEnumerable<string> adapters) =>
            WriteSetting("ClientAdapters." + clientId, string.Join("|", adapters));

        private static string ReadSetting(string key)
        {
            if (!File.Exists(SettingsFile)) return null;
            return File.ReadAllLines(SettingsFile)
                .Select(line => line.Split(new[] { '=' }, 2))
                .Where(parts => parts.Length == 2 && parts[0].Trim() == key)
                .Select(parts => parts[1].Trim())
                .LastOrDefault();
        }

        private static void WriteSetting(string key, string value)
        {
            AppDataDir.Ensure();
            var lines = File.Exists(SettingsFile)
                ? File.ReadAllLines(SettingsFile).Where(l => !l.StartsWith(key + "=")).ToList()
                : new List<string>();
            lines.Add(key + "=" + value);
            File.WriteAllLines(SettingsFile, lines);
        }
    }
}
