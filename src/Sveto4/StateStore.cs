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
            AppDataDir.Trust(Dir);

            foreach (var file in Directory.GetFiles(Dir, "*.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var ids = ClientProfiles.BuiltIn.Select(p => p.Id).Concat(result.Select(p => p.Id));
                    AppDataDir.Trust(file);
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
            AppDataDir.Trust(Dir);
            var file = System.IO.Path.Combine(Dir, id + ".json");
            AppDataDir.Trust(file); // an existing file keeps its permissions when overwritten
            AtomicFile.WriteAllText(file, json);
        }

        public void Delete(string id)
        {
            var file = System.IO.Path.Combine(Dir, id + ".json");
            if (File.Exists(file)) File.Delete(file);
        }
    }

    /// <summary>
    /// %ProgramData%\Sveto4. Writable by administrators only: settings and imported profiles decide
    /// which programs get network access past the Kill Switch, so a non-elevated program must not change them.
    /// (By default ProgramData subfolders let any user create files.)
    /// </summary>
    internal static class AppDataDir
    {
        public static readonly string Path = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sveto4");

        private static volatile bool secured;

        /// <summary>The folder permissions were applied in this process (the log waits for it).</summary>
        public static bool Secured => secured;

        public static string Ensure()
        {
            Directory.CreateDirectory(Path);
            if (secured) return Path;
            try
            {
                var security = new DirectorySecurity();
                // Owner too: the owner can always rewrite permissions, and a user may have created the folder first.
                security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
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

        /// <summary>
        /// Call before reading or rewriting a file (or folder) in the app folder. A file moved in from elsewhere
        /// keeps its old permissions, e.g. full access for the user, so a non-elevated program could change it;
        /// such a file gets the folder's permissions back. Throws if the permissions cannot be checked.
        /// </summary>
        public static void Trust(string path)
        {
            Ensure();
            if (!File.Exists(path) && !Directory.Exists(path)) return;
            if (FolderSecurity.IsAdminOnlyItem(path)) return;
            FolderSecurity.ResetItem(path);
            Log.Info("Permissions reset (could be changed without administrator rights): " + path);
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
            AppDataDir.Trust(DisabledFile);
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
            AppDataDir.Trust(DisabledFile);
            AtomicFile.WriteAllLines(DisabledFile, rules.Select(r => r.Kind + "\t" + r.RuleName));
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
            AppDataDir.Trust(SettingsFile);
            return File.ReadAllLines(SettingsFile)
                .Select(line => line.Split(new[] { '=' }, 2))
                .Where(parts => parts.Length == 2 && parts[0].Trim() == key)
                .Select(parts => parts[1].Trim())
                .LastOrDefault();
        }

        private static readonly object SettingsSync = new object();

        /// <summary>Read-modify-write under a lock: settings are written from worker threads.</summary>
        private static void WriteSetting(string key, string value)
        {
            lock (SettingsSync)
            {
                AppDataDir.Trust(SettingsFile);
                var lines = File.Exists(SettingsFile)
                    ? File.ReadAllLines(SettingsFile).Where(l => !l.StartsWith(key + "=")).ToList()
                    : new List<string>();
                lines.Add(key + "=" + value);
                AtomicFile.WriteAllLines(SettingsFile, lines);
            }
        }
    }
}
