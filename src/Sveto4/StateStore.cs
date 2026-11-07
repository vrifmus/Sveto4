using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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
    }

    /// <summary>Files in %ProgramData%\Sveto4 (machine-wide, the app always runs elevated).</summary>
    internal sealed class FileStateStore : IStateStore
    {
        private static readonly string Dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sveto4");
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
            Directory.CreateDirectory(Dir);
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
            Directory.CreateDirectory(Dir);
            var lines = File.Exists(SettingsFile)
                ? File.ReadAllLines(SettingsFile).Where(l => !l.StartsWith(key + "=")).ToList()
                : new List<string>();
            lines.Add(key + "=" + value);
            File.WriteAllLines(SettingsFile, lines);
        }
    }
}
