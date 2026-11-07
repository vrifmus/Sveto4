using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;

namespace Sveto4
{
    internal enum KsMode
    {
        Off,
        On,
        /// <summary>Some firewall profiles block outbound traffic, others do not.</summary>
        Partial
    }

    internal sealed class AdapterInfo
    {
        public AdapterInfo(string name, string description, bool isUp, bool isSystem)
        {
            Name = name;
            Description = description;
            IsUp = isUp;
            IsSystem = isSystem;
        }

        public string Name { get; }
        public string Description { get; }
        public bool IsUp { get; }
        /// <summary>Service adapters (WAN Miniport, Teredo, ...) hidden from the menu.</summary>
        public bool IsSystem { get; }
    }

    /// <summary>Immutable-by-convention snapshot of kill switch state. Replaced as a whole.</summary>
    internal sealed class KsState
    {
        public KsMode Mode = KsMode.Off;
        /// <summary>Profiles that do not block traffic (filled in Partial mode).</summary>
        public string NotBlocked = "";
        public bool RulesLoaded;
        public List<RuleInfo> Rules = new List<RuleInfo>();
        public HashSet<string> Interfaces = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool Lan;
        public bool Nat;
        public List<AdapterInfo> Adapters = new List<AdapterInfo>();

        public void CopyRulesFrom(KsState other)
        {
            RulesLoaded = other.RulesLoaded;
            Rules = other.Rules;
            Interfaces = other.Interfaces;
            Lan = other.Lan;
            Nat = other.Nat;
        }
    }

    /// <summary>
    /// Kill switch logic. All methods are blocking and must run off the UI thread.
    /// Rule names are compatible with the legacy PowerShell version.
    /// </summary>
    internal static class KillSwitch
    {
        public const string Prefix = "KS-";
        private const string AllowPrefix = Prefix + "Allow-";
        private const string AppPrefix = Prefix + "App-";
        private const string LanPrefix = Prefix + "LAN-Allow-";
        private const string NatRule = Prefix + "NAT-Allow";

        // Rule name suffix (CIDR, as in the legacy version) -> firewall address.
        private static readonly Dictionary<string, string> LanSubnets = new Dictionary<string, string>
        {
            ["192.168.0.0/16"] = "192.168.0.0/255.255.0.0",
            ["10.0.0.0/8"] = "10.0.0.0/255.0.0.0",
            ["172.16.0.0/12"] = "172.16.0.0/255.240.0.0",
            ["fc00::/7"] = "fc00::/7",
        };

        /// <summary>VPN clients whose processes get their own allow rules.</summary>
        private static readonly string[] TargetApps = { "happ", "hiddify" };

        private static readonly string[] SystemAdapterMarkers =
        {
            "WAN Miniport", "Hyper-V Virtual Switch Extension", "Microsoft Kernel Debug",
            "Microsoft Wi-Fi Direct Virtual", "Teredo", "isatap", "6to4", "IP-HTTPS",
        };

        // ---------- Read ----------

        public static void ReadProfiles(KsState s)
        {
            var blocked = new List<string>();
            var open = new List<string>();
            foreach (var profile in Firewall.Profiles)
            {
                var name = Firewall.ProfileName(profile);
                if (!Firewall.IsFirewallEnabled(profile)) open.Add(name + " (firewall disabled)");
                else if (Firewall.IsOutboundBlocked(profile)) blocked.Add(name);
                else open.Add(name);
            }

            s.Mode = open.Count == 0 ? KsMode.On : blocked.Count == 0 ? KsMode.Off : KsMode.Partial;
            s.NotBlocked = s.Mode == KsMode.Partial ? string.Join(", ", open) : "";
        }

        public static void ReadRules(KsState s)
        {
            s.Rules = Firewall.GetRules(Prefix);
            s.Interfaces = new HashSet<string>(
                s.Rules.Where(r => r.Enabled && r.Name.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase))
                       .Select(r => r.Name.Substring(AllowPrefix.Length)),
                StringComparer.OrdinalIgnoreCase);
            s.Lan = s.Rules.Any(r => r.Enabled && r.Name.StartsWith(LanPrefix, StringComparison.OrdinalIgnoreCase));
            s.Nat = s.Rules.Any(r => r.Enabled && string.Equals(r.Name, NatRule, StringComparison.OrdinalIgnoreCase));
            s.RulesLoaded = true;
        }

        public static void ReadAdapters(KsState s)
        {
            var list = new List<AdapterInfo>();
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var description = n.Description ?? "";
                var isSystem = SystemAdapterMarkers.Any(m => description.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);
                list.Add(new AdapterInfo(n.Name, description, n.OperationalStatus == OperationalStatus.Up, isSystem));
            }
            s.Adapters = list;
        }

        // ---------- Actions ----------

        public static void SetMode(bool block)
        {
            foreach (var profile in Firewall.Profiles)
                Firewall.SetOutboundBlocked(profile, block);
        }

        public static void SetLan(bool on)
        {
            foreach (var subnet in LanSubnets)
            {
                var name = LanPrefix + subnet.Key;
                if (Firewall.Exists(name)) Firewall.SetEnabled(name, on);
                else Firewall.AddOutboundAllow(name, on, r => r.RemoteAddresses = subnet.Value);
            }
        }

        public static void SetNat(bool on)
        {
            if (Firewall.Exists(NatRule)) Firewall.SetEnabled(NatRule, on);
            else Firewall.AddOutboundAllow(NatRule, on, r => r.ApplicationName = "System");
        }

        public static void SelectInterface(string iface)
        {
            var name = AllowPrefix + iface;
            if (Firewall.Exists(name)) Firewall.SetEnabled(name, true);
            else Firewall.AddOutboundAllow(name, true, r => r.Interfaces = new object[] { iface });

            var app = MatchApp(iface);
            if (app != null) AddAppRules(app);
        }

        /// <param name="remaining">Interfaces that stay selected after this one is removed.</param>
        public static void DeselectInterface(string iface, ICollection<string> remaining)
        {
            var name = AllowPrefix + iface;
            Firewall.RemoveWhere(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));

            var app = MatchApp(iface);
            if (app != null && !remaining.Any(i => MatchApp(i) == app))
            {
                var appRules = AppPrefix + app + "-";
                Firewall.RemoveWhere(n => n.StartsWith(appRules, StringComparison.OrdinalIgnoreCase));
            }
        }

        public static void ClearInterfaces()
        {
            Firewall.RemoveWhere(n => n.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase)
                                   || n.StartsWith(AppPrefix, StringComparison.OrdinalIgnoreCase));
        }

        public static void ResetAll()
        {
            SetMode(false);
            Firewall.RemoveWhere(n => n.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase));
        }

        // ---------- VPN client processes ----------

        private static string MatchApp(string iface) =>
            TargetApps.FirstOrDefault(a => iface.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0);

        private sealed class ProcessEntry
        {
            public uint Pid;
            public uint ParentPid;
            public string Name;
            public string ExePath;
        }

        /// <summary>
        /// Allows outbound traffic for the client's processes and their children (e.g. xray core),
        /// so the client can reach the VPN server through the physical interface.
        /// </summary>
        private static void AddAppRules(string app)
        {
            var processes = new List<ProcessEntry>();
            using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process"))
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject mo in results)
                {
                    processes.Add(new ProcessEntry
                    {
                        Pid = Convert.ToUInt32(mo["ProcessId"]),
                        ParentPid = Convert.ToUInt32(mo["ParentProcessId"]),
                        Name = mo["Name"] as string,
                        ExePath = mo["ExecutablePath"] as string,
                    });
                }
            }

            var parents = new HashSet<uint>();
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in processes.Where(p => p.Name != null && p.Name.IndexOf(app, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                parents.Add(p.Pid);
                if (!string.IsNullOrEmpty(p.ExePath)) paths.Add(p.ExePath);
            }
            foreach (var p in processes.Where(p => parents.Contains(p.ParentPid) && !string.IsNullOrEmpty(p.ExePath)))
                paths.Add(p.ExePath);

            foreach (var exePath in paths.Where(File.Exists))
            {
                var name = $"{AppPrefix}{app}-{Path.GetFileNameWithoutExtension(exePath)}";
                try
                {
                    Firewall.RemoveWhere(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
                    Firewall.AddOutboundAllow(name, true, r => r.ApplicationName = exePath);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "app rule " + name);
                }
            }
        }
    }
}
