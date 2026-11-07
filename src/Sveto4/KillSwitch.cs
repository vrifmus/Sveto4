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

    /// <summary>What the tray icon shows; mapped to a color in <see cref="TrayApp"/>.</summary>
    internal enum IconState
    {
        Busy,
        Off,
        Partial,
        NoInterfaces,
        AdapterMissing,
        Connected,
        Disconnected
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

    internal sealed class ProfileStatus
    {
        public ProfileStatus(string name, bool firewallEnabled, bool outboundBlocked)
        {
            Name = name;
            FirewallEnabled = firewallEnabled;
            OutboundBlocked = outboundBlocked;
        }

        public string Name { get; }
        public bool FirewallEnabled { get; }
        public bool OutboundBlocked { get; }
    }

    /// <summary>A system Allow rule that lets traffic bypass the kill switch.</summary>
    internal sealed class LeakInfo
    {
        public LeakInfo(string kind, string ruleName)
        {
            Kind = kind;
            RuleName = ruleName;
        }

        /// <summary>Short description, e.g. "DNS".</summary>
        public string Kind { get; }
        public string RuleName { get; }
    }

    internal sealed class ProcessEntry
    {
        public uint Pid;
        public uint ParentPid;
        public string Name;
        public string ExePath;
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
        /// <summary>System rules that bypass the kill switch (warning only, not changed).</summary>
        public List<LeakInfo> Leaks = new List<LeakInfo>();

        public void CopyRulesFrom(KsState other)
        {
            RulesLoaded = other.RulesLoaded;
            Leaks = other.Leaks;
            Rules = other.Rules;
            Interfaces = other.Interfaces;
            Lan = other.Lan;
            Nat = other.Nat;
        }
    }

    /// <summary>
    /// Kill switch logic. Instance methods are blocking and must run off the UI thread.
    /// Static methods are pure and covered by unit tests.
    /// Rule names are compatible with the legacy PowerShell version.
    /// </summary>
    internal sealed class KillSwitch
    {
        public const string Prefix = "KS-";
        public const string AllowPrefix = Prefix + "Allow-";
        public const string AppPrefix = Prefix + "App-";
        public const string LanPrefix = Prefix + "LAN-Allow-";
        public const string NatRule = Prefix + "NAT-Allow";

        // Rule name suffix (CIDR, as in the legacy version) -> firewall address.
        public static readonly IReadOnlyDictionary<string, string> LanSubnets = new Dictionary<string, string>
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

        private readonly IFirewall firewall;
        private readonly Func<IEnumerable<ProcessEntry>> getProcesses;
        private readonly Func<string, bool> fileExists;

        public KillSwitch(IFirewall firewall, Func<IEnumerable<ProcessEntry>> getProcesses, Func<string, bool> fileExists)
        {
            this.firewall = firewall;
            this.getProcesses = getProcesses;
            this.fileExists = fileExists;
        }

        public static KillSwitch CreateDefault() => new KillSwitch(new ComFirewall(), GetWmiProcesses, File.Exists);

        // ---------- Pure logic ----------

        public static void ApplyProfiles(KsState s, IEnumerable<ProfileStatus> profiles)
        {
            var blocked = new List<string>();
            var open = new List<string>();
            foreach (var p in profiles)
            {
                if (!p.FirewallEnabled) open.Add(p.Name + " (firewall disabled)");
                else if (p.OutboundBlocked) blocked.Add(p.Name);
                else open.Add(p.Name);
            }

            s.Mode = open.Count == 0 ? KsMode.On : blocked.Count == 0 ? KsMode.Off : KsMode.Partial;
            s.NotBlocked = s.Mode == KsMode.Partial ? string.Join(", ", open) : "";
        }

        public static void ApplyRules(KsState s, List<RuleInfo> rules)
        {
            s.Rules = rules;
            s.Interfaces = new HashSet<string>(
                rules.Where(r => r.Enabled && r.Name.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase))
                     .Select(r => r.Name.Substring(AllowPrefix.Length)),
                StringComparer.OrdinalIgnoreCase);
            s.Lan = rules.Any(r => r.Enabled && r.Name.StartsWith(LanPrefix, StringComparison.OrdinalIgnoreCase));
            s.Nat = rules.Any(r => r.Enabled && string.Equals(r.Name, NatRule, StringComparison.OrdinalIgnoreCase));
            s.RulesLoaded = true;
        }

        public static IconState GetIconState(KsState s, bool busy)
        {
            if (busy) return IconState.Busy;
            if (s.Mode == KsMode.Off) return IconState.Off;
            if (s.Mode == KsMode.Partial) return IconState.Partial;
            if (s.Interfaces.Count == 0) return IconState.NoInterfaces;

            var present = s.Adapters.Where(a => s.Interfaces.Contains(a.Name)).ToList();
            if (present.Count == 0) return IconState.AdapterMissing;
            return present.Any(a => a.IsUp) ? IconState.Connected : IconState.Disconnected;
        }

        public static bool IsSystemAdapter(string description) =>
            SystemAdapterMarkers.Any(m => (description ?? "").IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);

        /// <summary>Returns the VPN client whose name occurs in the interface name, or null.</summary>
        public static string MatchApp(string iface) =>
            TargetApps.FirstOrDefault(a => iface.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0);

        public const string LeakDns = "DNS";
        public const string LeakIpv6Tunnel = "IPv6 tunnel (6to4/ISATAP)";
        public const string LeakTeredo = "Teredo tunnel";
        public const string LeakIpHttps = "IP-HTTPS tunnel";

        private const int ProtocolTcp = 6;
        private const int ProtocolUdp = 17;
        private const int ProtocolIpv6 = 41;

        /// <summary>
        /// Recognizes built-in "Core Networking" rules that let traffic bypass the kill switch.
        /// Matching is by properties, not by name, because rule names are localized.
        /// </summary>
        public static List<LeakInfo> FindLeaks(IEnumerable<RuleProps> enabledOutboundAllow)
        {
            var result = new List<LeakInfo>();
            foreach (var r in enabledOutboundAllow)
            {
                var kind = ClassifyLeak(r);
                if (kind != null) result.Add(new LeakInfo(kind, r.Name));
            }
            return result;
        }

        private static string ClassifyLeak(RuleProps r)
        {
            var svchost = (r.ApplicationName ?? "").EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase);
            var service = r.ServiceName ?? "";

            if (svchost && service.Equals("dnscache", StringComparison.OrdinalIgnoreCase)
                && r.Protocol == ProtocolUdp && PortsContain(r.RemotePorts, "53"))
                return LeakDns;

            if (r.Protocol == ProtocolIpv6 && string.Equals(r.ApplicationName, "System", StringComparison.OrdinalIgnoreCase))
                return LeakIpv6Tunnel;

            if (svchost && service.Equals("iphlpsvc", StringComparison.OrdinalIgnoreCase))
            {
                if (r.Protocol == ProtocolUdp) return LeakTeredo;
                if (r.Protocol == ProtocolTcp) return LeakIpHttps;
            }
            return null;
        }

        private static bool PortsContain(string ports, string port) =>
            (ports ?? "").Split(',').Any(p => p.Trim() == port);

        /// <summary>Exe paths of the client's processes and of their direct children (e.g. xray core).</summary>
        public static List<string> CollectAppPaths(IEnumerable<ProcessEntry> processes, string app)
        {
            var list = processes.ToList();
            var parents = new HashSet<uint>();
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var p in list.Where(p => p.Name != null && p.Name.IndexOf(app, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                parents.Add(p.Pid);
                if (!string.IsNullOrEmpty(p.ExePath)) paths.Add(p.ExePath);
            }
            foreach (var p in list.Where(p => parents.Contains(p.ParentPid) && !string.IsNullOrEmpty(p.ExePath)))
                paths.Add(p.ExePath);

            return paths.ToList();
        }

        // ---------- Read ----------

        public void ReadProfiles(KsState s)
        {
            ApplyProfiles(s, Firewall.Profiles.Select(p => new ProfileStatus(
                Firewall.ProfileName(p), firewall.IsFirewallEnabled(p), firewall.IsOutboundBlocked(p))));
        }

        public void ReadRules(KsState s)
        {
            ApplyRules(s, firewall.GetRules(Prefix));
            s.Leaks = FindLeaks(firewall.GetEnabledOutboundAllowRules());
        }

        public static void ReadAdapters(KsState s)
        {
            s.Adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => new AdapterInfo(n.Name, n.Description ?? "", n.OperationalStatus == OperationalStatus.Up,
                                             IsSystemAdapter(n.Description)))
                .ToList();
        }

        // ---------- Actions ----------

        public void SetMode(bool block)
        {
            foreach (var profile in Firewall.Profiles)
                firewall.SetOutboundBlocked(profile, block);
        }

        public void SetLan(bool on)
        {
            foreach (var subnet in LanSubnets)
            {
                var name = LanPrefix + subnet.Key;
                if (firewall.Exists(name)) firewall.SetEnabled(name, on);
                else firewall.AddOutboundAllow(new RuleSpec { Name = name, Enabled = on, RemoteAddresses = subnet.Value });
            }
        }

        public void SetNat(bool on)
        {
            if (firewall.Exists(NatRule)) firewall.SetEnabled(NatRule, on);
            else firewall.AddOutboundAllow(new RuleSpec { Name = NatRule, Enabled = on, ApplicationName = "System" });
        }

        public void SelectInterface(string iface)
        {
            var name = AllowPrefix + iface;
            if (firewall.Exists(name)) firewall.SetEnabled(name, true);
            else firewall.AddOutboundAllow(new RuleSpec { Name = name, Interface = iface });

            var app = MatchApp(iface);
            if (app != null) AddAppRules(app);
        }

        /// <param name="remaining">Interfaces that stay selected after this one is removed.</param>
        public void DeselectInterface(string iface, ICollection<string> remaining)
        {
            var name = AllowPrefix + iface;
            firewall.RemoveWhere(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));

            var app = MatchApp(iface);
            if (app != null && !remaining.Any(i => MatchApp(i) == app))
            {
                var appRules = AppPrefix + app + "-";
                firewall.RemoveWhere(n => n.StartsWith(appRules, StringComparison.OrdinalIgnoreCase));
            }
        }

        public void ClearInterfaces()
        {
            firewall.RemoveWhere(n => n.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase)
                                   || n.StartsWith(AppPrefix, StringComparison.OrdinalIgnoreCase));
        }

        public void ResetAll()
        {
            SetMode(false);
            firewall.RemoveWhere(n => n.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase));
        }

        // ---------- VPN client processes ----------

        /// <summary>
        /// Allows outbound traffic for the client's processes and their children,
        /// so the client can reach the VPN server through the physical interface.
        /// </summary>
        private void AddAppRules(string app)
        {
            foreach (var exePath in CollectAppPaths(getProcesses(), app).Where(fileExists))
            {
                var name = $"{AppPrefix}{app}-{Path.GetFileNameWithoutExtension(exePath)}";
                try
                {
                    firewall.RemoveWhere(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
                    firewall.AddOutboundAllow(new RuleSpec { Name = name, ApplicationName = exePath });
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "app rule " + name);
                }
            }
        }

        private static IEnumerable<ProcessEntry> GetWmiProcesses()
        {
            var result = new List<ProcessEntry>();
            using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process"))
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject mo in results)
                {
                    result.Add(new ProcessEntry
                    {
                        Pid = Convert.ToUInt32(mo["ProcessId"]),
                        ParentPid = Convert.ToUInt32(mo["ParentProcessId"]),
                        Name = mo["Name"] as string,
                        ExePath = mo["ExecutablePath"] as string,
                    });
                }
            }
            return result;
        }
    }
}
