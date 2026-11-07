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
        /// <summary>Enabled system rules that let traffic bypass the kill switch.</summary>
        public List<LeakInfo> Leaks = new List<LeakInfo>();
        /// <summary>System rules disabled by the app while the kill switch is on.</summary>
        public List<LeakInfo> DisabledLeaks = new List<LeakInfo>();
        /// <summary>"Block system leaks" setting.</summary>
        public bool BlockLeaks = true;
        /// <summary>VPN client profiles and whether they are enabled.</summary>
        public List<ClientStatus> Clients = new List<ClientStatus>();

        public bool IsClientEnabled(string clientId) => Clients.Any(c => c.Enabled && c.Profile.Id == clientId);

        /// <summary>Enabled client that manages this interface, or null.</summary>
        public ClientProfile ManagingClient(string iface) =>
            Clients.Where(c => c.Enabled).Select(c => c.Profile)
                   .FirstOrDefault(p => ClientProfiles.IsClientAdapterName(p, iface, this));

        /// <summary>Copy with its own collections (adapters are shared: they are never modified).</summary>
        public KsState Clone() => new KsState
        {
            Mode = Mode,
            NotBlocked = NotBlocked,
            RulesLoaded = RulesLoaded,
            Rules = new List<RuleInfo>(Rules),
            Interfaces = new HashSet<string>(Interfaces, StringComparer.OrdinalIgnoreCase),
            Lan = Lan,
            Nat = Nat,
            Adapters = Adapters,
            Leaks = new List<LeakInfo>(Leaks),
            DisabledLeaks = new List<LeakInfo>(DisabledLeaks),
            BlockLeaks = BlockLeaks,
            Clients = new List<ClientStatus>(Clients),
        };

        public void CopyRulesFrom(KsState other)
        {
            RulesLoaded = other.RulesLoaded;
            Clients = other.Clients;
            Leaks = other.Leaks;
            DisabledLeaks = other.DisabledLeaks;
            BlockLeaks = other.BlockLeaks;
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

        private static readonly string[] SystemAdapterMarkers =
        {
            "WAN Miniport", "Hyper-V Virtual Switch Extension", "Microsoft Kernel Debug",
            "Microsoft Wi-Fi Direct Virtual", "Teredo", "isatap", "6to4", "IP-HTTPS",
        };

        private readonly IFirewall firewall;
        private readonly ClientEnvironment env;
        private readonly IStateStore store;

        public KillSwitch(IFirewall firewall, ClientEnvironment env, IStateStore store)
        {
            this.firewall = firewall;
            this.env = env;
            this.store = store;
        }

        public static KillSwitch CreateDefault() =>
            new KillSwitch(new ComFirewall(), ClientProfiles.CreateDefaultEnvironment(GetWmiProcesses), new FileStateStore());

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

        // ---------- Tray tooltip ----------

        /// <summary>Multi-line tooltip; the interface list is shortened with "…" to fit <paramref name="maxLength"/>.</summary>
        public static string FormatTooltip(KsState s, int maxLength)
        {
            var mode = s.Mode == KsMode.On ? "ON" : s.Mode == KsMode.Partial ? "PARTIAL" : "OFF";
            string leaks;
            if (!s.BlockLeaks) leaks = "OFF";
            else if (s.Mode != KsMode.Off && s.Leaks.Count > 0) leaks = $"ON, {s.Leaks.Count} open";
            else if (s.DisabledLeaks.Count > 0) leaks = $"ON ({s.DisabledLeaks.Count})";
            else leaks = "ON";

            var head = string.Join("\n",
                "Sveto4",
                "Kill switch: " + mode,
                "LAN: " + OnOff(s.Lan),
                "NAT (WSL): " + OnOff(s.Nat),
                "VPN clients: " + (s.Clients.Any(c => c.Enabled)
                    ? string.Join(", ", s.Clients.Where(c => c.Enabled).Select(c => c.Profile.Name))
                    : "none"),
                "Block system leaks: " + leaks,
                "Interfaces: ");

            var interfaces = s.Interfaces.Count == 0
                ? "none"
                : string.Join(", ", s.Interfaces.OrderBy(i => i, StringComparer.OrdinalIgnoreCase));

            var room = maxLength - head.Length;
            if (interfaces.Length > room)
                interfaces = room > 1 ? interfaces.Substring(0, room - 1) + "…" : "";
            var text = head + interfaces;
            return text.Length > maxLength ? text.Substring(0, maxLength) : text;
        }

        private static string OnOff(bool on) => on ? "ON" : "OFF";

        // ---------- Predicted state (shown immediately, corrected by the next read) ----------

        public static KsState PredictMode(KsState s, bool block)
        {
            var n = s.Clone();
            n.Mode = block ? KsMode.On : KsMode.Off;
            n.NotBlocked = "";
            if (!block) MoveLeaks(n.DisabledLeaks, n.Leaks);
            else if (n.BlockLeaks) MoveLeaks(n.Leaks, n.DisabledLeaks);
            return n;
        }

        public static KsState PredictBlockLeaks(KsState s, bool on, bool killSwitchActive)
        {
            var n = s.Clone();
            n.BlockLeaks = on;
            if (!on) MoveLeaks(n.DisabledLeaks, n.Leaks);
            else if (killSwitchActive) MoveLeaks(n.Leaks, n.DisabledLeaks);
            return n;
        }

        public static KsState PredictLan(KsState s, bool on)
        {
            var n = s.Clone();
            n.Lan = on;
            foreach (var subnet in LanSubnets.Keys) SetRule(n, LanPrefix + subnet, on);
            return n;
        }

        public static KsState PredictNat(KsState s, bool on)
        {
            var n = s.Clone();
            n.Nat = on;
            SetRule(n, NatRule, on);
            return n;
        }

        public static KsState PredictSelect(KsState s, string iface)
        {
            var n = s.Clone();
            n.Interfaces.Add(iface);
            SetRule(n, AllowPrefix + iface, true);
            return n;
        }

        public static KsState PredictDeselect(KsState s, string iface)
        {
            var n = s.Clone();
            n.Interfaces.Remove(iface);
            RemoveRules(n, r => string.Equals(r, AllowPrefix + iface, StringComparison.OrdinalIgnoreCase));
            return n;
        }

        /// <remarks>Executable rules (KS-App-*) are not predicted: they depend on files on disk.</remarks>
        public static KsState PredictClient(KsState s, ClientProfile profile, bool on)
        {
            var n = s.Clone();
            SetClientEnabled(n, profile.Id, on);
            if (on)
            {
                foreach (var name in ClientProfiles.PlanAdapters(profile, n).ToSelect)
                {
                    n.Interfaces.Add(name);
                    SetRule(n, AllowPrefix + name, true);
                }
            }
            else
            {
                foreach (var iface in n.Interfaces.Where(i => ClientProfiles.IsClientAdapterName(profile, i, n)).ToList())
                {
                    n.Interfaces.Remove(iface);
                    RemoveRules(n, r => string.Equals(r, AllowPrefix + iface, StringComparison.OrdinalIgnoreCase));
                }
                RemoveRules(n, r => r.StartsWith(AppPrefix + profile.Id + "-", StringComparison.OrdinalIgnoreCase));
            }
            return n;
        }

        public static KsState PredictClear(KsState s)
        {
            var n = s.Clone();
            n.Interfaces.Clear();
            RemoveRules(n, r => r.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase)
                             || r.StartsWith(AppPrefix, StringComparison.OrdinalIgnoreCase));
            foreach (var c in n.Clients.ToList()) SetClientEnabled(n, c.Profile.Id, false);
            return n;
        }

        public static KsState PredictReset(KsState s)
        {
            var n = PredictClear(PredictMode(s, false));
            n.Lan = false;
            n.Nat = false;
            n.Rules = new List<RuleInfo>();
            return n;
        }

        private static void SetClientEnabled(KsState n, string clientId, bool on) =>
            n.Clients = n.Clients.Select(c => c.Profile.Id == clientId ? new ClientStatus(c.Profile, on, c.InstallDir) : c).ToList();

        private static void MoveLeaks(List<LeakInfo> from, List<LeakInfo> to)
        {
            foreach (var leak in from)
                if (!to.Any(l => l.Kind == leak.Kind && l.RuleName == leak.RuleName))
                    to.Add(leak);
            from.Clear();
        }

        private static void SetRule(KsState n, string name, bool enabled)
        {
            RemoveRules(n, r => string.Equals(r, name, StringComparison.OrdinalIgnoreCase));
            n.Rules.Add(new RuleInfo(name, enabled));
        }

        private static void RemoveRules(KsState n, Func<string, bool> match) =>
            n.Rules.RemoveAll(r => match(r.Name));

        public static bool IsSystemAdapter(string description) =>
            SystemAdapterMarkers.Any(m => (description ?? "").IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);

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

        /// <summary>
        /// True when system rules must be disabled (kill switch on, blocking enabled, leaks open)
        /// or restored (kill switch off or blocking disabled, but some rules are still disabled by us).
        /// </summary>
        public static bool NeedsLeakReconcile(KsState s)
        {
            var shouldBlock = s.Mode != KsMode.Off && s.BlockLeaks;
            return shouldBlock ? s.Leaks.Count > 0 : s.DisabledLeaks.Count > 0;
        }

        public static string ClassifyLeak(RuleProps r)
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

        /// <summary>
        /// True when an enabled client has adapters to add/remove, or its executable rules are missing
        /// (e.g. the client was installed after the profile was enabled).
        /// </summary>
        public static bool NeedsClientSync(KsState s) =>
            s.Clients.Where(c => c.Enabled).Any(c =>
                !ClientProfiles.PlanAdapters(c.Profile, s).IsEmpty
                || (c.InstallDir != null && !s.Rules.Any(r => r.Name.StartsWith(AppPrefix + c.Profile.Id + "-", StringComparison.OrdinalIgnoreCase))));

        /// <summary>Rule names for client executables; duplicates in subfolders get a numeric suffix.</summary>
        public static List<KeyValuePair<string, string>> AppRuleNames(ClientProfile profile, IEnumerable<string> exePaths)
        {
            var result = new List<KeyValuePair<string, string>>();
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var path in exePaths)
            {
                var baseName = $"{AppPrefix}{profile.Id}-{Path.GetFileNameWithoutExtension(path)}";
                var name = baseName;
                for (var i = 2; !used.Add(name); i++) name = baseName + "-" + i;
                result.Add(new KeyValuePair<string, string>(name, path));
            }
            return result;
        }

        // ---------- Read ----------

        public void ReadProfiles(KsState s)
        {
            ApplyProfiles(s, Firewall.Profiles.Select(p => new ProfileStatus(
                Firewall.ProfileName(p), firewall.IsFirewallEnabled(p), firewall.IsOutboundBlocked(p))));
        }

        public void ReadRules(KsState s)
        {
            var all = firewall.GetAllRules();
            ApplyRules(s, all.Where(r => r.Name != null && r.Name.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
                             .Select(r => new RuleInfo(r.Name, r.Enabled))
                             .ToList());
            s.Leaks = FindLeaks(all.Where(r => r.IsOutboundAllow && r.Enabled));
            s.DisabledLeaks = store.LoadDisabledRules();
            s.BlockLeaks = store.BlockSystemLeaks;
            s.Clients = ClientProfiles.All
                .Select(p => new ClientStatus(p, IsClientEnabled(p, s.Rules), ClientProfiles.ResolveInstallDir(p, env)))
                .ToList();
        }

        /// <summary>Stored setting; before it is first set, a client counts as enabled if its rules exist (migration).</summary>
        private bool IsClientEnabled(ClientProfile profile, List<RuleInfo> rules) =>
            store.GetClientEnabled(profile.Id)
            ?? rules.Any(r => r.Name.StartsWith(AppPrefix + profile.Id + "-", StringComparison.OrdinalIgnoreCase));

        public void ReadAdapters(KsState s) => s.Adapters = env.Adapters();

        // ---------- Actions ----------

        public void SetMode(bool block)
        {
            foreach (var profile in Firewall.Profiles)
                firewall.SetOutboundBlocked(profile, block);

            if (!block) RestoreSystemLeaks();
            else if (store.BlockSystemLeaks) BlockSystemLeaks();
        }

        /// <param name="killSwitchActive">Kill switch is on (fully or partially).</param>
        public void SetBlockLeaks(bool on, bool killSwitchActive)
        {
            store.BlockSystemLeaks = on;
            if (!on) RestoreSystemLeaks();
            else if (killSwitchActive) BlockSystemLeaks();
        }

        /// <summary>Brings system rules in line with the state (self-healing after external changes).</summary>
        public void ReconcileLeaks(KsState s)
        {
            if (s.Mode != KsMode.Off && s.BlockLeaks) BlockSystemLeaks();
            else RestoreSystemLeaks();
        }

        /// <summary>Disables enabled leak rules and remembers them for restoring.</summary>
        private void BlockSystemLeaks()
        {
            // One pass over the rules. The list is saved before anything is disabled,
            // so restoring still knows every rule if disabling fails halfway.
            var changed = firewall.SetOutboundAllowEnabledWhere(r => r.Enabled && ClassifyLeak(r) != null, false, matches =>
            {
                if (matches.Count == 0) return;
                var records = store.LoadDisabledRules();
                foreach (var leak in FindLeaks(matches))
                    if (!records.Any(r => r.Kind == leak.Kind && r.RuleName == leak.RuleName))
                        records.Add(leak);
                store.SaveDisabledRules(records);
            });
            if (changed.Count > 0)
                Log.Info("Disabled system rules: " + string.Join("; ", changed.Select(r => r.Name)));
        }

        /// <summary>Re-enables only the rules this app disabled.</summary>
        private void RestoreSystemLeaks()
        {
            var records = store.LoadDisabledRules();
            if (records.Count == 0) return;

            firewall.SetOutboundAllowEnabledWhere(
                r => !r.Enabled && records.Any(rec => rec.Kind == ClassifyLeak(r) && rec.RuleName == r.Name), true);
            store.SaveDisabledRules(new List<LeakInfo>());
            Log.Info("Restored system rules: " + string.Join("; ", records.Select(l => l.RuleName)));
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
        }

        public void DeselectInterface(string iface)
        {
            var name = AllowPrefix + iface;
            firewall.RemoveWhere(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>"None": removes all interface and client rules and disables client profiles.</summary>
        public void ClearInterfaces()
        {
            foreach (var profile in ClientProfiles.All) store.SetClientEnabled(profile.Id, false);
            firewall.RemoveWhere(n => n.StartsWith(AllowPrefix, StringComparison.OrdinalIgnoreCase)
                                   || n.StartsWith(AppPrefix, StringComparison.OrdinalIgnoreCase));
        }

        public void ResetAll()
        {
            SetMode(false);
            foreach (var profile in ClientProfiles.All) store.SetClientEnabled(profile.Id, false);
            firewall.RemoveWhere(n => n.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase));
        }

        // ---------- VPN client profiles ----------

        /// <summary>Allows the client's executables and all its present tunnel adapters.</summary>
        public void EnableClient(ClientProfile profile)
        {
            store.SetClientEnabled(profile.Id, true);
            AddClientAppRules(profile);

            var s = new KsState();
            ReadRules(s);
            ReadAdapters(s);
            foreach (var iface in ClientProfiles.PlanAdapters(profile, s).ToSelect) SelectInterface(iface);
        }

        /// <summary>Removes the client's executable rules and its adapter rules.</summary>
        public void DisableClient(ClientProfile profile, KsState s)
        {
            store.SetClientEnabled(profile.Id, false);
            firewall.RemoveWhere(n => n.StartsWith(AppPrefix + profile.Id + "-", StringComparison.OrdinalIgnoreCase));
            foreach (var iface in s.Interfaces.Where(i => ClientProfiles.IsClientAdapterName(profile, i, s)).ToList())
                DeselectInterface(iface);
        }

        /// <summary>For enabled clients: adds new adapters, removes vanished ones, restores missing executable rules.</summary>
        public void SyncClients(KsState s)
        {
            foreach (var c in s.Clients.Where(c => c.Enabled))
            {
                var plan = ClientProfiles.PlanAdapters(c.Profile, s);
                foreach (var iface in plan.ToSelect) SelectInterface(iface);
                foreach (var iface in plan.ToDeselect) DeselectInterface(iface);
                if (plan.ToSelect.Count + plan.ToDeselect.Count > 0)
                    Log.Info($"{c.Profile.Name} adapters: +[{string.Join(", ", plan.ToSelect)}] -[{string.Join(", ", plan.ToDeselect)}]");

                var hasAppRules = s.Rules.Any(r => r.Name.StartsWith(AppPrefix + c.Profile.Id + "-", StringComparison.OrdinalIgnoreCase));
                if (!hasAppRules && c.InstallDir != null) AddClientAppRules(c.Profile);
            }
        }

        /// <summary>
        /// Allows every executable in the client's install folder (not only running ones),
        /// so cores started later (e.g. sing-box) can reach the VPN server through the physical interface.
        /// </summary>
        private void AddClientAppRules(ClientProfile profile)
        {
            var dir = ClientProfiles.ResolveInstallDir(profile, env);
            if (dir == null)
            {
                Log.Info(profile.Name + ": install folder not found");
                return;
            }

            var appRules = AppPrefix + profile.Id + "-";
            firewall.RemoveWhere(n => n.StartsWith(appRules, StringComparison.OrdinalIgnoreCase));
            foreach (var rule in AppRuleNames(profile, ClientProfiles.ExecutablesToAllow(profile, dir, env)))
            {
                try
                {
                    firewall.AddOutboundAllow(new RuleSpec { Name = rule.Key, ApplicationName = rule.Value });
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "app rule " + rule.Key);
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
