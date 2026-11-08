using System;
using System.Collections.Generic;
using System.Linq;

namespace Sveto4.Tests
{
    /// <summary>In-memory Hyper-V firewall: never touches the system.</summary>
    internal sealed class FakeHyperV : IHyperVFirewall
    {
        public bool Available = true;
        public readonly Dictionary<string, bool> Rules = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public bool IsWslAvailable() => Available;
        public bool? GetRuleEnabled(string name) => Rules.TryGetValue(name, out var on) ? on : (bool?)null;
        public void SetWslAllow(string name, bool enabled)
        {
            if (!Available) throw new InvalidOperationException("no WSL");
            Rules[name] = enabled;
        }
        public void Remove(string name) => Rules.Remove(name);
    }

    /// <summary>In-memory firewall: records state, never touches the system.</summary>
    internal sealed class FakeFirewall : IFirewall
    {
        public readonly Dictionary<int, bool> Enabled = Firewall.Profiles.ToDictionary(p => p, p => true);
        public readonly Dictionary<int, bool> Blocked = Firewall.Profiles.ToDictionary(p => p, p => false);
        public readonly List<RuleSpec> Rules = new List<RuleSpec>();

        public RuleSpec Find(string name) =>
            Rules.SingleOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));

        public bool IsFirewallEnabled(int profile) => Enabled[profile];
        public bool IsOutboundBlocked(int profile) => Blocked[profile];
        public void SetOutboundBlocked(int profile, bool block) => Blocked[profile] = block;

        /// <summary>Number of full passes over all rules (the slow operation in the real firewall).</summary>
        public int Enumerations;

        public List<RuleProps> GetAllRules()
        {
            Enumerations++;
            return Rules.Select(r => new RuleProps
                        {
                            Name = r.Name, Enabled = r.Enabled, IsOutboundAllow = true,
                            ApplicationName = r.ApplicationName, Protocol = 256,
                        })
                        .Concat(SystemRules.Select(Copy))
                        .ToList();
        }

        public bool Exists(string name) => Find(name) != null;

        public void SetEnabled(string name, bool enabled)
        {
            foreach (var r in Rules.Where(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
                r.Enabled = enabled;
        }

        public void RemoveWhere(Func<string, bool> match) => Rules.RemoveAll(r => match(r.Name));

        public void AddOutboundAllow(RuleSpec spec) => Rules.Add(spec);

        /// <summary>System outbound Allow rules (own KS rules are not mirrored here).</summary>
        public readonly List<RuleProps> SystemRules = new List<RuleProps>();

        public List<RuleProps> SetOutboundAllowEnabledWhere(Func<RuleProps, bool> match, bool enabled,
                                                            Action<List<RuleProps>> beforeChange = null)
        {
            Enumerations++;
            var matches = SystemRules.Where(r => match(Copy(r))).ToList();
            var changed = matches.Select(Copy).ToList();
            beforeChange?.Invoke(changed);
            foreach (var r in matches) r.Enabled = enabled;
            return changed;
        }

        private static RuleProps Copy(RuleProps r) => new RuleProps
        {
            Name = r.Name, Enabled = r.Enabled, IsOutboundAllow = true, ApplicationName = r.ApplicationName,
            ServiceName = r.ServiceName, Protocol = r.Protocol, RemotePorts = r.RemotePorts,
        };
    }

    internal sealed class FakeStore : IStateStore
    {
        public List<LeakInfo> Disabled = new List<LeakInfo>();
        public List<LeakInfo> LoadDisabledRules() => Disabled.ToList();
        public void SaveDisabledRules(List<LeakInfo> rules) => Disabled = rules.ToList();
        public bool BlockSystemLeaks { get; set; } = true;
        public readonly Dictionary<string, bool> Clients = new Dictionary<string, bool>();
        public bool? GetClientEnabled(string clientId) => Clients.TryGetValue(clientId, out var v) ? v : (bool?)null;
        public void SetClientEnabled(string clientId, bool enabled) => Clients[clientId] = enabled;
        public readonly Dictionary<string, List<string>> ClientAdapters = new Dictionary<string, List<string>>();
        public List<string> GetClientAdapters(string clientId) =>
            ClientAdapters.TryGetValue(clientId, out var v) ? v.ToList() : new List<string>();
        public void SetClientAdapters(string clientId, IEnumerable<string> adapters) => ClientAdapters[clientId] = adapters.ToList();
    }
}
