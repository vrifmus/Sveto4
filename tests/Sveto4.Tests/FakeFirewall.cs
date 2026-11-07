using System;
using System.Collections.Generic;
using System.Linq;

namespace Sveto4.Tests
{
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

        public List<RuleInfo> GetRules(string prefix) =>
            Rules.Where(r => r.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                 .Select(r => new RuleInfo(r.Name, r.Enabled))
                 .ToList();

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

        public List<RuleProps> GetOutboundAllowRules() =>
            SystemRules.Select(r => new RuleProps
            {
                Name = r.Name, Enabled = r.Enabled, ApplicationName = r.ApplicationName,
                ServiceName = r.ServiceName, Protocol = r.Protocol, RemotePorts = r.RemotePorts,
            }).ToList();

        public void SetOutboundAllowEnabledWhere(Func<RuleProps, bool> match, bool enabled)
        {
            foreach (var r in SystemRules.Where(match).ToList())
                r.Enabled = enabled;
        }
    }

    internal sealed class FakeStore : IStateStore
    {
        public List<LeakInfo> Disabled = new List<LeakInfo>();
        public List<LeakInfo> LoadDisabledRules() => Disabled.ToList();
        public void SaveDisabledRules(List<LeakInfo> rules) => Disabled = rules.ToList();
        public bool BlockSystemLeaks { get; set; } = true;
    }
}
