using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Sveto4
{
    internal sealed class RuleInfo
    {
        public RuleInfo(string name, bool enabled)
        {
            Name = name;
            Enabled = enabled;
        }

        public string Name { get; }
        public bool Enabled { get; }
    }

    /// <summary>Outbound Allow rule for all profiles. Only one of the filters is normally set.</summary>
    internal sealed class RuleSpec
    {
        public string Name;
        public bool Enabled = true;
        /// <summary>Interface alias (e.g. "Wi-Fi").</summary>
        public string Interface;
        /// <summary>Full exe path, or "System" for the kernel.</summary>
        public string ApplicationName;
        /// <summary>Address or subnet, e.g. "10.0.0.0/255.0.0.0".</summary>
        public string RemoteAddresses;
    }

    /// <summary>Properties of an existing rule, used to recognize system rules regardless of UI language.</summary>
    internal sealed class RuleProps
    {
        public string Name;
        public bool Enabled;
        /// <summary>Outbound Allow rule; the remaining fields are filled only for such rules.</summary>
        public bool IsOutboundAllow;
        public string ApplicationName;
        public string ServiceName;
        /// <summary>IANA protocol number: 6 = TCP, 17 = UDP, 41 = IPv6, 256 = any.</summary>
        public int Protocol;
        public string RemotePorts;
    }

    /// <summary>Windows Firewall operations used by the kill switch. Replaced by a fake in tests.</summary>
    internal interface IFirewall
    {
        bool IsFirewallEnabled(int profile);
        bool IsOutboundBlocked(int profile);
        void SetOutboundBlocked(int profile, bool block);
        /// <summary>All rules in one pass (enumerating ~600 COM rules is the slowest operation).</summary>
        List<RuleProps> GetAllRules();
        bool Exists(string name);
        /// <summary>Enables or disables every rule with this exact name.</summary>
        void SetEnabled(string name, bool enabled);
        /// <summary>Removes every rule whose name matches the predicate.</summary>
        void RemoveWhere(Func<string, bool> match);
        void AddOutboundAllow(RuleSpec spec);
        /// <summary>
        /// Enables or disables every outbound Allow rule matching the predicate, in one pass.
        /// <paramref name="beforeChange"/> receives the matches before anything is changed.
        /// </summary>
        /// <returns>The rules that were changed.</returns>
        List<RuleProps> SetOutboundAllowEnabledWhere(Func<RuleProps, bool> match, bool enabled,
                                                     Action<List<RuleProps>> beforeChange = null);
    }

    internal static class Firewall
    {
        public const int ProfileDomain = 1;
        public const int ProfilePrivate = 2;
        public const int ProfilePublic = 4;
        public static readonly int[] Profiles = { ProfileDomain, ProfilePrivate, ProfilePublic };

        public static string ProfileName(int profile) =>
            profile == ProfileDomain ? "Domain" : profile == ProfilePrivate ? "Private" : "Public";
    }

    /// <summary>
    /// Late-bound wrapper over the Windows Firewall COM API (HNetCfg.FwPolicy2).
    /// COM "Name" of a rule is the same as DisplayName in PowerShell cmdlets,
    /// so rules created by the legacy script are recognized.
    /// </summary>
    internal sealed class ComFirewall : IFirewall
    {
        private const int ProfilesAll = 0x7FFFFFFF;
        private const int DirectionOut = 2;
        private const int ActionBlock = 0;
        private const int ActionAllow = 1;
        private const string RuleGroup = "Sveto4";

        public bool IsFirewallEnabled(int profile) =>
            Convert.ToBoolean(GetIndexed(NewPolicy(), "FirewallEnabled", profile));

        public bool IsOutboundBlocked(int profile) =>
            Convert.ToInt32(GetIndexed(NewPolicy(), "DefaultOutboundAction", profile)) == ActionBlock;

        public void SetOutboundBlocked(int profile, bool block) =>
            SetIndexed(NewPolicy(), "DefaultOutboundAction", profile, block ? ActionBlock : ActionAllow);

        public List<RuleProps> GetAllRules()
        {
            var result = new List<RuleProps>();
            dynamic policy = NewPolicy();
            foreach (dynamic rule in policy.Rules)
                result.Add(ToProps(rule));
            return result;
        }

        public bool Exists(string name)
        {
            dynamic policy = NewPolicy();
            try
            {
                object rule = policy.Rules.Item(name);
                return rule != null;
            }
            catch (Exception)
            {
                // Item() throws when the rule is not found.
                return false;
            }
        }

        public void SetEnabled(string name, bool enabled)
        {
            dynamic policy = NewPolicy();
            foreach (dynamic rule in policy.Rules)
            {
                string ruleName = rule.Name;
                if (string.Equals(ruleName, name, StringComparison.OrdinalIgnoreCase))
                    rule.Enabled = enabled;
            }
        }

        public void RemoveWhere(Func<string, bool> match)
        {
            dynamic policy = NewPolicy();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (dynamic rule in policy.Rules)
            {
                string name = rule.Name;
                if (name != null && match(name)) names.Add(name);
            }

            foreach (var name in names)
            {
                // Remove() deletes one rule per call; repeat to catch duplicates.
                for (var i = 0; i < 16 && Exists(name); i++)
                {
                    try { policy.Rules.Remove(name); }
                    catch (Exception ex) { Log.Error(ex, "remove rule " + name); break; }
                }
            }
        }

        public void AddOutboundAllow(RuleSpec spec)
        {
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
            rule.Name = spec.Name;
            rule.Grouping = RuleGroup;
            rule.Direction = DirectionOut;
            rule.Action = ActionAllow;
            rule.Profiles = ProfilesAll;
            if (spec.Interface != null) rule.Interfaces = new object[] { spec.Interface };
            if (spec.ApplicationName != null) rule.ApplicationName = spec.ApplicationName;
            if (spec.RemoteAddresses != null) rule.RemoteAddresses = spec.RemoteAddresses;
            rule.Enabled = spec.Enabled;

            dynamic policy = NewPolicy();
            policy.Rules.Add(rule);
        }

        public List<RuleProps> SetOutboundAllowEnabledWhere(Func<RuleProps, bool> match, bool enabled,
                                                            Action<List<RuleProps>> beforeChange = null)
        {
            var matches = new List<(dynamic Rule, RuleProps Props)>();
            dynamic policy = NewPolicy();
            foreach (dynamic rule in policy.Rules)
            {
                RuleProps props = ToProps(rule);
                if (props.IsOutboundAllow && match(props)) matches.Add((rule, props));
            }

            var changed = matches.Select(m => m.Props).ToList();
            beforeChange?.Invoke(changed);
            foreach (var m in matches) m.Rule.Enabled = enabled;
            return changed;
        }

        /// <summary>Reads rule properties; details only for outbound Allow rules (fewer COM calls).</summary>
        private static RuleProps ToProps(dynamic rule)
        {
            var props = new RuleProps { Name = rule.Name, Enabled = (bool)rule.Enabled };
            props.IsOutboundAllow = (int)rule.Direction == DirectionOut && (int)rule.Action == ActionAllow;
            if (props.IsOutboundAllow)
            {
                props.ApplicationName = rule.ApplicationName;
                props.ServiceName = rule.ServiceName;
                props.Protocol = (int)rule.Protocol;
                props.RemotePorts = rule.RemotePorts;
            }
            return props;
        }

        private static object NewPolicy() =>
            Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));

        // Parameterized COM properties (indexed by profile) are not reachable via "dynamic".
        private static object GetIndexed(object com, string property, int profile) =>
            com.GetType().InvokeMember(property, BindingFlags.GetProperty, null, com, new object[] { profile });

        private static void SetIndexed(object com, string property, int profile, object value) =>
            com.GetType().InvokeMember(property, BindingFlags.SetProperty, null, com, new object[] { profile, value });
    }
}
