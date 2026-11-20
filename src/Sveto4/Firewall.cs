using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

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
        /// <summary>IANA protocol number: 6 = TCP, 17 = UDP, 256 = any.</summary>
        public int Protocol = 256;
        /// <summary>Remote ports, e.g. "22" or "8000-8100" (only with TCP/UDP).</summary>
        public string RemotePorts;
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
        /// <summary>Rule group; built-in Windows groups are resource references like "@FirewallAPI.dll,-23255".</summary>
        public string Grouping;
        /// <summary>IANA protocol number: 6 = TCP, 17 = UDP, 41 = IPv6, 256 = any.</summary>
        public int Protocol;
        public string RemotePorts;
    }

    /// <summary>Windows Firewall operations used by the Kill Switch. Replaced by a fake in tests.</summary>
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
    /// Every COM object is released explicitly: the managed heap barely grows, so the GC
    /// would rarely run and the native memory behind unreleased objects would pile up.
    /// </summary>
    internal sealed class ComFirewall : IFirewall
    {
        private const int ProfilesAll = 0x7FFFFFFF;
        private const int DirectionOut = 2;
        private const int ActionBlock = 0;
        private const int ActionAllow = 1;
        private const string RuleGroup = "Sveto4";

        public bool IsFirewallEnabled(int profile) =>
            WithPolicy(policy => Convert.ToBoolean(GetIndexed(policy, "FirewallEnabled", profile)));

        public bool IsOutboundBlocked(int profile) =>
            WithPolicy(policy => Convert.ToInt32(GetIndexed(policy, "DefaultOutboundAction", profile)) == ActionBlock);

        public void SetOutboundBlocked(int profile, bool block) =>
            WithPolicy(policy =>
            {
                SetIndexed(policy, "DefaultOutboundAction", profile, block ? ActionBlock : ActionAllow);
                return true;
            });

        public List<RuleProps> GetAllRules()
        {
            var result = new List<RuleProps>();
            WithRules(rules => ForEachRule(rules, rule => result.Add(ToProps(rule))));
            return result;
        }

        public bool Exists(string name) => WithRules(rules => Exists(rules, name));

        private static bool Exists(object rules, string name)
        {
            object rule = null;
            try
            {
                rule = ((dynamic)rules).Item(name);
                return rule != null;
            }
            catch (Exception)
            {
                // Item() throws when the rule is not found.
                return false;
            }
            finally
            {
                Release(rule);
            }
        }

        public void SetEnabled(string name, bool enabled) =>
            WithRules(rules => ForEachRule(rules, rule =>
            {
                dynamic r = rule;
                string ruleName = r.Name;
                if (string.Equals(ruleName, name, StringComparison.OrdinalIgnoreCase))
                    r.Enabled = enabled;
            }));

        public void RemoveWhere(Func<string, bool> match) =>
            WithRules(rules =>
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ForEachRule(rules, rule =>
                {
                    string name = ((dynamic)rule).Name;
                    if (name != null && match(name)) names.Add(name);
                });

                foreach (var name in names)
                {
                    // Remove() deletes one rule per call; repeat to catch duplicates.
                    for (var i = 0; i < 16 && Exists(rules, name); i++)
                    {
                        try { ((dynamic)rules).Remove(name); }
                        catch (Exception ex) { Log.Error(ex, "remove rule " + name); break; }
                    }
                }
            });

        public void AddOutboundAllow(RuleSpec spec)
        {
            object com = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
            try
            {
                dynamic rule = com;
                rule.Name = spec.Name;
                rule.Grouping = RuleGroup;
                rule.Direction = DirectionOut;
                rule.Action = ActionAllow;
                rule.Profiles = ProfilesAll;
                if (spec.Interface != null) rule.Interfaces = new object[] { spec.Interface };
                if (spec.ApplicationName != null) rule.ApplicationName = spec.ApplicationName;
                if (spec.RemoteAddresses != null) rule.RemoteAddresses = spec.RemoteAddresses;
                // Ports can only be set after a protocol that has ports.
                if (spec.Protocol != 256) rule.Protocol = spec.Protocol;
                if (spec.RemotePorts != null) rule.RemotePorts = spec.RemotePorts;
                rule.Enabled = spec.Enabled;

                WithRules(rules => { ((dynamic)rules).Add(com); });
            }
            finally
            {
                Release(com);
            }
        }

        public List<RuleProps> SetOutboundAllowEnabledWhere(Func<RuleProps, bool> match, bool enabled,
                                                            Action<List<RuleProps>> beforeChange = null)
        {
            var matches = new List<(object Rule, RuleProps Props)>();
            try
            {
                return WithRules(rules =>
                {
                    ForEachRuleKeeping(rules, rule =>
                    {
                        RuleProps props = ToProps(rule);
                        if (!props.IsOutboundAllow || !match(props)) return false;
                        matches.Add((rule, props)); // released in the outer finally
                        return true;
                    });

                    var changed = matches.Select(m => m.Props).ToList();
                    beforeChange?.Invoke(changed);
                    foreach (var m in matches) ((dynamic)m.Rule).Enabled = enabled;
                    return changed;
                });
            }
            finally
            {
                foreach (var m in matches) Release(m.Rule);
            }
        }

        /// <summary>Reads rule properties; details only for outbound Allow rules (fewer COM calls).</summary>
        /// <remarks>
        /// Takes "object", not "dynamic": a call with a dynamic COM argument is bound anew every time,
        /// about 20 times slower, and the binder keeps memory the GC never frees (~2 MB per full read).
        /// </remarks>
        private static RuleProps ToProps(object com)
        {
            dynamic rule = com;
            var props = new RuleProps { Name = rule.Name, Enabled = (bool)rule.Enabled };
            props.IsOutboundAllow = (int)rule.Direction == DirectionOut && (int)rule.Action == ActionAllow;
            if (props.IsOutboundAllow)
            {
                props.ApplicationName = rule.ApplicationName;
                props.ServiceName = rule.ServiceName;
                props.Grouping = rule.Grouping;
                props.Protocol = (int)rule.Protocol;
                props.RemotePorts = rule.RemotePorts;
            }
            return props;
        }

        /// <summary>Runs <paramref name="use"/> with a new policy object and releases it afterwards.</summary>
        private static T WithPolicy<T>(Func<object, T> use)
        {
            object policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            try
            {
                return use(policy);
            }
            finally
            {
                Release(policy);
            }
        }

        /// <summary>Runs <paramref name="use"/> with the rule collection of a new policy object.</summary>
        private static T WithRules<T>(Func<object, T> use) =>
            WithPolicy(policy =>
            {
                object rules = ((dynamic)policy).Rules;
                try
                {
                    return use(rules);
                }
                finally
                {
                    Release(rules);
                }
            });

        private static void WithRules(Action<object> use) =>
            WithRules(rules =>
            {
                use(rules);
                return true;
            });

        /// <summary>Calls <paramref name="visit"/> for every rule and releases each rule right after.</summary>
        /// <remarks>The rule is passed as "object" for the reason given at <see cref="ToProps"/>.</remarks>
        private static void ForEachRule(object rules, Action<object> visit) =>
            ForEachRuleKeeping(rules, rule =>
            {
                visit(rule);
                return false;
            });

        /// <summary>
        /// Calls <paramref name="visit"/> for every rule. A rule is released right after the call
        /// unless <paramref name="visit"/> returns true: then the caller owns and releases it.
        /// </summary>
        private static void ForEachRuleKeeping(object rules, Func<object, bool> visit)
        {
            var enumerator = ((IEnumerable)rules).GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    object rule = enumerator.Current;
                    var kept = false;
                    try
                    {
                        kept = visit(rule);
                    }
                    finally
                    {
                        if (!kept) Release(rule);
                    }
                }
            }
            finally
            {
                // The managed enumerator wraps a COM IEnumVARIANT.
                if (enumerator is ICustomAdapter adapter) Release(adapter.GetUnderlyingObject());
            }
        }

        private static void Release(object com)
        {
            if (com != null && Marshal.IsComObject(com)) Marshal.FinalReleaseComObject(com);
        }

        // Parameterized COM properties (indexed by profile) are not reachable via "dynamic".
        private static object GetIndexed(object com, string property, int profile) =>
            com.GetType().InvokeMember(property, BindingFlags.GetProperty, null, com, new object[] { profile });

        private static void SetIndexed(object com, string property, int profile, object value) =>
            com.GetType().InvokeMember(property, BindingFlags.SetProperty, null, com, new object[] { profile, value });
    }
}
