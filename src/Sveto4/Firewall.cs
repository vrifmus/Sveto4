using System;
using System.Collections.Generic;
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

    /// <summary>
    /// Late-bound wrapper over the Windows Firewall COM API (HNetCfg.FwPolicy2).
    /// COM "Name" of a rule is the same as DisplayName in PowerShell cmdlets,
    /// so rules created by the legacy script are recognized.
    /// </summary>
    internal static class Firewall
    {
        public const int ProfileDomain = 1;
        public const int ProfilePrivate = 2;
        public const int ProfilePublic = 4;
        public static readonly int[] Profiles = { ProfileDomain, ProfilePrivate, ProfilePublic };

        private const int ProfilesAll = 0x7FFFFFFF;
        private const int DirectionOut = 2;
        private const int ActionBlock = 0;
        private const int ActionAllow = 1;
        private const string RuleGroup = "Sveto4";

        public static string ProfileName(int profile) =>
            profile == ProfileDomain ? "Domain" : profile == ProfilePrivate ? "Private" : "Public";

        public static bool IsFirewallEnabled(int profile) =>
            Convert.ToBoolean(GetIndexed(NewPolicy(), "FirewallEnabled", profile));

        public static bool IsOutboundBlocked(int profile) =>
            Convert.ToInt32(GetIndexed(NewPolicy(), "DefaultOutboundAction", profile)) == ActionBlock;

        public static void SetOutboundBlocked(int profile, bool block) =>
            SetIndexed(NewPolicy(), "DefaultOutboundAction", profile, block ? ActionBlock : ActionAllow);

        /// <summary>Returns all rules whose name starts with the prefix (case-insensitive).</summary>
        public static List<RuleInfo> GetRules(string prefix)
        {
            var result = new List<RuleInfo>();
            dynamic policy = NewPolicy();
            foreach (dynamic rule in policy.Rules)
            {
                string name = rule.Name;
                if (name != null && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    result.Add(new RuleInfo(name, (bool)rule.Enabled));
            }
            return result;
        }

        public static bool Exists(string name)
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

        /// <summary>Enables or disables every rule with this exact name.</summary>
        public static void SetEnabled(string name, bool enabled)
        {
            dynamic policy = NewPolicy();
            foreach (dynamic rule in policy.Rules)
            {
                string ruleName = rule.Name;
                if (string.Equals(ruleName, name, StringComparison.OrdinalIgnoreCase))
                    rule.Enabled = enabled;
            }
        }

        /// <summary>Removes every rule whose name matches the predicate.</summary>
        public static void RemoveWhere(Func<string, bool> match)
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

        /// <summary>Creates an outbound Allow rule for all profiles.</summary>
        public static void AddOutboundAllow(string name, bool enabled, Action<dynamic> configure)
        {
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
            rule.Name = name;
            rule.Grouping = RuleGroup;
            rule.Direction = DirectionOut;
            rule.Action = ActionAllow;
            rule.Profiles = ProfilesAll;
            configure?.Invoke(rule);
            rule.Enabled = enabled;

            dynamic policy = NewPolicy();
            policy.Rules.Add(rule);
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
