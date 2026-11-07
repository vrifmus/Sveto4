using System;
using System.Management;

namespace Sveto4
{
    /// <summary>
    /// Hyper-V firewall (Windows 11 22H2+): filters traffic of WSL before it reaches the host.
    /// Host rules are merged into it, but interface rules (KS-Allow-*) do not apply there,
    /// so WSL needs its own Allow rule. Replaced by a fake in tests.
    /// </summary>
    internal interface IHyperVFirewall
    {
        /// <summary>WSL is registered as a Hyper-V firewall VM creator.</summary>
        bool IsWslAvailable();
        /// <summary>Null if the rule does not exist.</summary>
        bool? GetRuleEnabled(string name);
        /// <summary>Creates an outbound Allow rule for WSL, or enables/disables the existing one.</summary>
        void SetWslAllow(string name, bool enabled);
        void Remove(string name);
    }

    /// <summary>No Hyper-V firewall (older Windows or no WSL).</summary>
    internal sealed class NoHyperVFirewall : IHyperVFirewall
    {
        public bool IsWslAvailable() => false;
        public bool? GetRuleEnabled(string name) => null;
        public void SetWslAllow(string name, bool enabled) => throw new InvalidOperationException("Hyper-V firewall is not available");
        public void Remove(string name) { }
    }

    /// <summary>Hyper-V firewall through WMI (root\StandardCimv2), the API behind *-NetFirewallHyperVRule cmdlets.</summary>
    internal sealed class WmiHyperVFirewall : IHyperVFirewall
    {
        private const string Namespace = @"root\StandardCimv2";
        private const string RuleClass = "MSFT_NetFirewallHyperVRule";
        /// <summary>WSL's VM creator id, used if it cannot be queried.</summary>
        private const string WslCreatorId = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}";
        private const ushort Enabled = 1, Disabled = 2;
        private const ushort Outbound = 2, Allow = 2;

        private static ManagementScope Scope() => new ManagementScope(Namespace);

        /// <summary>Writes go to the persistent store, as with New-NetFirewallHyperVRule; reads use the active store.</summary>
        private static ManagementNamedValueCollection Context(bool persistent) =>
            persistent ? new ManagementNamedValueCollection { { "PolicyStore", "PersistentStore" } } : null;

        private static string WslCreator()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(Scope(),
                           new ObjectQuery("SELECT VMCreatorId FROM MSFT_NetFirewallHyperVVMCreator WHERE FriendlyName = 'WSL'")))
                using (var results = searcher.Get())
                {
                    foreach (ManagementBaseObject mo in results)
                        return mo["VMCreatorId"] as string;
                }
            }
            catch (ManagementException)
            {
                // Class missing: Hyper-V firewall not supported on this Windows.
            }
            return null;
        }

        public bool IsWslAvailable() => WslCreator() != null;

        private static ManagementObject Find(string name, bool persistent)
        {
            var options = new EnumerationOptions { Context = Context(persistent) };
            using (var searcher = new ManagementObjectSearcher(Scope(),
                       new ObjectQuery($"SELECT * FROM {RuleClass} WHERE InstanceID = '{name.Replace("'", "\\'")}'"), options))
            {
                foreach (ManagementObject mo in searcher.Get()) return mo;
            }
            return null;
        }

        public bool? GetRuleEnabled(string name)
        {
            try
            {
                using (var rule = Find(name, false))
                    return rule == null ? (bool?)null : Convert.ToUInt16(rule["Enabled"]) == Enabled;
            }
            catch (ManagementException)
            {
                return null;
            }
        }

        public void SetWslAllow(string name, bool enabled)
        {
            using (var existing = Find(name, true))
            {
                if (existing != null)
                {
                    existing.InvokeMethod(enabled ? "Enable" : "Disable", null, new InvokeMethodOptions { Context = Context(true) });
                    return;
                }
            }

            using (var cls = new ManagementClass(Scope(), new ManagementPath(RuleClass), null))
            using (var rule = cls.CreateInstance())
            {
                rule["InstanceID"] = name;
                rule["ElementName"] = name;
                rule["Direction"] = Outbound;
                rule["Action"] = Allow;
                rule["Enabled"] = enabled ? Enabled : Disabled;
                rule["VMCreatorId"] = WslCreator() ?? WslCreatorId;
                rule.Put(new PutOptions { Context = Context(true), Type = PutType.CreateOnly });
            }
        }

        public void Remove(string name)
        {
            using (var rule = Find(name, true))
                rule?.Delete(new DeleteOptions { Context = Context(true) });
        }
    }
}
