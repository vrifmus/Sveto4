using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class ActionTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly List<ProcessEntry> processes = new List<ProcessEntry>
        {
            new ProcessEntry { Pid = 10, ParentPid = 1, Name = "Happ.exe", ExePath = @"C:\Happ\Happ.exe" },
            new ProcessEntry { Pid = 12, ParentPid = 10, Name = "xray.exe", ExePath = @"C:\Happ\core\xray.exe" },
        };

        private KillSwitch Create() => new KillSwitch(fw, () => processes, path => true);

        private string[] RuleNames() => fw.Rules.Select(r => r.Name).OrderBy(n => n).ToArray();

        [Fact]
        public void SetMode_BlocksAndAllowsAllProfiles()
        {
            var ks = Create();
            ks.SetMode(true);
            Assert.All(fw.Blocked.Values, Assert.True);
            ks.SetMode(false);
            Assert.All(fw.Blocked.Values, Assert.False);
        }

        [Fact]
        public void SelectInterface_PlainAdapter_CreatesOnlyInterfaceRule()
        {
            Create().SelectInterface("Wi-Fi");

            var rule = Assert.Single(fw.Rules);
            Assert.Equal("KS-Allow-Wi-Fi", rule.Name);
            Assert.Equal("Wi-Fi", rule.Interface);
            Assert.True(rule.Enabled);
        }

        [Fact]
        public void SelectInterface_ClientAdapter_AlsoAllowsClientProcesses()
        {
            Create().SelectInterface("happ-xray");

            Assert.Equal(new[] { "KS-Allow-happ-xray", "KS-App-happ-Happ", "KS-App-happ-xray" }, RuleNames());
            Assert.Equal(@"C:\Happ\core\xray.exe", fw.Find("KS-App-happ-xray").ApplicationName);
        }

        [Fact]
        public void SelectInterface_ExistingDisabledRule_IsEnabledNotDuplicated()
        {
            fw.Rules.Add(new RuleSpec { Name = "KS-Allow-Wi-Fi", Interface = "Wi-Fi", Enabled = false });

            Create().SelectInterface("Wi-Fi");

            Assert.True(Assert.Single(fw.Rules).Enabled);
        }

        [Fact]
        public void SelectInterface_Twice_DoesNotDuplicateAppRules()
        {
            var ks = Create();
            ks.SelectInterface("happ-xray");
            ks.SelectInterface("happ-sing-box");

            Assert.Single(fw.Rules, r => r.Name == "KS-App-happ-xray");
        }

        [Fact]
        public void DeselectLastClientInterface_RemovesAppRules()
        {
            var ks = Create();
            ks.SelectInterface("happ-xray");
            ks.SelectInterface("Wi-Fi");

            ks.DeselectInterface("happ-xray", remaining: new[] { "Wi-Fi" });

            Assert.Equal(new[] { "KS-Allow-Wi-Fi" }, RuleNames());
        }

        [Fact]
        public void DeselectClientInterface_KeepsAppRulesWhileAnotherClientAdapterSelected()
        {
            var ks = Create();
            ks.SelectInterface("happ-xray");
            ks.SelectInterface("happ-sing-box");

            ks.DeselectInterface("happ-xray", remaining: new[] { "happ-sing-box" });

            Assert.Equal(new[] { "KS-Allow-happ-sing-box", "KS-App-happ-Happ", "KS-App-happ-xray" }, RuleNames());
        }

        [Fact]
        public void SetLan_CreatesThenTogglesSubnetRules()
        {
            var ks = Create();

            ks.SetLan(true);
            Assert.Equal(KillSwitch.LanSubnets.Count, fw.Rules.Count);
            Assert.All(fw.Rules, r => Assert.True(r.Enabled));
            Assert.Equal("10.0.0.0/255.0.0.0", fw.Find("KS-LAN-Allow-10.0.0.0/8").RemoteAddresses);

            ks.SetLan(false);
            Assert.Equal(KillSwitch.LanSubnets.Count, fw.Rules.Count);
            Assert.All(fw.Rules, r => Assert.False(r.Enabled));
        }

        [Fact]
        public void SetNat_AllowsSystemProcess()
        {
            Create().SetNat(true);

            var rule = Assert.Single(fw.Rules);
            Assert.Equal("KS-NAT-Allow", rule.Name);
            Assert.Equal("System", rule.ApplicationName);
        }

        [Fact]
        public void ClearInterfaces_KeepsLanAndNat()
        {
            var ks = Create();
            ks.SelectInterface("happ-xray");
            ks.SetNat(true);

            ks.ClearInterfaces();

            Assert.Equal(new[] { "KS-NAT-Allow" }, RuleNames());
        }

        [Fact]
        public void ResetAll_AllowsTrafficAndRemovesOnlyOwnRules()
        {
            fw.Rules.Add(new RuleSpec { Name = "Core Networking - DNS (UDP-Out)" });
            var ks = Create();
            ks.SetMode(true);
            ks.SelectInterface("happ-xray");
            ks.SetLan(true);

            ks.ResetAll();

            Assert.All(fw.Blocked.Values, Assert.False);
            Assert.Equal(new[] { "Core Networking - DNS (UDP-Out)" }, RuleNames());
        }

        [Fact]
        public void ReadBack_MatchesActions()
        {
            var ks = Create();
            ks.SetMode(true);
            ks.SelectInterface("happ-xray");
            ks.SetLan(true);

            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);

            Assert.Equal(KsMode.On, s.Mode);
            Assert.Equal(new[] { "happ-xray" }, s.Interfaces.ToArray());
            Assert.True(s.Lan);
            Assert.False(s.Nat);
        }
    }
}
