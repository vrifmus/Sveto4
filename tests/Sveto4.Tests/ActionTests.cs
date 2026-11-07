using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class ActionTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();

        private KillSwitch Create() => new KillSwitch(fw, TestEnv.Create(), new FakeStore());

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
        public void SelectInterface_CreatesOnlyInterfaceRule()
        {
            // Client executables are allowed by the client profile, not by selecting an adapter.
            Create().SelectInterface("happ-xray");

            var rule = Assert.Single(fw.Rules);
            Assert.Equal("KS-Allow-happ-xray", rule.Name);
            Assert.Equal("happ-xray", rule.Interface);
            Assert.True(rule.Enabled);
        }

        [Fact]
        public void SelectInterface_ExistingDisabledRule_IsEnabledNotDuplicated()
        {
            fw.Rules.Add(new RuleSpec { Name = "KS-Allow-Wi-Fi", Interface = "Wi-Fi", Enabled = false });

            Create().SelectInterface("Wi-Fi");

            Assert.True(Assert.Single(fw.Rules).Enabled);
        }

        [Fact]
        public void DeselectInterface_RemovesOnlyItsRule()
        {
            var ks = Create();
            ks.SelectInterface("Wi-Fi");
            ks.SelectInterface("Ethernet");

            ks.DeselectInterface("Wi-Fi");

            Assert.Equal(new[] { "KS-Allow-Ethernet" }, RuleNames());
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
            ks.SelectInterface("Wi-Fi");
            fw.Rules.Add(new RuleSpec { Name = "KS-App-happ-xray" });
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
