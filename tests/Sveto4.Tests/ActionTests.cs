using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class ActionTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeHyperV hyperV = new FakeHyperV();

        private KillSwitch Create() => new KillSwitch(fw, TestEnv.Create(), new FakeStore(), hyperV);

        private KsState Read(KillSwitch ks)
        {
            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            return s;
        }

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
        public void SetWsl_HyperVRuleOnly_NoSystemProcessRule()
        {
            var ks = Create();
            ks.SetWsl(true);

            Assert.Empty(fw.Rules);
            Assert.True(hyperV.Rules["KS-WSL-Allow"]);
            var s = Read(ks);
            Assert.True(s.Wsl);
            Assert.Contains(s.Rules, r => r.Name == "KS-WSL-Allow" && r.Enabled); // shown in "Rules"

            ks.SetWsl(false);
            Assert.False(hyperV.Rules["KS-WSL-Allow"]);
            Assert.False(Read(ks).Wsl);
        }

        [Fact]
        public void SetWslOff_NoRule_NothingCreated()
        {
            Create().SetWsl(false);
            Assert.Empty(hyperV.Rules);
        }

        [Fact]
        public void WslNotInstalled_Unavailable()
        {
            hyperV.Available = false;
            Assert.False(Read(Create()).WslAvailable);
        }

        [Theory]
        [InlineData(true, true, true)]    // enabled legacy rule -> Allow WSL
        [InlineData(false, true, false)]  // disabled legacy rule -> just removed
        [InlineData(true, false, false)]  // WSL not installed -> just removed
        public void Migration_ReplacesLegacyNatRule(bool legacyEnabled, bool wslAvailable, bool expectWsl)
        {
            hyperV.Available = wslAvailable;
            fw.Rules.Add(new RuleSpec { Name = "KS-NAT-Allow", ApplicationName = "System", Enabled = legacyEnabled });
            var ks = Create();
            var s = Read(ks);
            Assert.True(KillSwitch.NeedsNatMigration(s));

            ks.MigrateNatRule(s);

            Assert.Empty(fw.Rules);
            var after = Read(ks);
            Assert.Equal(expectWsl, after.Wsl);
            Assert.False(KillSwitch.NeedsNatMigration(after));
        }

        [Fact]
        public void ClearInterfaces_KeepsLanAndWsl()
        {
            var ks = Create();
            ks.SelectInterface("Wi-Fi");
            fw.Rules.Add(new RuleSpec { Name = "KS-App-happ-xray" });
            ks.SetLan(true);
            ks.SetWsl(true);

            ks.ClearInterfaces();

            Assert.All(fw.Rules, r => Assert.StartsWith("KS-LAN-", r.Name));
            Assert.True(hyperV.Rules["KS-WSL-Allow"]);
        }

        [Fact]
        public void ResetAll_RemovesWslRule()
        {
            var ks = Create();
            ks.SetWsl(true);
            ks.ResetAll();
            Assert.Empty(hyperV.Rules);
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
            Assert.False(s.Wsl);
        }
    }
}
