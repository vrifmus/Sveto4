using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class LeakBlockingTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeStore store = new FakeStore();
        private readonly RuleProps dns = LeakTests.Dns();
        private readonly RuleProps teredo = LeakTests.Teredo;
        private readonly RuleProps dhcp = new RuleProps
        {
            Name = "Core Networking - DHCP-Out", Enabled = true, ApplicationName = @"%SystemRoot%\system32\svchost.exe",
            ServiceName = "dhcp", Protocol = 17, RemotePorts = "67",
        };

        public LeakBlockingTests()
        {
            fw.SystemRules.AddRange(new[] { dns, teredo, dhcp });
        }

        private KillSwitch Create() => new KillSwitch(fw, () => new ProcessEntry[0], p => true, store);

        [Fact]
        public void TurnOn_DisablesLeakRulesOnly_AndRemembersThem()
        {
            Create().SetMode(true);

            Assert.False(dns.Enabled);
            Assert.False(teredo.Enabled);
            Assert.True(dhcp.Enabled);
            Assert.Equal(new[] { dns.Name, teredo.Name }, store.Disabled.Select(r => r.RuleName).ToArray());
        }

        [Fact]
        public void TurnOff_RestoresOnlyRulesDisabledByApp()
        {
            var userDisabled = LeakTests.IpHttps;
            userDisabled.Enabled = false; // disabled by the user before, must stay disabled
            fw.SystemRules.Add(userDisabled);
            var ks = Create();

            ks.SetMode(true);
            ks.SetMode(false);

            Assert.True(dns.Enabled);
            Assert.True(teredo.Enabled);
            Assert.False(userDisabled.Enabled);
            Assert.Empty(store.Disabled);
        }

        [Fact]
        public void ResetAll_Restores()
        {
            var ks = Create();
            ks.SetMode(true);
            ks.ResetAll();

            Assert.True(dns.Enabled);
            Assert.Empty(store.Disabled);
        }

        [Fact]
        public void SettingOff_TurnOnLeavesRulesAlone()
        {
            store.BlockSystemLeaks = false;
            Create().SetMode(true);

            Assert.True(dns.Enabled);
            Assert.Empty(store.Disabled);
        }

        [Fact]
        public void SwitchSettingOffWhileOn_Restores_AndOnAgain_Disables()
        {
            var ks = Create();
            ks.SetMode(true);

            ks.SetBlockLeaks(false, killSwitchActive: true);
            Assert.True(dns.Enabled);
            Assert.False(store.BlockSystemLeaks);

            ks.SetBlockLeaks(true, killSwitchActive: true);
            Assert.False(dns.Enabled);
        }

        [Fact]
        public void SwitchSettingOnWhileOff_DoesNotDisable()
        {
            store.BlockSystemLeaks = false;
            Create().SetBlockLeaks(true, killSwitchActive: false);

            Assert.True(dns.Enabled);
            Assert.True(store.BlockSystemLeaks);
        }

        [Fact]
        public void RepeatedTurnOn_DoesNotDuplicateRecords()
        {
            var ks = Create();
            ks.SetMode(true);
            dns.Enabled = true; // re-enabled by Windows update
            ks.SetMode(true);

            Assert.Equal(2, store.Disabled.Count);
            Assert.False(dns.Enabled);
        }

        [Fact]
        public void TurnOnAndOff_PassOverRulesOnceEach()
        {
            var ks = Create();
            ks.SetMode(true);
            Assert.Equal(1, fw.Enumerations);

            ks.SetMode(false);
            Assert.Equal(2, fw.Enumerations);
        }

        [Fact]
        public void ReadRules_PassesOverRulesOnce()
        {
            Create().ReadRules(new KsState());
            Assert.Equal(1, fw.Enumerations);
        }

        [Fact]
        public void BlockSystemLeaks_SavesListBeforeDisabling()
        {
            var savedWhileEnabled = false;
            var store2 = new RecordingStore(() => savedWhileEnabled = dns.Enabled);
            new KillSwitch(fw, () => new ProcessEntry[0], p => true, store2).SetMode(true);

            Assert.True(savedWhileEnabled);
            Assert.False(dns.Enabled);
        }

        private sealed class RecordingStore : IStateStore
        {
            private readonly System.Action onSave;
            private List<LeakInfo> disabled = new List<LeakInfo>();
            public RecordingStore(System.Action onSave) => this.onSave = onSave;
            public List<LeakInfo> LoadDisabledRules() => disabled.ToList();
            public void SaveDisabledRules(List<LeakInfo> rules) { onSave(); disabled = rules.ToList(); }
            public bool BlockSystemLeaks { get; set; } = true;
        }

        [Fact]
        public void ReadRules_ReportsOpenAndDisabledLeaks()
        {
            var ks = Create();
            ks.SetMode(true);

            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);

            Assert.Empty(s.Leaks);
            Assert.Equal(2, s.DisabledLeaks.Count);
            Assert.True(s.BlockLeaks);
            Assert.False(KillSwitch.NeedsLeakReconcile(s));
        }

        [Fact]
        public void Reconcile_ReDisablesRuleReEnabledByWindows()
        {
            var ks = Create();
            ks.SetMode(true);
            dns.Enabled = true;

            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            Assert.True(KillSwitch.NeedsLeakReconcile(s));

            ks.ReconcileLeaks(s);
            Assert.False(dns.Enabled);
        }

        [Fact]
        public void Reconcile_RestoresWhenKillSwitchTurnedOffOutsideApp()
        {
            var ks = Create();
            ks.SetMode(true);
            foreach (var p in Firewall.Profiles) fw.Blocked[p] = false; // turned off in Windows settings

            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            Assert.True(KillSwitch.NeedsLeakReconcile(s));

            ks.ReconcileLeaks(s);
            Assert.True(dns.Enabled);
            Assert.True(teredo.Enabled);
            Assert.Empty(store.Disabled);
        }

        [Theory]
        [InlineData((int)KsMode.On, true, 1, 0, true)]   // open leak while on -> disable
        [InlineData((int)KsMode.On, true, 0, 2, false)]  // all blocked -> nothing to do
        [InlineData((int)KsMode.On, false, 1, 0, false)] // setting off: leaks are only reported
        [InlineData((int)KsMode.On, false, 0, 2, true)]  // setting off but rules still disabled -> restore
        [InlineData((int)KsMode.Off, true, 1, 0, false)] // off: leaks are irrelevant
        [InlineData((int)KsMode.Off, true, 0, 2, true)]  // off but rules still disabled -> restore
        [InlineData((int)KsMode.Partial, true, 1, 0, true)]
        public void NeedsLeakReconcile(int mode, bool block, int open, int disabled, bool expected)
        {
            var s = new KsState
            {
                Mode = (KsMode)mode,
                BlockLeaks = block,
                Leaks = Enumerable.Range(0, open).Select(i => new LeakInfo("DNS", "r" + i)).ToList(),
                DisabledLeaks = Enumerable.Range(0, disabled).Select(i => new LeakInfo("DNS", "d" + i)).ToList(),
            };
            Assert.Equal(expected, KillSwitch.NeedsLeakReconcile(s));
        }
    }
}
