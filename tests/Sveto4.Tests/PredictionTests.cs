using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    /// <summary>
    /// The predicted state (shown in the menu right after a click) must match
    /// what is read back from the firewall after the action completes.
    /// </summary>
    public class PredictionTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeStore store = new FakeStore();
        private readonly FakeHyperV hyperV = new FakeHyperV();
        private readonly FakeExceptionStore exceptions = new FakeExceptionStore();
        private readonly KillSwitch ks;

        public PredictionTests()
        {
            fw.SystemRules.Add(LeakTests.Dns());
            fw.SystemRules.Add(LeakTests.Teredo);
            ks = new KillSwitch(fw, TestEnv.Create(files: TestEnv.HappFiles, adapters: adapters), store, hyperV, exceptionStore: exceptions);
        }

        private readonly List<AdapterInfo> adapters = new List<AdapterInfo>
        {
            TestEnv.Adapter("Wi-Fi"),
            TestEnv.Adapter("happ-xray", "Happ Tunnel"),
        };

        private KsState Read()
        {
            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            ks.ReadAdapters(s);
            return s;
        }

        /// <summary>Runs the action and checks that the prediction equals the state read afterwards.</summary>
        private void Check(Action action, Func<KsState, KsState> predict)
        {
            var before = Read();
            var predicted = predict(before);
            action();
            var actual = Read();

            Assert.Equal(actual.Mode, predicted.Mode);
            Assert.Equal(actual.Lan, predicted.Lan);
            Assert.Equal(actual.Wsl, predicted.Wsl);
            Assert.Equal(actual.BlockLeaks, predicted.BlockLeaks);
            Assert.Equal(Sorted(actual.Interfaces), Sorted(predicted.Interfaces));
            Assert.Equal(Sorted(actual.Leaks.Select(l => l.RuleName)), Sorted(predicted.Leaks.Select(l => l.RuleName)));
            Assert.Equal(Sorted(actual.DisabledLeaks.Select(l => l.RuleName)), Sorted(predicted.DisabledLeaks.Select(l => l.RuleName)));
            Assert.Equal(Sorted(actual.Exceptions.Select(x => x.Entry.Name + ":" + x.Enabled)),
                         Sorted(predicted.Exceptions.Select(x => x.Entry.Name + ":" + x.Enabled)));
            Assert.Equal(Sorted(actual.Clients.Where(c => c.Enabled).Select(c => c.Profile.Id)),
                         Sorted(predicted.Clients.Where(c => c.Enabled).Select(c => c.Profile.Id)));
            // Client executable rules depend on files on disk and are not predicted.
            Assert.Equal(OwnRules(actual), OwnRules(predicted));
        }

        private static string[] Sorted(IEnumerable<string> items) => items.OrderBy(i => i, StringComparer.OrdinalIgnoreCase).ToArray();

        private static string[] OwnRules(KsState s) =>
            Sorted(s.Rules.Where(r => !r.Name.StartsWith(KillSwitch.AppPrefix)).Select(r => r.Name + ":" + r.Enabled));

        [Fact]
        public void TurnOn() => Check(() => ks.SetMode(true), s => KillSwitch.PredictMode(s, true));

        [Fact]
        public void TurnOn_WithoutLeakBlocking()
        {
            store.BlockSystemLeaks = false;
            Check(() => ks.SetMode(true), s => KillSwitch.PredictMode(s, true));
        }

        [Fact]
        public void TurnOff()
        {
            ks.SetMode(true);
            Check(() => ks.SetMode(false), s => KillSwitch.PredictMode(s, false));
        }

        [Fact]
        public void BlockLeaksOff_WhileOn()
        {
            ks.SetMode(true);
            Check(() => ks.SetBlockLeaks(false, true), s => KillSwitch.PredictBlockLeaks(s, false, true));
        }

        [Fact]
        public void BlockLeaksOn_WhileOn()
        {
            store.BlockSystemLeaks = false;
            ks.SetMode(true);
            Check(() => ks.SetBlockLeaks(true, true), s => KillSwitch.PredictBlockLeaks(s, true, true));
        }

        [Fact]
        public void BlockLeaksOn_WhileOff()
        {
            store.BlockSystemLeaks = false;
            Check(() => ks.SetBlockLeaks(true, false), s => KillSwitch.PredictBlockLeaks(s, true, false));
        }

        [Fact]
        public void LanOnAndOff()
        {
            Check(() => ks.SetLan(true), s => KillSwitch.PredictLan(s, true));
            Check(() => ks.SetLan(false), s => KillSwitch.PredictLan(s, false));
        }

        [Fact]
        public void WslOnAndOff()
        {
            Check(() => ks.SetWsl(true), s => KillSwitch.PredictWsl(s, true));
            Check(() => ks.SetWsl(false), s => KillSwitch.PredictWsl(s, false));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void NatMigration(bool legacyEnabled)
        {
            fw.Rules.Add(new RuleSpec { Name = "KS-NAT-Allow", ApplicationName = "System", Enabled = legacyEnabled });
            var snapshot = Read();
            Check(() => ks.MigrateNatRule(snapshot), KillSwitch.PredictNatMigration);
        }

        [Fact]
        public void SelectAndDeselect()
        {
            Check(() => ks.SelectInterface("happ-xray"), s => KillSwitch.PredictSelect(s, "happ-xray"));
            Check(() => ks.SelectInterface("Wi-Fi"), s => KillSwitch.PredictSelect(s, "Wi-Fi"));
            Check(() => ks.DeselectInterface("happ-xray"), s => KillSwitch.PredictDeselect(s, "happ-xray"));
        }

        [Fact]
        public void EnableAndDisableHapp()
        {
            Check(() => ks.EnableClient(ClientProfiles.Happ), s => KillSwitch.PredictClient(s, ClientProfiles.Happ, true));
            var snapshot = Read();
            Check(() => ks.DisableClient(ClientProfiles.Happ, snapshot), s => KillSwitch.PredictClient(s, ClientProfiles.Happ, false));
        }

        [Fact]
        public void ClearInterfaces_DisablesClient()
        {
            ks.EnableClient(ClientProfiles.Happ);
            Check(() => ks.ClearInterfaces(), KillSwitch.PredictClear);
        }

        [Fact]
        public void ClearInterfaces()
        {
            ks.SelectInterface("happ-xray");
            ks.SetLan(true);
            Check(() => ks.ClearInterfaces(), KillSwitch.PredictClear);
        }

        [Fact]
        public void ResetAll()
        {
            ks.SetMode(true);
            ks.SelectInterface("happ-xray");
            ks.SetLan(true);
            ks.SetWsl(true);
            ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Tcp, "22");
            Check(() => ks.ResetAll(), KillSwitch.PredictReset);
        }

        [Fact]
        public void ResetAll_WhileOff()
        {
            ks.SelectInterface("happ-xray");
            Check(() => ks.ResetAll(), KillSwitch.PredictReset);
        }

        [Fact]
        public void Exceptions_AddToggleRemove()
        {
            var entry = Exceptions.Create("SSH", "203.0.113.5", null, ExceptionProtocol.Tcp, "22", new string[0]);
            Check(() => ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Tcp, "22"),
                  s => KillSwitch.PredictAddException(s, entry));
            Check(() => ks.SetExceptionEnabled(entry, false), s => KillSwitch.PredictException(s, entry, false));
            Check(() => ks.SetExceptionEnabled(entry, true), s => KillSwitch.PredictException(s, entry, true));
            Check(() => ks.RemoveException(entry), s => KillSwitch.PredictRemoveException(s, entry));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Exceptions_Edit(bool enabled)
        {
            var old = ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Tcp, "22");
            ks.AddException("Other", "203.0.113.6", null, ExceptionProtocol.Any, null);
            if (!enabled) ks.SetExceptionEnabled(old, false);
            var updated = Exceptions.Create("VPS", "203.0.113.7", null, ExceptionProtocol.Tcp, "2222", new string[0]);
            Check(() => ks.EditException(old, "VPS", "203.0.113.7", null, ExceptionProtocol.Tcp, "2222", enabled),
                  s => KillSwitch.PredictEditException(s, old, updated, enabled));
        }

        [Fact]
        public void Prediction_DoesNotModifyOriginal()
        {
            var before = Read();
            KillSwitch.PredictSelect(before, "Wi-Fi");
            KillSwitch.PredictMode(before, true);
            Assert.Empty(before.Interfaces);
            Assert.Equal(KsMode.Off, before.Mode);
            Assert.Equal(2, before.Leaks.Count);
        }
    }
}
