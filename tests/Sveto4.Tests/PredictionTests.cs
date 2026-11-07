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
        private readonly KillSwitch ks;

        public PredictionTests()
        {
            fw.SystemRules.Add(LeakTests.Dns());
            fw.SystemRules.Add(LeakTests.Teredo);
            var processes = new[]
            {
                new ProcessEntry { Pid = 10, ParentPid = 1, Name = "Happ.exe", ExePath = @"C:\Happ\Happ.exe" },
            };
            ks = new KillSwitch(fw, () => processes, p => true, store);
        }

        private KsState Read()
        {
            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
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
            Assert.Equal(actual.Nat, predicted.Nat);
            Assert.Equal(actual.BlockLeaks, predicted.BlockLeaks);
            Assert.Equal(Sorted(actual.Interfaces), Sorted(predicted.Interfaces));
            Assert.Equal(Sorted(actual.Leaks.Select(l => l.RuleName)), Sorted(predicted.Leaks.Select(l => l.RuleName)));
            Assert.Equal(Sorted(actual.DisabledLeaks.Select(l => l.RuleName)), Sorted(predicted.DisabledLeaks.Select(l => l.RuleName)));
            // Client process rules depend on running processes and are not predicted.
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
        public void NatOnAndOff()
        {
            Check(() => ks.SetNat(true), s => KillSwitch.PredictNat(s, true));
            Check(() => ks.SetNat(false), s => KillSwitch.PredictNat(s, false));
        }

        [Fact]
        public void SelectAndDeselect()
        {
            Check(() => ks.SelectInterface("happ-xray"), s => KillSwitch.PredictSelect(s, "happ-xray"));
            Check(() => ks.SelectInterface("Wi-Fi"), s => KillSwitch.PredictSelect(s, "Wi-Fi"));
            var remaining = new[] { "Wi-Fi" };
            Check(() => ks.DeselectInterface("happ-xray", remaining), s => KillSwitch.PredictDeselect(s, "happ-xray", remaining));
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
            ks.SetNat(true);
            Check(() => ks.ResetAll(), KillSwitch.PredictReset);
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
