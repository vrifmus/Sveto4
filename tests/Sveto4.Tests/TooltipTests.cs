using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class TooltipTests
    {
        private static List<LeakInfo> Leaks(int n) =>
            Enumerable.Range(0, n).Select(i => new LeakInfo("DNS", "r" + i)).ToList();

        [Fact]
        public void FullState()
        {
            var s = new KsState { Mode = KsMode.On, Lan = true, DisabledLeaks = Leaks(4) };
            s.Clients.Add(new ClientStatus(ClientProfiles.Happ, true, @"C:\Happ"));
            s.Interfaces.Add("Wi-Fi");
            s.Interfaces.Add("happ-xray");

            Assert.Equal(
                "Sveto4\nKill switch: ON\nLAN: ON\nWSL: OFF\nVPN clients: Happ\nBlock system leaks: ON (4)\nInterfaces: happ-xray, Wi-Fi",
                KillSwitch.FormatTooltip(s, 127));
        }

        [Fact]
        public void Off_NoInterfaces()
        {
            var s = new KsState { Mode = KsMode.Off };
            Assert.Equal(
                "Sveto4\nKill switch: OFF\nLAN: OFF\nWSL: OFF\nVPN clients: none\nBlock system leaks: ON\nInterfaces: none",
                KillSwitch.FormatTooltip(s, 127));
        }

        [Theory]
        [InlineData((int)KsMode.On, true, 2, 0, "ON, 2 open")]
        [InlineData((int)KsMode.On, true, 0, 4, "ON (4)")]
        [InlineData((int)KsMode.Off, true, 4, 0, "ON")]      // leaks do not matter while off
        [InlineData((int)KsMode.On, false, 4, 0, "OFF")]
        [InlineData((int)KsMode.Partial, true, 1, 3, "ON, 1 open")]
        public void LeakLine(int mode, bool block, int open, int disabled, string expected)
        {
            var s = new KsState { Mode = (KsMode)mode, BlockLeaks = block, Leaks = Leaks(open), DisabledLeaks = Leaks(disabled) };
            Assert.Contains("Block system leaks: " + expected + "\n", KillSwitch.FormatTooltip(s, 127));
        }

        [Theory]
        [InlineData((int)KsMode.Off, "\U0001F534 Sveto4\n")]
        [InlineData((int)KsMode.Partial, "\U0001F7E0 Sveto4\n")]
        [InlineData((int)KsMode.On, "⚪ Sveto4\n")] // on, no interfaces
        public void StatusCircle_MatchesIconColor(int mode, string start)
        {
            var s = new KsState { Mode = (KsMode)mode };
            Assert.StartsWith(start, KillSwitch.FormatTooltip(s, 127, KillSwitch.GetIconState(s, false)));
        }

        [Fact]
        public void StatusCircle_Connected()
        {
            var s = new KsState { Mode = KsMode.On, Adapters = { TestEnv.Adapter("Wi-Fi") } };
            s.Interfaces.Add("Wi-Fi");
            Assert.StartsWith("\U0001F7E2 Sveto4\n", KillSwitch.FormatTooltip(s, 127, KillSwitch.GetIconState(s, false)));
        }

        [Fact]
        public void StatusCircle_LongListStillFits()
        {
            var s = new KsState { Mode = KsMode.On };
            for (var i = 0; i < 10; i++) s.Interfaces.Add("Very long adapter name " + i);
            Assert.Equal(127, KillSwitch.FormatTooltip(s, 127, IconState.Disconnected).Length);
        }

        [Fact]
        public void Partial()
        {
            var s = new KsState { Mode = KsMode.Partial };
            Assert.Contains("Kill switch: PARTIAL\n", KillSwitch.FormatTooltip(s, 127));
        }

        [Fact]
        public void LongInterfaceList_IsShortenedToFit()
        {
            var s = new KsState { Mode = KsMode.On };
            for (var i = 0; i < 10; i++) s.Interfaces.Add("Very long adapter name " + i);

            var text = KillSwitch.FormatTooltip(s, 127);

            Assert.Equal(127, text.Length);
            Assert.EndsWith("…", text);
            Assert.StartsWith("Sveto4\nKill switch: ON\n", text);
        }

        [Fact]
        public void LegacyLimit_NeverExceeded()
        {
            var s = new KsState { Mode = KsMode.On };
            s.Interfaces.Add("happ-xray");
            Assert.True(KillSwitch.FormatTooltip(s, 63).Length <= 63);
        }
    }
}
