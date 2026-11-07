using Xunit;

namespace Sveto4.Tests
{
    public class MatchingTests
    {
        [Theory]
        [InlineData("Local Area Connection* 7", "WAN Miniport (IP)", true)]
        [InlineData("Teredo", "Microsoft Teredo Tunneling Adapter", true)]
        [InlineData("Local Area Connection* 10", "Microsoft Wi-Fi Direct Virtual Adapter #2", true)]
        [InlineData("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter", true)]
        [InlineData("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", true)]
        [InlineData("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", true)]
        [InlineData("vEthernet (External)", "Hyper-V Virtual Ethernet Adapter", false)] // host's real connection
        [InlineData("happ-xray", "Happ Tunnel", false)]
        [InlineData("Wi-Fi", "Killer(R) Wi-Fi 6E AX1675x", false)]
        [InlineData(null, null, false)]
        public void IsSystemAdapter(string name, string description, bool expected) =>
            Assert.Equal(expected, KillSwitch.IsSystemAdapter(name, description));

        [Fact]
        public void NewAdapters_ReportedOnce()
        {
            var seen = new System.Collections.Generic.HashSet<string>();
            Assert.Single(KillSwitch.NewAdapters(seen, new[] { TestEnv.Adapter("Wi-Fi") }));
            Assert.Empty(KillSwitch.NewAdapters(seen, new[] { TestEnv.Adapter("Wi-Fi") }));
            Assert.Single(KillSwitch.NewAdapters(seen, new[] { TestEnv.Adapter("Wi-Fi"), TestEnv.Adapter("happ-sing-box", "Happ Tunnel") }));
        }

        [Fact]
        public void DescribeAdapter_ListsCodePointsOfGarbledName()
        {
            var text = KillSwitch.DescribeAdapter(new AdapterInfo("长诲", "Happ Tunnel", true, false));
            Assert.Equal("'长诲' [U+957F U+8BF2], description 'Happ Tunnel', up", text);
        }
    }
}
