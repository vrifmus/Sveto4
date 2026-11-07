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
    }
}
