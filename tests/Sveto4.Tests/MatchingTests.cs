using Xunit;

namespace Sveto4.Tests
{
    public class MatchingTests
    {
        [Theory]
        [InlineData("WAN Miniport (IP)", true)]
        [InlineData("Microsoft Teredo Tunneling Adapter", true)]
        [InlineData("Microsoft Wi-Fi Direct Virtual Adapter #2", true)]
        [InlineData("Happ Tunnel", false)]
        [InlineData("Killer(R) Wi-Fi 6E AX1675x", false)]
        [InlineData(null, false)]
        public void IsSystemAdapter(string description, bool expected) =>
            Assert.Equal(expected, KillSwitch.IsSystemAdapter(description));
    }
}
