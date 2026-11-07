using System.Collections.Generic;
using Xunit;

namespace Sveto4.Tests
{
    public class MatchingTests
    {
        [Theory]
        [InlineData("happ-xray", "happ")]
        [InlineData("happ-sing-box", "happ")]
        [InlineData("Hiddify Tunnel", "hiddify")]
        [InlineData("Wi-Fi", null)]
        [InlineData("vEthernet (WSLCore)", null)]
        public void MatchApp(string iface, string expected) =>
            Assert.Equal(expected, KillSwitch.MatchApp(iface));

        [Theory]
        [InlineData("WAN Miniport (IP)", true)]
        [InlineData("Microsoft Teredo Tunneling Adapter", true)]
        [InlineData("Microsoft Wi-Fi Direct Virtual Adapter #2", true)]
        [InlineData("Happ Tunnel", false)]
        [InlineData("Killer(R) Wi-Fi 6E AX1675x", false)]
        [InlineData(null, false)]
        public void IsSystemAdapter(string description, bool expected) =>
            Assert.Equal(expected, KillSwitch.IsSystemAdapter(description));

        [Fact]
        public void CollectAppPaths_TakesClientAndItsChildren()
        {
            var processes = new List<ProcessEntry>
            {
                new ProcessEntry { Pid = 10, ParentPid = 1, Name = "Happ.exe", ExePath = @"C:\Happ\Happ.exe" },
                new ProcessEntry { Pid = 11, ParentPid = 1, Name = "happd.exe", ExePath = @"C:\Happ\happd.exe" },
                new ProcessEntry { Pid = 12, ParentPid = 11, Name = "xray.exe", ExePath = @"C:\Happ\core\xray.exe" },
                new ProcessEntry { Pid = 13, ParentPid = 99, Name = "chrome.exe", ExePath = @"C:\Chrome\chrome.exe" },
                new ProcessEntry { Pid = 14, ParentPid = 10, Name = "noaccess.exe", ExePath = null },
            };

            var paths = KillSwitch.CollectAppPaths(processes, "happ");

            Assert.Equal(3, paths.Count);
            Assert.Contains(@"C:\Happ\Happ.exe", paths);
            Assert.Contains(@"C:\Happ\happd.exe", paths);
            Assert.Contains(@"C:\Happ\core\xray.exe", paths);
        }

        [Fact]
        public void CollectAppPaths_NoClient_Empty() =>
            Assert.Empty(KillSwitch.CollectAppPaths(new[]
            {
                new ProcessEntry { Pid = 1, Name = "explorer.exe", ExePath = @"C:\Windows\explorer.exe" },
            }, "happ"));
    }
}
