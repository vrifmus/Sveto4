using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class LeakTests
    {
        // Real property values of built-in Windows rules (names are localized, properties are not).
        internal static RuleProps Dns(string name = "Core Networking - DNS (UDP-Out)") => new RuleProps
        {
            Name = name, Enabled = true, ApplicationName = @"%SystemRoot%\system32\svchost.exe", ServiceName = "dnscache",
            Protocol = 17, RemotePorts = "53",
        };

        internal static RuleProps Ipv6 => new RuleProps
        {
            Name = "Core Networking - IPv6 (IPv6-Out)", Enabled = true, ApplicationName = "System", Protocol = 41, RemotePorts = "*",
        };

        internal static RuleProps Teredo => new RuleProps
        {
            Name = "Core Networking - Teredo (UDP-Out)", Enabled = true, ApplicationName = @"%SystemRoot%\system32\svchost.exe",
            ServiceName = "iphlpsvc", Protocol = 17, RemotePorts = "*",
        };

        internal static RuleProps IpHttps => new RuleProps
        {
            Name = "Core Networking - IPHTTPS (TCP-Out)", Enabled = true, ApplicationName = @"%SystemRoot%\system32\svchost.exe",
            ServiceName = "iphlpsvc", Protocol = 6, RemotePorts = "IPHTTPSOut",
        };

        [Fact]
        public void RecognizesAllFourCoreNetworkingRules()
        {
            var leaks = KillSwitch.FindLeaks(new[] { Dns(), Ipv6, Teredo, IpHttps });

            Assert.Equal(
                new[] { KillSwitch.LeakDns, KillSwitch.LeakIpv6Tunnel, KillSwitch.LeakTeredo, KillSwitch.LeakIpHttps },
                leaks.Select(l => l.Kind).ToArray());
        }

        [Fact]
        public void MatchesByPropertiesNotName()
        {
            var leak = Assert.Single(KillSwitch.FindLeaks(new[] { Dns("Основы сетей — DNS (UDP — исходящий)") }));
            Assert.Equal(KillSwitch.LeakDns, leak.Kind);
            Assert.Equal("Основы сетей — DNS (UDP — исходящий)", leak.RuleName);
        }

        [Fact]
        public void ExpandedSvchostPath_IsRecognized()
        {
            var rule = Dns();
            rule.ApplicationName = @"C:\WINDOWS\system32\svchost.exe";
            Assert.Single(KillSwitch.FindLeaks(new[] { rule }));
        }

        [Fact]
        public void IgnoresUnrelatedRules()
        {
            var rules = new List<RuleProps>
            {
                // Same service, but not DNS port.
                new RuleProps { Name = "x", ApplicationName = @"%SystemRoot%\system32\svchost.exe", ServiceName = "dnscache", Protocol = 17, RemotePorts = "5353" },
                // DHCP client.
                new RuleProps { Name = "Core Networking - DHCP-Out", ApplicationName = @"%SystemRoot%\system32\svchost.exe", ServiceName = "dhcp", Protocol = 17, RemotePorts = "67" },
                // Regular app.
                new RuleProps { Name = "Some app", ApplicationName = @"C:\App\app.exe", Protocol = 256, RemotePorts = "*" },
                // Our own rule.
                new RuleProps { Name = "KS-App-happ-xray", ApplicationName = @"C:\Happ\core\xray.exe", Protocol = 256, RemotePorts = "*" },
            };

            Assert.Empty(KillSwitch.FindLeaks(rules));
        }

        [Fact]
        public void DnsPortInList_IsRecognized()
        {
            var rule = Dns();
            rule.RemotePorts = "53, 853";
            Assert.Single(KillSwitch.FindLeaks(new[] { rule }));
        }

        [Fact]
        public void ReadRules_FillsLeaks()
        {
            var fw = new FakeFirewall();
            fw.SystemRules.Add(Dns());
            var ks = new KillSwitch(fw, () => new ProcessEntry[0], p => true, new FakeStore());

            var s = new KsState();
            ks.ReadRules(s);

            Assert.Equal(KillSwitch.LeakDns, Assert.Single(s.Leaks).Kind);
        }
    }
}
