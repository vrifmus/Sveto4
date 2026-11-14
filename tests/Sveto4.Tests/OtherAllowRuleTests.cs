using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class OtherAllowRuleTests
    {
        private static RuleProps Rule(string name, string app = null, string group = null) =>
            new RuleProps { Name = name, Enabled = true, IsOutboundAllow = true, ApplicationName = app, Grouping = group, Protocol = 256 };

        [Fact]
        public void ProgramRules_AreFound_BuiltInOwnAndLeaksAreNot()
        {
            var rules = new[]
            {
                Rule("Logi Agent", @"C:\Program Files\LogiOptionsPlus\logioptionsplus_agent.exe"),
                Rule("Xbox", group: "Xbox"),
                Rule("Core Networking - DHCP", @"%SystemRoot%\system32\svchost.exe", "@FirewallAPI.dll,-25000"),
                Rule("KS-App-happ-xray", @"C:\Program Files\FlyFrogLLC\Happ\core\xray.exe"),
                LeakTests.Dns(),
            };

            Assert.Equal(new[] { "Logi Agent", "Xbox" },
                         KillSwitch.FindOtherAllowRules(rules).Select(r => r.Name).ToArray());
        }

        [Fact]
        public void SameName_IsMerged_WithDistinctPrograms()
        {
            var rules = new[]
            {
                Rule("Claude", group: "Claude"),
                Rule("Claude", @"C:\Apps\Claude\Claude.exe", "{78E1CD88-49E3-476E-B926-580E596AD309}"),
                Rule("claude", @"C:\Apps\Claude\cowork-svc.exe"),
                Rule("Claude", @"C:\Apps\Claude\claude.exe"),
            };

            var r = Assert.Single(KillSwitch.FindOtherAllowRules(rules));
            Assert.Equal(new[] { "Claude.exe", "cowork-svc.exe" }, r.Programs.ToArray());
        }

        [Fact]
        public void UnresolvedStoreName_ShowsExe()
        {
            var rules = new[] { Rule("ms-resource:ProductPkgDisplayName", @"C:\Windows\SystemApps\X\WindowsBackupClient.exe") };
            Assert.Equal("WindowsBackupClient.exe", Assert.Single(KillSwitch.FindOtherAllowRules(rules)).Name);
        }

        [Fact]
        public void ReadRules_FillsOtherAllowRules()
        {
            var fw = new FakeFirewall();
            fw.SystemRules.Add(Rule("Logi Agent", @"C:\Logi\agent.exe"));
            var ks = new KillSwitch(fw, TestEnv.Create(), new FakeStore(), new FakeHyperV());
            var s = new KsState();
            ks.ReadRules(s);

            Assert.Equal("Logi Agent", Assert.Single(s.OtherAllowRules).Name);
        }
    }
}
