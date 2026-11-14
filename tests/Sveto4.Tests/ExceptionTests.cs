using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class ExceptionTests
    {
        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeExceptionStore store = new FakeExceptionStore();

        private KillSwitch Create() => new KillSwitch(fw, TestEnv.Create(), new FakeStore(), exceptionStore: store);

        private static ExceptionEntry Entry(string addresses, string program = null,
                                            ExceptionProtocol protocol = ExceptionProtocol.Any, string ports = null) =>
            Exceptions.Create("Test", addresses, program, protocol, ports, new string[0]);

        // ---------- Validation ----------

        [Theory]
        [InlineData("203.0.113.5", "203.0.113.5")]
        [InlineData(" 203.0.113.5 , 198.51.100.7 ", "203.0.113.5,198.51.100.7")]
        [InlineData("203.0.113.5 203.0.113.5", "203.0.113.5")]
        [InlineData("203.0.113.5/32", "203.0.113.5")]
        [InlineData("198.51.100.77/24", "198.51.100.0/255.255.255.0")]
        [InlineData("10.1.2.3/8", "10.0.0.0/255.0.0.0")]
        [InlineData("198.51.100.0/255.255.255.0", "198.51.100.0/255.255.255.0")]
        [InlineData("2001:db8::1", "2001:db8::1")]
        [InlineData("2001:db8:1:2::5/64", "2001:db8:1:2::/64")]
        public void Addresses_AreNormalized(string input, string expected) =>
            Assert.Equal(expected, Exceptions.NormalizeAddresses(input));

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("example.com")]
        [InlineData("1")]
        [InlineData("256.1.1.1")]
        [InlineData("1.2.3")]
        [InlineData("0.0.0.0")]
        [InlineData("0.0.0.0/0")]
        [InlineData("10.0.0.0/7")]
        [InlineData("10.0.0.0/33")]
        [InlineData("10.0.0.0/x")]
        [InlineData("10.0.0.0/255.0.255.0")]
        [InlineData("10.0.0.0/254.0.0.0")]
        [InlineData("::")]
        [InlineData("::/0")]
        [InlineData("2001::/15")]
        [InlineData("fe80::1%5")]
        [InlineData("LocalSubnet")]
        [InlineData("*")]
        [InlineData("10.0.0.1-10.0.0.9")]
        public void Addresses_InvalidOrTooBroad_AreRefused(string input) =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.NormalizeAddresses(input));

        [Theory]
        [InlineData("22", "22")]
        [InlineData("22, 2222", "22,2222")]
        [InlineData("8000-8100", "8000-8100")]
        [InlineData("443-443", "443")]
        [InlineData("", null)]
        public void Ports_AreNormalized(string input, string expected) =>
            Assert.Equal(expected, Exceptions.NormalizePorts(input, ExceptionProtocol.Tcp));

        [Theory]
        [InlineData("0")]
        [InlineData("65536")]
        [InlineData("22-")]
        [InlineData("100-50")]
        [InlineData("1-2-3")]
        [InlineData("ssh")]
        public void Ports_Invalid_AreRefused(string input) =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.NormalizePorts(input, ExceptionProtocol.Udp));

        [Fact]
        public void Ports_RequireTcpOrUdp() =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.NormalizePorts("22", ExceptionProtocol.Any));

        [Theory]
        [InlineData(@"C:\Windows\System32\OpenSSH\ssh.exe", @"C:\Windows\System32\OpenSSH\ssh.exe")]
        [InlineData(@"""C:\Tools\app.exe""", @"C:\Tools\app.exe")]
        [InlineData(@"%SystemRoot%\System32\OpenSSH\ssh.exe", @"%SystemRoot%\System32\OpenSSH\ssh.exe")]
        [InlineData("", null)]
        public void Program_IsNormalized(string input, string expected) =>
            Assert.Equal(expected, Exceptions.NormalizeProgram(input));

        [Theory]
        [InlineData("ssh.exe")]
        [InlineData(@"C:\Tools\app.bat")]
        [InlineData(@"C:\Tools\*.exe")]
        [InlineData(@"\\server\share\app.exe")]
        public void Program_Invalid_IsRefused(string input) =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.NormalizeProgram(input));

        [Fact]
        public void Name_MustBeUnique()
        {
            var e = Assert.Throws<ExceptionValidationError>(() =>
                Exceptions.Create("ssh", "203.0.113.5", null, ExceptionProtocol.Any, null, new[] { "SSH" }));
            Assert.Contains("already exists", e.Message);
        }

        [Theory]
        [InlineData("")]
        [InlineData("a\nb")]
        [InlineData("12345678901234567890123456789012345678901")]
        public void Name_Invalid_IsRefused(string name) =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.ValidateName(name));

        [Fact]
        public void Describe()
        {
            Assert.Equal("203.0.113.5 TCP 22", Exceptions.Describe(Entry("203.0.113.5", protocol: ExceptionProtocol.Tcp, ports: "22")));
            Assert.Equal("203.0.113.5, 198.51.100.7", Exceptions.Describe(Entry("203.0.113.5,198.51.100.7")));
        }

        // ---------- File format ----------

        [Fact]
        public void Serialize_ThenParse_RoundTrips()
        {
            var entries = new[]
            {
                Exceptions.Create("SSH to VPS", "203.0.113.5", @"C:\Windows\System32\OpenSSH\ssh.exe", ExceptionProtocol.Tcp, "22", new string[0]),
                Exceptions.Create("Lab", "198.51.100.0/24", null, ExceptionProtocol.Any, null, new string[0]),
            };
            var parsed = Exceptions.Parse(Exceptions.Serialize(entries));

            Assert.Equal(2, parsed.Count);
            Assert.Equal("SSH to VPS", parsed[0].Name);
            Assert.Equal("203.0.113.5", parsed[0].Addresses);
            Assert.Equal(@"C:\Windows\System32\OpenSSH\ssh.exe", parsed[0].Program);
            Assert.Equal(ExceptionProtocol.Tcp, parsed[0].Protocol);
            Assert.Equal("22", parsed[0].Ports);
            Assert.Null(parsed[1].Program);
            Assert.Null(parsed[1].Ports);
            Assert.Equal("198.51.100.0/255.255.255.0", parsed[1].Addresses);
        }

        [Fact]
        public void Parse_SkipsInvalidAndDuplicateEntries()
        {
            var json = @"{""exceptions"":[
                {""name"":""ok"",""addresses"":""203.0.113.5""},
                {""name"":""broad"",""addresses"":""0.0.0.0/0""},
                {""name"":""OK"",""addresses"":""203.0.113.6""},
                {""name"":""proto"",""addresses"":""203.0.113.7"",""protocol"":""icmp""}
            ]}";
            var skipped = 0;
            var parsed = Exceptions.Parse(json, _ => skipped++);

            Assert.Equal(new[] { "ok" }, parsed.Select(p => p.Name).ToArray());
            Assert.Equal(3, skipped);
        }

        [Fact]
        public void Parse_InvalidJson_Throws() =>
            Assert.Throws<ExceptionValidationError>(() => Exceptions.Parse("{not json"));

        [Fact]
        public void Parse_Empty_IsEmpty() => Assert.Empty(Exceptions.Parse(""));

        // ---------- Actions ----------

        [Fact]
        public void Add_StoresAndCreatesRule()
        {
            Create().AddException("SSH", "203.0.113.5", @"C:\Windows\System32\OpenSSH\ssh.exe", ExceptionProtocol.Tcp, "22");

            Assert.Equal("SSH", Assert.Single(store.Entries).Name);
            var rule = fw.Find("KS-Exc-SSH");
            Assert.NotNull(rule);
            Assert.True(rule.Enabled);
            Assert.Equal("203.0.113.5", rule.RemoteAddresses);
            Assert.Equal(@"C:\Windows\System32\OpenSSH\ssh.exe", rule.ApplicationName);
            Assert.Equal(6, rule.Protocol);
            Assert.Equal("22", rule.RemotePorts);
            Assert.Null(rule.Interface);
        }

        [Fact]
        public void Add_AnyProgramAnyProtocol()
        {
            Create().AddException("Lab", "198.51.100.0/24", "", ExceptionProtocol.Any, "");

            var rule = fw.Find("KS-Exc-Lab");
            Assert.Null(rule.ApplicationName);
            Assert.Equal(256, rule.Protocol);
            Assert.Null(rule.RemotePorts);
        }

        [Fact]
        public void Add_Duplicate_Throws_AndChangesNothing()
        {
            var ks = Create();
            ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Any, null);
            Assert.Throws<ExceptionValidationError>(() => ks.AddException("ssh", "203.0.113.6", null, ExceptionProtocol.Any, null));
            Assert.Single(store.Entries);
            Assert.Single(fw.Rules);
        }

        [Fact]
        public void Disable_RemovesRule_KeepsDefinition()
        {
            var ks = Create();
            var e = ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Any, null);
            ks.SetExceptionEnabled(e, false);

            Assert.Empty(fw.Rules);
            Assert.Single(store.Entries);
        }

        [Fact]
        public void Remove_RemovesRuleAndDefinition()
        {
            var ks = Create();
            var e = ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Any, null);
            ks.AddException("Other", "203.0.113.6", null, ExceptionProtocol.Any, null);
            ks.RemoveException(e);

            Assert.Equal(new[] { "KS-Exc-Other" }, fw.Rules.Select(r => r.Name).ToArray());
            Assert.Equal("Other", Assert.Single(store.Entries).Name);
        }

        [Fact]
        public void ResetAll_RemovesRules_KeepsDefinitions()
        {
            var ks = Create();
            ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Any, null);
            ks.ResetAll();

            Assert.Empty(fw.Rules);
            Assert.Single(store.Entries);

            var s = new KsState();
            ks.ReadRules(s);
            Assert.False(Assert.Single(s.Exceptions).Enabled);
        }

        [Fact]
        public void Read_ShowsEnabledState()
        {
            var ks = Create();
            ks.AddException("SSH", "203.0.113.5", null, ExceptionProtocol.Any, null);
            var s = new KsState();
            ks.ReadRules(s);

            var x = Assert.Single(s.Exceptions);
            Assert.Equal("SSH", x.Entry.Name);
            Assert.True(x.Enabled);
            Assert.Empty(s.Interfaces); // not mistaken for an interface rule
        }

        [Fact]
        public void OwnRule_IsNeverALeak()
        {
            // An exception for svchost on UDP 53 looks like the system DNS rule, but must not be disabled.
            var rule = LeakTests.Dns();
            rule.Name = "KS-Exc-DNS";
            Assert.Null(KillSwitch.ClassifyLeak(rule));
        }
    }
}
