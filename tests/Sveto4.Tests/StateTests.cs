using System.Collections.Generic;
using Xunit;

namespace Sveto4.Tests
{
    public class StateTests
    {
        private static KsState Profiles(params ProfileStatus[] profiles)
        {
            var s = new KsState();
            KillSwitch.ApplyProfiles(s, profiles);
            return s;
        }

        [Fact]
        public void AllProfilesBlocked_IsOn()
        {
            var s = Profiles(new ProfileStatus("Domain", true, true), new ProfileStatus("Private", true, true), new ProfileStatus("Public", true, true));
            Assert.Equal(KsMode.On, s.Mode);
            Assert.Equal("", s.NotBlocked);
        }

        [Fact]
        public void NoProfileBlocked_IsOff()
        {
            var s = Profiles(new ProfileStatus("Domain", true, false), new ProfileStatus("Private", true, false), new ProfileStatus("Public", true, false));
            Assert.Equal(KsMode.Off, s.Mode);
        }

        [Fact]
        public void MixedProfiles_IsPartial_AndListsOpenOnes()
        {
            var s = Profiles(new ProfileStatus("Domain", true, true), new ProfileStatus("Private", true, false), new ProfileStatus("Public", true, true));
            Assert.Equal(KsMode.Partial, s.Mode);
            Assert.Equal("Private", s.NotBlocked);
        }

        [Fact]
        public void DisabledFirewall_CountsAsNotBlocked()
        {
            // Outbound is "Block", but the firewall itself is off for Private: traffic flows.
            var s = Profiles(new ProfileStatus("Domain", true, true), new ProfileStatus("Private", false, true), new ProfileStatus("Public", true, true));
            Assert.Equal(KsMode.Partial, s.Mode);
            Assert.Equal("Private (firewall disabled)", s.NotBlocked);
        }

        [Fact]
        public void ApplyRules_DerivesInterfacesLanWsl()
        {
            var s = new KsState();
            KillSwitch.ApplyRules(s, new List<RuleInfo>
            {
                new RuleInfo("KS-Allow-Wi-Fi", true),
                new RuleInfo("KS-Allow-happ-xray", true),
                new RuleInfo("KS-Allow-Ethernet", false),
                new RuleInfo("KS-LAN-Allow-10.0.0.0/8", true),
                new RuleInfo("KS-WSL-Allow", false),
                new RuleInfo("KS-App-happ-xray", true),
            });

            Assert.True(s.RulesLoaded);
            Assert.Equal(new HashSet<string> { "Wi-Fi", "happ-xray" }, s.Interfaces);
            Assert.Contains("WI-FI", s.Interfaces); // case-insensitive, like interface aliases
            Assert.True(s.Lan);
            Assert.False(s.Wsl);
        }

        [Fact]
        public void ApplyRules_Empty_AllOff()
        {
            var s = new KsState();
            KillSwitch.ApplyRules(s, new List<RuleInfo>());
            Assert.Empty(s.Interfaces);
            Assert.False(s.Lan);
            Assert.False(s.Wsl);
        }
    }
}
