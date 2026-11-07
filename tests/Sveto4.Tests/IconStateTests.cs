using System.Collections.Generic;
using Xunit;

namespace Sveto4.Tests
{
    public class IconStateTests
    {
        private static KsState On(string[] selected, params AdapterInfo[] adapters)
        {
            var s = new KsState { Mode = KsMode.On, Adapters = new List<AdapterInfo>(adapters) };
            foreach (var i in selected) s.Interfaces.Add(i);
            return s;
        }

        [Fact]
        public void Busy_WinsOverEverything() =>
            Assert.Equal(IconState.Busy, KillSwitch.GetIconState(new KsState { Mode = KsMode.On }, busy: true));

        [Fact]
        public void Off() =>
            Assert.Equal(IconState.Off, KillSwitch.GetIconState(new KsState { Mode = KsMode.Off }, false));

        [Fact]
        public void Partial() =>
            Assert.Equal(IconState.Partial, KillSwitch.GetIconState(new KsState { Mode = KsMode.Partial }, false));

        [Fact]
        public void OnWithoutInterfaces() =>
            Assert.Equal(IconState.NoInterfaces, KillSwitch.GetIconState(On(new string[0]), false));

        [Fact]
        public void SelectedAdapterMissing() =>
            Assert.Equal(IconState.AdapterMissing,
                KillSwitch.GetIconState(On(new[] { "happ-xray" }, new AdapterInfo("Wi-Fi", "", true, false)), false));

        [Fact]
        public void SelectedAdapterUp() =>
            Assert.Equal(IconState.Connected,
                KillSwitch.GetIconState(On(new[] { "happ-xray" }, new AdapterInfo("happ-xray", "Happ Tunnel", true, false)), false));

        [Fact]
        public void SelectedAdapterDown() =>
            Assert.Equal(IconState.Disconnected,
                KillSwitch.GetIconState(On(new[] { "Ethernet" }, new AdapterInfo("Ethernet", "", false, false)), false));

        [Fact]
        public void AnySelectedAdapterUp_IsConnected() =>
            Assert.Equal(IconState.Connected,
                KillSwitch.GetIconState(On(new[] { "Ethernet", "Wi-Fi" },
                    new AdapterInfo("Ethernet", "", false, false),
                    new AdapterInfo("Wi-Fi", "", true, false)), false));
    }
}
