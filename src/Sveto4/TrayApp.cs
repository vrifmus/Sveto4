using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Sveto4
{
    /// <summary>Tray icon, native context menu, polling and icon animation.</summary>
    internal sealed class TrayApp : ApplicationContext
    {
        private static readonly Color Red = Color.FromArgb(239, 67, 73);
        private static readonly Color Blue = Color.FromArgb(0, 122, 204);
        private static readonly Color Gray = Color.FromArgb(73, 73, 73);
        private static readonly Color Green = Color.FromArgb(149, 222, 85);
        private static readonly Color Yellow = Color.FromArgb(255, 209, 79);
        private static readonly Color Orange = Color.FromArgb(255, 140, 0);

        private const int PollIntervalMs = 3000;
        private const int FullRefreshEveryTicks = 10; // re-read rules every ~30 s
        private const int AnimSteps = 8;

        private readonly NotifyIcon tray = new NotifyIcon();
        private readonly ContextMenu menu = new ContextMenu();
        private readonly MenuItem miPartial = new MenuItem { Enabled = false, Visible = false };
        private readonly MenuItem miToggle = new MenuItem("Turn ON");
        private readonly MenuItem miOff = new MenuItem("Turn OFF (all profiles)") { Visible = false };
        private readonly MenuItem miLan = new MenuItem("Allow LAN");
        private readonly MenuItem miNat = new MenuItem("Allow NAT (WSL)");
        private readonly MenuItem miInterfaces = new MenuItem("Interfaces");
        private readonly MenuItem miRules = new MenuItem("Rules");
        private readonly System.Windows.Forms.Timer pollTimer = new System.Windows.Forms.Timer { Interval = PollIntervalMs };
        private readonly System.Windows.Forms.Timer animTimer = new System.Windows.Forms.Timer { Interval = 15 };
        private readonly Icons icons = new Icons();
        private readonly SynchronizationContext ui;

        private KsState state = new KsState();
        private bool busy;
        private bool polling;
        private bool forceFullRefresh;
        private int generation;
        private int tick;

        private Color currentColor = Yellow;
        private Color animFrom;
        private Color animTo = Yellow;
        private int animStep;
        private Icon ownedIcon;

        public TrayApp(bool autoEnable)
        {
            ui = SynchronizationContext.Current;

            miToggle.Click += (s, e) => OnToggle();
            miOff.Click += (s, e) => Run("Turn OFF", () => KillSwitch.SetMode(false));
            miLan.Click += (s, e) => { var on = !state.Lan; Run("LAN " + on, () => KillSwitch.SetLan(on)); };
            miNat.Click += (s, e) => { var on = !state.Nat; Run("NAT " + on, () => KillSwitch.SetNat(on)); };

            menu.MenuItems.AddRange(new[]
            {
                miPartial,
                miToggle,
                miOff,
                new MenuItem("-"),
                miLan,
                miNat,
                miInterfaces,
                miRules,
                new MenuItem("-"),
                new MenuItem("Reset ALL", (s, e) => Run("Reset ALL", KillSwitch.ResetAll)),
                new MenuItem("-"),
                new MenuItem("Exit", (s, e) => ExitApp()),
            });
            // Menu content is built right before it is shown (the tray menu has no reliable "closed" event).
            menu.Popup += (s, e) => UpdateMenu();

            tray.Icon = icons.Get(Yellow);
            tray.Text = "Sveto4: starting...";
            tray.ContextMenu = menu;
            tray.Visible = true;

            animTimer.Tick += (s, e) => OnAnimTick();
            pollTimer.Tick += (s, e) => OnPoll();
            SystemEvents.PowerModeChanged += OnPowerModeChanged;

            Start(autoEnable);
        }

        // ---------- Lifecycle ----------

        private async void Start(bool autoEnable)
        {
            busy = true;
            var s = await ReadStateAsync(full: true, previous: state);
            if (s != null) state = s;
            busy = false;
            ApplyState();

            if (autoEnable && state.Mode != KsMode.On)
                Run("Auto-enable", () => KillSwitch.SetMode(true));

            pollTimer.Start();
        }

        private void ExitApp()
        {
            // The firewall state is intentionally left as is: the kill switch must survive app exit.
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            pollTimer.Stop();
            animTimer.Stop();
            tray.Visible = false;
            tray.Dispose();
            ownedIcon?.Dispose();
            icons.Dispose();
            ExitThread();
        }

        private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
        {
            if (e.Mode != PowerModes.Resume) return;
            // Raised on a system thread; marshal to the UI thread.
            ui.Post(_ =>
            {
                Log.Info("Resumed from sleep");
                forceFullRefresh = true;
            }, null);
        }

        // ---------- Actions and refresh ----------

        private void OnToggle()
        {
            if (state.Mode == KsMode.On) Run("Turn OFF", () => KillSwitch.SetMode(false));
            else Run("Turn ON", () => KillSwitch.SetMode(true));
        }

        private void OnInterfaceClick(string iface)
        {
            if (state.Interfaces.Contains(iface))
            {
                var remaining = state.Interfaces.Where(i => !string.Equals(i, iface, StringComparison.OrdinalIgnoreCase)).ToList();
                Run("Deselect " + iface, () => KillSwitch.DeselectInterface(iface, remaining));
            }
            else
            {
                Run("Select " + iface, () => KillSwitch.SelectInterface(iface));
            }
        }

        /// <summary>Runs a firewall action in the background, then re-reads the full state.</summary>
        private async void Run(string what, Action action)
        {
            if (busy) return;
            busy = true;
            generation++;
            AnimateTo(Yellow);

            try
            {
                await Task.Run(action);
                Log.Info(what);
            }
            catch (Exception ex)
            {
                Log.Error(ex, what);
            }

            var s = await ReadStateAsync(full: true, previous: state);
            if (s != null) state = s;
            busy = false;
            ApplyState();
        }

        private async void OnPoll()
        {
            if (busy || polling) return;
            polling = true;
            try
            {
                tick++;
                var full = forceFullRefresh || !state.RulesLoaded || tick % FullRefreshEveryTicks == 0;
                forceFullRefresh = false;
                var gen = generation;
                var s = await ReadStateAsync(full, state);
                // Drop the result if a user action started meanwhile.
                if (s != null && gen == generation && !busy) state = s;
            }
            finally
            {
                polling = false;
            }
            if (!busy) ApplyState();
        }

        /// <summary>Reads the state off the UI thread. Returns null on failure (e.g. right after wake-up).</summary>
        private static async Task<KsState> ReadStateAsync(bool full, KsState previous)
        {
            try
            {
                return await Task.Run(() =>
                {
                    var s = new KsState();
                    KillSwitch.ReadProfiles(s);
                    if (full) KillSwitch.ReadRules(s);
                    else s.CopyRulesFrom(previous);
                    KillSwitch.ReadAdapters(s);
                    return s;
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "read state");
                return null;
            }
        }

        // ---------- UI ----------

        private void ApplyState()
        {
            if (busy) return;
            UpdateTooltip();
            AnimateTo(TargetColor());
        }

        private void UpdateMenu()
        {
            var on = state.Mode != KsMode.Off;
            miPartial.Visible = state.Mode == KsMode.Partial;
            miPartial.Text = "⚠ Partially on. Not blocked: " + state.NotBlocked;
            miToggle.Text = state.Mode == KsMode.On ? "Turn OFF"
                          : state.Mode == KsMode.Partial ? "Turn ON (all profiles)"
                          : "Turn ON";
            miOff.Visible = state.Mode == KsMode.Partial;

            miLan.Checked = state.Lan;
            miLan.Enabled = on;
            miNat.Checked = state.Nat;
            miNat.Enabled = on;
            miInterfaces.Enabled = on;
            miRules.Enabled = on;

            BuildInterfacesMenu();
            BuildRulesMenu();
        }

        private void BuildInterfacesMenu()
        {
            var selected = state.Interfaces;
            miInterfaces.Text = selected.Count > 0 ? $"Interfaces ({selected.Count})" : "Interfaces";
            miInterfaces.MenuItems.Clear();

            miInterfaces.MenuItems.Add(new MenuItem("None", (s, e) => Run("Clear interfaces", KillSwitch.ClearInterfaces))
            {
                Checked = selected.Count == 0,
            });
            miInterfaces.MenuItems.Add(new MenuItem("-"));

            var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var a in state.Adapters.Where(a => a.IsUp && !a.IsSystem)) names.Add(a.Name);
            foreach (var name in selected) names.Add(name);

            foreach (var name in names)
            {
                var iface = name;
                miInterfaces.MenuItems.Add(new MenuItem(iface, (s, e) => OnInterfaceClick(iface))
                {
                    Checked = selected.Contains(iface),
                });
            }
        }

        private void BuildRulesMenu()
        {
            miRules.MenuItems.Clear();
            if (state.Rules.Count == 0)
            {
                miRules.Text = "Rules";
                miRules.MenuItems.Add(new MenuItem("No active rules") { Enabled = false });
                return;
            }

            miRules.Text = $"Rules ({state.Rules.Count})";
            foreach (var rule in state.Rules.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
                miRules.MenuItems.Add(new MenuItem(rule.Name + (rule.Enabled ? "" : " [Disabled]")) { Enabled = false });
        }

        private void UpdateTooltip()
        {
            var mode = state.Mode == KsMode.On ? "ON" : state.Mode == KsMode.Partial ? "PARTIAL" : "OFF";
            var text = $"Kill switch: {mode}\nLAN: {(state.Lan ? "ON" : "OFF")}  NAT: {(state.Nat ? "ON" : "OFF")}\nInterfaces: {state.Interfaces.Count}";
            tray.Text = text.Length > 63 ? text.Substring(0, 63) : text; // NotifyIcon limit
        }

        private Color TargetColor()
        {
            if (busy) return Yellow;
            if (state.Mode == KsMode.Off) return Red;
            if (state.Mode == KsMode.Partial) return Orange;
            if (state.Interfaces.Count == 0) return Gray;

            var present = state.Adapters.Where(a => state.Interfaces.Contains(a.Name)).ToList();
            if (present.Count == 0) return Blue;
            return present.Any(a => a.IsUp) ? Green : Gray;
        }

        // ---------- Icon animation (timer-based, no DoEvents) ----------

        private void AnimateTo(Color target)
        {
            if (animTimer.Enabled ? target.ToArgb() == animTo.ToArgb() : target.ToArgb() == currentColor.ToArgb())
                return;
            animFrom = currentColor;
            animTo = target;
            animStep = 0;
            animTimer.Start();
        }

        private void OnAnimTick()
        {
            animStep++;
            if (animStep >= AnimSteps)
            {
                animTimer.Stop();
                currentColor = animTo;
                SetIcon(icons.Get(animTo), owned: false);
                return;
            }

            var t = animStep / (float)AnimSteps;
            currentColor = Color.FromArgb(
                (int)Math.Round(animFrom.R + (animTo.R - animFrom.R) * t),
                (int)Math.Round(animFrom.G + (animTo.G - animFrom.G) * t),
                (int)Math.Round(animFrom.B + (animTo.B - animFrom.B) * t));
            SetIcon(Icons.Create(currentColor), owned: true);
        }

        private void SetIcon(Icon icon, bool owned)
        {
            var previous = ownedIcon;
            tray.Icon = icon;
            ownedIcon = owned ? icon : null;
            previous?.Dispose();
        }
    }
}
