using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
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
        /// <summary>Warning sign, right-aligned: native menus align text after a tab to the right edge.</summary>
        private const string Warn = "\t⚠";
        private const int ShellTooltipMax = 127;  // NOTIFYICONDATA.szTip is 128 chars incl. terminator
        private const int LegacyTooltipMax = 63;  // NotifyIcon.Text limit in .NET Framework

        private readonly NotifyIcon tray = new NotifyIcon();
        private readonly ContextMenu menu = new ContextMenu();
        private readonly MenuItem miPartial = new MenuItem { Enabled = false, Visible = false };
        private readonly MenuItem miToggle = new MenuItem("Turn ON");
        private readonly MenuItem miOff = new MenuItem("Turn OFF (all profiles)") { Visible = false };
        private readonly MenuItem miLeaks = new MenuItem { Visible = false };
        private readonly MenuItem miLan = new MenuItem("Allow LAN");
        private readonly MenuItem miWsl = new MenuItem("Allow WSL");
        private readonly MenuItem miBlockLeaks = new MenuItem("Block system leaks");
        private readonly MenuItem miClients = new MenuItem("VPN clients");
        private readonly MenuItem miInterfaces = new MenuItem("Interfaces");
        private readonly MenuItem miRules = new MenuItem("Rules");
        private readonly MenuItem miAutostart = new MenuItem("Start with Windows");
        private readonly Autostart autostart = Autostart.CreateDefault();
        private AutostartStatus autostartStatus = AutostartStatus.Unknown;
        private bool autostartBusy;
        private readonly System.Windows.Forms.Timer pollTimer = new System.Windows.Forms.Timer { Interval = PollIntervalMs };
        private readonly System.Windows.Forms.Timer animTimer = new System.Windows.Forms.Timer { Interval = 15 };
        private readonly Icons icons = new Icons();
        private readonly KillSwitch ks = KillSwitch.CreateDefault();
        private readonly SynchronizationContext ui;

        private KsState state = new KsState();
        private bool busy;
        private bool polling;
        private bool forceFullRefresh;
        private int generation;
        private int tick;
        private DateTime lastReconcile = DateTime.MinValue;
        private DateTime lastMigration = DateTime.MinValue;
        private DateTime lastLanSync = DateTime.MinValue;
        private DateTime lastSync = DateTime.MinValue;
        private string lastSyncSignature;
        private readonly System.Windows.Forms.Timer quickPollTimer = new System.Windows.Forms.Timer { Interval = 300 };
        private string lastTooltip;

        private Color currentColor = Yellow;
        private Color animFrom;
        private Color animTo = Yellow;
        private int animStep;
        private Icon ownedIcon;

        public TrayApp(bool autoEnable)
        {
            ui = SynchronizationContext.Current;

            miToggle.Click += (s, e) => OnToggle();
            miOff.Click += (s, e) => SetMode(false);
            miLan.Click += (s, e) =>
            {
                var on = !state.Lan;
                Run("LAN " + on, () => ks.SetLan(on), st => KillSwitch.PredictLan(st, on));
            };
            miWsl.Click += (s, e) =>
            {
                var on = !state.Wsl;
                Run("WSL " + on, () => ks.SetWsl(on), st => KillSwitch.PredictWsl(st, on));
            };
            miBlockLeaks.Click += (s, e) =>
            {
                var on = !state.BlockLeaks;
                var active = state.Mode != KsMode.Off;
                Run("Block system leaks " + on, () => ks.SetBlockLeaks(on, active),
                    st => KillSwitch.PredictBlockLeaks(st, on, active));
            };
            miAutostart.Click += (s, e) => OnAutostartClick();

            menu.MenuItems.AddRange(new[]
            {
                miPartial,
                miToggle,
                miOff,
                new MenuItem("-"),
                miLan,
                miWsl,
                miClients,
                miInterfaces,
                miRules,
                new MenuItem("-"),
                miBlockLeaks,
                miLeaks,
                new MenuItem("-"),
                new MenuItem("Reset ALL", (s, e) => Run("Reset ALL", ks.ResetAll, KillSwitch.PredictReset)),
                new MenuItem("-"),
                miAutostart,
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
            quickPollTimer.Tick += (s, e) => OnQuickPoll();
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            SystemEvents.PowerModeChanged += OnPowerModeChanged;
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            MenuTheme.Apply();

            Start(autoEnable);
        }

        // ---------- Lifecycle ----------

        private async void Start(bool autoEnable)
        {
            UpdateAutostart(() =>
            {
                if (autostart.RepairIfBroken()) Log.Info("Autostart task pointed to the moved exe");
            });

            busy = true;
            var s = await ReadStateAsync(full: true, previous: state);
            if (s != null) state = s;
            busy = false;
            ApplyState();

            if (autoEnable && state.Mode != KsMode.On)
                Run("Auto-enable", () => ks.SetMode(true), st => KillSwitch.PredictMode(st, true));

            pollTimer.Start();
        }

        private void ExitApp()
        {
            // The firewall state is intentionally left as is: the kill switch must survive app exit.
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
            quickPollTimer.Stop();
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
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

        private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            // Light/dark switch arrives as General; re-apply the menu theme on the UI thread.
            if (e.Category == UserPreferenceCategory.General || e.Category == UserPreferenceCategory.Color)
                ui.Post(_ => MenuTheme.Apply(), null);
        }

        // ---------- Actions and refresh ----------

        private void OnToggle() => SetMode(state.Mode != KsMode.On);

        private void SetMode(bool block) =>
            Run(block ? "Turn ON" : "Turn OFF", () => ks.SetMode(block), st => KillSwitch.PredictMode(st, block));

        private void OnInterfaceClick(string iface)
        {
            if (state.Interfaces.Contains(iface))
            {
                Run("Deselect " + iface, () => ks.DeselectInterface(iface), st => KillSwitch.PredictDeselect(st, iface));
            }
            else
            {
                Run("Select " + iface, () => ks.SelectInterface(iface), st => KillSwitch.PredictSelect(st, iface));
            }
        }

        /// <summary>
        /// Runs a firewall action in the background, then re-reads the full state.
        /// <paramref name="predict"/> applies the expected result immediately, so a menu reopened
        /// during the action already shows it; the re-read corrects it if the action failed.
        /// </summary>
        private async void Run(string what, Action action, Func<KsState, KsState> predict = null)
        {
            if (busy) return;
            busy = true;
            generation++;
            if (predict != null) state = predict(state);
            AnimateTo(Yellow);

            try
            {
                var watch = System.Diagnostics.Stopwatch.StartNew();
                await Task.Run(action);
                Log.Info($"{what} ({watch.ElapsedMilliseconds} ms)");
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
            if (busy) return;
            ApplyState();

            // Legacy "Allow NAT (WSL)" let System traffic past the VPN: replace it with the Hyper-V rule.
            if (state.RulesLoaded && KillSwitch.NeedsNatMigration(state)
                && DateTime.UtcNow - lastMigration > TimeSpan.FromMinutes(5))
            {
                lastMigration = DateTime.UtcNow;
                var snapshot = state;
                Run("Migrate NAT rule", () => ks.MigrateNatRule(snapshot), KillSwitch.PredictNatMigration);
                return;
            }

            // "Allow LAN" is on, but a subnet added in a newer version has no rule yet.
            if (state.RulesLoaded && KillSwitch.NeedsLanSync(state)
                && DateTime.UtcNow - lastLanSync > TimeSpan.FromMinutes(5))
            {
                lastLanSync = DateTime.UtcNow;
                Run("Sync LAN rules", () => ks.SetLan(true), st => KillSwitch.PredictLan(st, true));
                return;
            }

            // VPN client profiles: allow new tunnel adapters (e.g. after a core switch), drop vanished ones.
            // The same plan is not retried more often than every 30 s if it keeps failing.
            if (state.RulesLoaded && KillSwitch.NeedsClientSync(state))
            {
                var signature = string.Join("|", state.Interfaces.OrderBy(i => i)) + "#" +
                                string.Join("|", state.Adapters.Select(a => a.Name).OrderBy(n => n));
                if (signature != lastSyncSignature || DateTime.UtcNow - lastSync > TimeSpan.FromSeconds(30))
                {
                    lastSyncSignature = signature;
                    lastSync = DateTime.UtcNow;
                    var snapshot = state;
                    Run("Sync VPN client adapters", () => ks.SyncClients(snapshot), SyncPrediction(snapshot));
                    return;
                }
            }

            // Self-healing: Windows updates or policies may re-enable system rules (or the
            // kill switch may be turned off outside the app). Retry at most every 5 minutes.
            if (state.RulesLoaded && KillSwitch.NeedsLeakReconcile(state)
                && DateTime.UtcNow - lastReconcile > TimeSpan.FromMinutes(5))
            {
                lastReconcile = DateTime.UtcNow;
                var snapshot = state;
                Run("Reconcile system rules", () => ks.ReconcileLeaks(snapshot));
            }
        }

        private static Func<KsState, KsState> SyncPrediction(KsState snapshot) => st =>
        {
            var n = st;
            foreach (var c in snapshot.Clients.Where(c => c.Enabled))
            {
                var plan = ClientProfiles.PlanAdapters(c.Profile, n);
                foreach (var iface in plan.ToSelect) n = KillSwitch.PredictSelect(n, iface);
                foreach (var iface in plan.ToDeselect) n = KillSwitch.PredictDeselect(n, iface);
            }
            return n;
        };

        private void OnClientClick(ClientProfile profile)
        {
            var on = !state.IsClientEnabled(profile.Id);
            var snapshot = state;
            if (on) Run("Enable " + profile.Name, () => ks.EnableClient(profile), st => KillSwitch.PredictClient(st, profile, true));
            else Run("Disable " + profile.Name, () => ks.DisableClient(profile, snapshot), st => KillSwitch.PredictClient(st, profile, false));
        }

        private void OnAutostartClick()
        {
            var on = autostartStatus != AutostartStatus.On;
            UpdateAutostart(on ? (Action)autostart.Enable : autostart.Disable,
                            on ? AutostartStatus.On : AutostartStatus.Off,
                            "Start with Windows " + on);
        }

        /// <summary>
        /// Runs a Task Scheduler action off the UI thread, then re-reads the status.
        /// Independent of the firewall operations (Reset ALL does not touch autostart).
        /// </summary>
        private async void UpdateAutostart(Action action, AutostartStatus? predicted = null, string what = null)
        {
            if (autostartBusy) return;
            autostartBusy = true;
            if (predicted != null) autostartStatus = predicted.Value;
            try
            {
                await Task.Run(() =>
                {
                    try
                    {
                        action();
                        if (what != null) Log.Info(what);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, what ?? "autostart");
                    }
                });
                autostartStatus = await Task.Run(() => autostart.GetStatus());
            }
            catch (Exception ex)
            {
                Log.Error(ex, "read autostart");
                autostartStatus = AutostartStatus.Unknown;
            }
            finally
            {
                autostartBusy = false;
            }
        }

        /// <summary>Network adapters changed: re-read soon instead of waiting for the next poll.</summary>
        private void OnNetworkAddressChanged(object sender, EventArgs e) =>
            ui.Post(_ =>
            {
                quickPollTimer.Stop();
                quickPollTimer.Start(); // events come in bursts: wait until they settle
            }, null);

        private void OnQuickPoll()
        {
            quickPollTimer.Stop();
            if (busy || polling) { quickPollTimer.Start(); return; } // retry shortly
            OnPoll();
        }

        /// <summary>Reads the state off the UI thread. Returns null on failure (e.g. right after wake-up).</summary>
        private async Task<KsState> ReadStateAsync(bool full, KsState previous)
        {
            try
            {
                return await Task.Run(() =>
                {
                    var s = new KsState();
                    ks.ReadProfiles(s);
                    if (full) ks.ReadRules(s);
                    else s.CopyRulesFrom(previous);
                    ks.ReadAdapters(s);
                    LogNewAdapters(s.Adapters);
                    return s;
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "read state");
                return null;
            }
        }

        private readonly HashSet<string> seenAdapters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool adaptersKnown;

        /// <summary>Logs adapters that appear after startup (runs on a worker thread).</summary>
        private void LogNewAdapters(List<AdapterInfo> adapters)
        {
            lock (seenAdapters)
            {
                var added = KillSwitch.NewAdapters(seenAdapters, adapters);
                if (!adaptersKnown) { adaptersKnown = true; return; } // the initial set is not interesting
                foreach (var a in added) Log.Info("New adapter: " + KillSwitch.DescribeAdapter(a));
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
            miBlockLeaks.Checked = state.BlockLeaks;
            miBlockLeaks.Enabled = state.RulesLoaded;
            miPartial.Visible = state.Mode == KsMode.Partial;
            miPartial.Text = "Partially on. Not blocked: " + state.NotBlocked + Warn;
            miToggle.Text = state.Mode == KsMode.On ? "Turn OFF"
                          : state.Mode == KsMode.Partial ? "Turn ON (all profiles)"
                          : "Turn ON";
            miOff.Visible = state.Mode == KsMode.Partial;

            miLan.Checked = state.Lan;
            miLan.Enabled = on;
            miWsl.Checked = state.Wsl;
            // Kept clickable while on, so the rule can be turned off even if WSL was uninstalled.
            miWsl.Enabled = on && (state.WslAvailable || state.Wsl);
            miWsl.Text = "Allow WSL" + (state.WslAvailable || !state.RulesLoaded ? "" : "\tnot installed");
            miInterfaces.Enabled = on;
            miClients.Enabled = on;
            miRules.Enabled = on;

            miAutostart.Checked = autostartStatus == AutostartStatus.On;
            miAutostart.Enabled = autostartStatus != AutostartStatus.Unknown;
            miAutostart.Text = "Start with Windows" +
                (autostartStatus == AutostartStatus.OtherCopy ? "\tother copy"
                 : autostartStatus == AutostartStatus.Broken ? Warn + " Not found" : "");

            BuildClientsMenu();
            BuildInterfacesMenu();
            BuildRulesMenu();
            BuildLeaksMenu(on);
        }

        private void BuildLeaksMenu(bool on)
        {
            miLeaks.MenuItems.Clear();
            miLeaks.Visible = false;
            if (!on) return;

            if (state.Leaks.Count > 0)
            {
                miLeaks.Visible = true;
                miLeaks.Text = $"Possible leaks ({state.Leaks.Count})" + Warn;
                AddLeakItems(state.Leaks);
                miLeaks.MenuItems.Add(new MenuItem("These Windows rules allow traffic outside the VPN.") { Enabled = false });
                miLeaks.MenuItems.Add(new MenuItem(state.BlockLeaks
                    ? "They could not be disabled, see the log."
                    : "Turn on \"Block system leaks\" to disable them.") { Enabled = false });
            }
            else if (state.DisabledLeaks.Count > 0)
            {
                miLeaks.Visible = true;
                miLeaks.Text = $"System leaks blocked ({state.DisabledLeaks.Count})";
                AddLeakItems(state.DisabledLeaks);
                miLeaks.MenuItems.Add(new MenuItem("These Windows rules are disabled while the kill switch is on.") { Enabled = false });
                miLeaks.MenuItems.Add(new MenuItem("They are restored on Turn OFF / Reset ALL.") { Enabled = false });
            }
        }

        private void AddLeakItems(IEnumerable<LeakInfo> leaks)
        {
            foreach (var leak in leaks)
                miLeaks.MenuItems.Add(new MenuItem($"{leak.Kind}: {leak.RuleName}") { Enabled = false });
            miLeaks.MenuItems.Add(new MenuItem("-"));
        }

        private void BuildClientsMenu()
        {
            miClients.MenuItems.Clear();
            var enabled = state.Clients.Count(c => c.Enabled);
            miClients.Text = enabled > 0 ? $"VPN clients ({enabled})" : "VPN clients";

            foreach (var c in state.Clients)
            {
                var profile = c.Profile;
                // Not installed: still clickable when enabled, so it can be turned off.
                var mark = c.InstallDir == null ? Warn + " Not found" : "";
                miClients.MenuItems.Add(new MenuItem(profile.Name + mark, (s, e) => OnClientClick(profile))
                {
                    Checked = c.Enabled,
                    Enabled = c.Enabled || c.InstallDir != null,
                });
            }
            if (state.Clients.Count == 0)
                miClients.MenuItems.Add(new MenuItem("No profiles") { Enabled = false });
        }

        private void BuildInterfacesMenu()
        {
            var selected = state.Interfaces;
            miInterfaces.Text = selected.Count > 0 ? $"Interfaces ({selected.Count})" : "Interfaces";
            miInterfaces.MenuItems.Clear();

            miInterfaces.MenuItems.Add(new MenuItem("None", (s, e) => Run("Clear interfaces", ks.ClearInterfaces, KillSwitch.PredictClear))
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
                var isSelected = selected.Contains(iface);
                // Selected but absent or disconnected: marked on the right; clicking it deselects.
                var adapter = state.Adapters.FirstOrDefault(a => string.Equals(a.Name, iface, StringComparison.OrdinalIgnoreCase));
                var client = isSelected ? state.ManagingClient(iface) : null;
                var mark = client != null ? "\t" + client.Name // managed by a VPN client profile
                         : !isSelected || (adapter != null && adapter.IsUp) ? ""
                         : adapter == null ? Warn + " Not found"
                         : Warn + " Disconnected";
                miInterfaces.MenuItems.Add(new MenuItem(iface + mark, (s, e) => OnInterfaceClick(iface))
                {
                    Checked = isSelected,
                    Enabled = client == null, // turn the profile off to remove it
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
            var text = KillSwitch.FormatTooltip(state, ShellTooltipMax);
            if (text == lastTooltip) return;
            lastTooltip = text;
            SetTooltip(text);
        }

        /// <summary>
        /// WinForms on .NET Framework limits NotifyIcon.Text to 63 chars, while Windows allows 127.
        /// Writes the private "text" field and refreshes the icon via reflection; falls back to the 63-char limit.
        /// </summary>
        private void SetTooltip(string text)
        {
            try
            {
                var type = typeof(NotifyIcon);
                var field = type.GetField("text", BindingFlags.NonPublic | BindingFlags.Instance);
                var update = type.GetMethod("UpdateIcon", BindingFlags.NonPublic | BindingFlags.Instance);
                if (field != null && update != null)
                {
                    field.SetValue(tray, text);
                    if (tray.Visible) update.Invoke(tray, new object[] { true });
                    return;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "tooltip");
            }
            tray.Text = text.Length > LegacyTooltipMax ? text.Substring(0, LegacyTooltipMax) : text;
        }

        private Color TargetColor()
        {
            switch (KillSwitch.GetIconState(state, busy))
            {
                case IconState.Busy: return Yellow;
                case IconState.Off: return Red;
                case IconState.Partial: return Orange;
                case IconState.AdapterMissing: return Blue;
                case IconState.Connected: return Green;
                default: return Gray; // NoInterfaces, Disconnected
            }
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
