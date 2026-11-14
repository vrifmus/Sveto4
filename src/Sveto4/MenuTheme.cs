using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace Sveto4
{
    /// <summary>
    /// Makes native popup menus follow the Windows app theme (light/dark).
    /// Uses undocumented uxtheme.dll exports (ordinals 135/136, Windows 10 1903+),
    /// the same approach as Notepad++ and other Win32 apps. On failure menus stay light.
    /// </summary>
    internal static class MenuTheme
    {
        private const int MinBuild = 18362; // Windows 10 1903: ordinal 135 = SetPreferredAppMode
        private const int ForceDark = 2;
        private const int ForceLight = 3;

        public static void Apply()
        {
            try
            {
                if (Environment.OSVersion.Version.Major < 10 || Environment.OSVersion.Version.Build < MinBuild) return;
                SetPreferredAppMode(IsSystemDark() ? ForceDark : ForceLight);
                FlushMenuThemes();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "menu theme");
            }
        }

        /// <summary>Windows "Choose your app mode" setting.</summary>
        private static bool IsSystemDark()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }

        /// <summary>
        /// Repaints the popup menu windows (class "#32768") of this thread, so items changed while a
        /// menu is open are drawn in their new state without waiting for the mouse to pass over them.
        /// </summary>
        public static void RedrawOpenMenus()
        {
            EnumThreadWindows(GetCurrentThreadId(), (hwnd, lParam) =>
            {
                var name = new StringBuilder(16);
                if (IsWindowVisible(hwnd) && GetClassName(hwnd, name, name.Capacity) > 0 && name.ToString() == "#32768")
                    InvalidateRect(hwnd, IntPtr.Zero, true);
                return true;
            }, IntPtr.Zero);
        }

        private delegate bool EnumThreadWndProc(IntPtr hwnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumThreadWindows(uint threadId, EnumThreadWndProc callback, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hwnd, StringBuilder name, int maxCount);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hwnd);

        [DllImport("user32.dll")]
        private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);

        [DllImport("uxtheme.dll", EntryPoint = "#135")]
        private static extern int SetPreferredAppMode(int mode);

        [DllImport("uxtheme.dll", EntryPoint = "#136")]
        private static extern void FlushMenuThemes();
    }
}
