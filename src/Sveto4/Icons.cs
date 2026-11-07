using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Sveto4
{
    /// <summary>Draws round tray icons sized for the current DPI and caches static colors.</summary>
    internal sealed class Icons : IDisposable
    {
        private readonly Dictionary<int, Icon> cache = new Dictionary<int, Icon>();

        public Icon Get(Color color)
        {
            var key = color.ToArgb();
            if (!cache.TryGetValue(key, out var icon))
            {
                icon = Create(color);
                cache[key] = icon;
            }
            return icon;
        }

        /// <summary>Creates a new icon; the caller owns and disposes it.</summary>
        public static Icon Create(Color color)
        {
            var size = SystemInformation.SmallIconSize;
            using (var bitmap = new Bitmap(size.Width, size.Height))
            using (var g = Graphics.FromImage(bitmap))
            using (var brush = new SolidBrush(color))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                g.FillEllipse(brush, 0, 0, size.Width - 1, size.Height - 1);

                var handle = bitmap.GetHicon();
                try
                {
                    using (var temp = Icon.FromHandle(handle))
                        return (Icon)temp.Clone();
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
        }

        public void Dispose()
        {
            foreach (var icon in cache.Values) icon.Dispose();
            cache.Clear();
        }

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);
    }
}
