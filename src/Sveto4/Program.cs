using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Sveto4
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            using (var mutex = new Mutex(true, @"Global\Sveto4.SingleInstance", out var isFirst))
            {
                if (!isFirst) return;

                // Never show error dialogs: log instead.
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += (s, e) => Log.Error(e.Exception, "UI thread");
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error(e.ExceptionObject as Exception, "unhandled");
                TaskScheduler.UnobservedTaskException += (s, e) => { Log.Error(e.Exception, "task"); e.SetObserved(); };

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // Needed so that "await" continues on the UI thread (there is no Form here).
                SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());

                var autoEnable = args.Any(a =>
                    a.Equals("--auto-enable", StringComparison.OrdinalIgnoreCase) ||
                    a.Equals("-AutoEnable", StringComparison.OrdinalIgnoreCase));

                Log.Info("Started" + (autoEnable ? " (auto-enable)" : ""));
                Application.Run(new TrayApp(autoEnable));
                Log.Info("Exited");
                GC.KeepAlive(mutex);
            }
        }
    }
}
