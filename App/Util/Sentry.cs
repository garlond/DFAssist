using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpRaven;
using SharpRaven.Data;

namespace App
{
    internal class Sentry
    {
        private static RavenClient ravenClient;

        internal static void Initialise()
        {
  
        }

        internal static void Report(Exception exception, object extra)
        {
            var @event = new SentryEvent(exception);
            @event.Extra = extra;
            Report(@event);
        }

        internal static void Report(string message)
        {
            var @event = new SentryEvent(new SentryMessage(message));
            @event.Level = ErrorLevel.Debug;
            Report(@event);
        }

        internal static void Report(SentryEvent @event)
        {

        }

        internal static void ReportAsync(Exception exception, object extra)
        {
            var @event = new SentryEvent(exception);
            @event.Extra = extra;
            ReportAsync(@event);
        }

        internal static void ReportAsync(string message, ErrorLevel level = ErrorLevel.Debug)
        {
            var @event = new SentryEvent(new SentryMessage(message));
            @event.Level = level;
            ReportAsync(@event);
        }

        internal static void ReportAsync(SentryEvent @event)
        {
            Task.Factory.StartNew(() =>
            {
                try
                {
                    Report(@event);
                }
                catch { }
            });
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                var exception = e.ExceptionObject as Exception;
                if (exception == null)
                {
                    return;
                }

                MessageBox.Show(Localization.GetText("app-crashed", exception.Message), Localization.GetText("msgbox-title-error"), MessageBoxButtons.OK, MessageBoxIcon.Error);

                var @event = new SentryEvent(exception);
                @event.Level = ErrorLevel.Fatal;
                Report(@event);
            }
            catch { }
        }
    }
}
