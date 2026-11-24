using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace TheFirewall.App.Services;

/// <summary>
/// Ensures one app instance per Windows session. A second launch asks the running instance to show its window;
/// an elevated "--takeover" launch asks a non-elevated instance to exit and replaces it.
/// Messages go through a hidden window so they also work from a non-elevated to an elevated process.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    public const int CommandShow = 1;
    public const int CommandExit = 2;

    private const uint MsgFltAllow = 1;
    private static readonly string MutexName = $@"Local\TheFirewall.App.{System.Diagnostics.Process.GetCurrentProcess().SessionId}";
    private static readonly string WindowTitle = $"TheFirewall.App.Messages.{System.Diagnostics.Process.GetCurrentProcess().SessionId}";
    private static readonly uint MessageId = RegisterWindowMessage("TheFirewall.App.Command");

    private Mutex? mutex;
    private HwndSource? source;

    public event Action<int>? CommandReceived;

    /// <summary>Tries to become the single instance. With takeover, a running instance is asked to exit first.</summary>
    public bool TryAcquire(bool takeover)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                mutex = new Mutex(true, MutexName, out bool created);
                if (created)
                {
                    return true;
                }

                if (!takeover)
                {
                    mutex.Dispose();
                    mutex = null;
                    return false;
                }

                Send(CommandExit);
                try
                {
                    if (mutex.WaitOne(TimeSpan.FromSeconds(8)))
                    {
                        return true;
                    }
                }
                catch (AbandonedMutexException)
                {
                    return true; // previous owner exited; we now own the mutex
                }

                mutex.Dispose();
                mutex = null;
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                // The running instance is elevated and we are not: just ask it to show itself.
                mutex = null;
                if (!takeover)
                {
                    return false;
                }

                Thread.Sleep(500);
            }
        }

        return false;
    }

    /// <summary>Creates the hidden message window. Call on the UI thread after acquiring.</summary>
    public void Listen()
    {
        var parameters = new HwndSourceParameters(WindowTitle)
        {
            Width = 0,
            Height = 0,
            WindowStyle = 0,
            ParentWindow = new IntPtr(-3), // HWND_MESSAGE: message-only window
        };
        source = new HwndSource(parameters);
        source.AddHook(WndProc);

        // Allow a non-elevated second instance to message an elevated first instance (UIPI).
        ChangeWindowMessageFilterEx(source.Handle, MessageId, MsgFltAllow, IntPtr.Zero);
    }

    /// <summary>Sends a command to the running instance. Returns false when none was found.</summary>
    public static bool Send(int command)
    {
        var hwnd = FindWindowEx(new IntPtr(-3), IntPtr.Zero, null, WindowTitle);
        if (hwnd == IntPtr.Zero)
        {
            return false;
        }

        AllowSetForegroundWindow(-1);
        return PostMessage(hwnd, MessageId, new IntPtr(command), IntPtr.Zero);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if ((uint)msg == MessageId)
        {
            handled = true;
            CommandReceived?.Invoke(wParam.ToInt32());
        }

        return IntPtr.Zero;
    }

    public void Dispose()
    {
        source?.Dispose();
        source = null;
        if (mutex is not null)
        {
            try
            {
                mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
            }

            mutex.Dispose();
            mutex = null;
        }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessage(string message);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindWindowEx(IntPtr parent, IntPtr childAfter, string? className, string windowTitle);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr changeInfo);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(int processId);
}
