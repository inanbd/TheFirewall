using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace TheFirewall.App.Services;

public static class Elevation
{
    public static bool IsElevated { get; } = CheckElevated();

    private static bool CheckElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts an elevated copy of the app that takes over from this one. Returns false when the user cancelled UAC.
    /// </summary>
    public static bool RestartElevated(bool showWindow)
    {
        var exe = Environment.ProcessPath;
        if (exe is null)
        {
            return false;
        }

        var args = "--takeover" + (showWindow ? " --show" : " --tray") + (App.IsDemo ? " --demo" : string.Empty);
        try
        {
            Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false;
        }
    }
}
