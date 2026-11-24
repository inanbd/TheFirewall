using System.IO;
using System.Windows;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.Services;

/// <summary>Message boxes and central error handling.</summary>
public static class UiDialogs
{
    private static Window? Owner => Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive) ?? Application.Current?.MainWindow;

    public static void Info(string title, string message) => Show(title, message, MessageBoxButton.OK, MessageBoxImage.Information);

    public static void Error(string title, string message) => Show(title, message, MessageBoxButton.OK, MessageBoxImage.Warning);

    public static bool Confirm(string title, string message, bool destructive = false) =>
        Show(title, message, MessageBoxButton.YesNo, destructive ? MessageBoxImage.Warning : MessageBoxImage.Question) == MessageBoxResult.Yes;

    private static MessageBoxResult Show(string title, string message, MessageBoxButton buttons, MessageBoxImage image)
    {
        var owner = Owner;
        return owner is { IsVisible: true }
            ? MessageBox.Show(owner, message, title, buttons, image)
            : MessageBox.Show(message, title, buttons, image);
    }

    /// <summary>Shows a friendly message for an exception from a service call.</summary>
    public static void HandleError(Exception ex, string action)
    {
        switch (ex)
        {
            case IpcException { Code: IpcErrorCodes.ElevationRequired }:
                RequestElevation();
                break;
            case IpcException ipc:
                Error(action, ipc.Message);
                break;
            case IOException:
                Error(action, "TheFirewall service is not running or cannot be reached.\n\nStart the service from the dashboard and try again.");
                break;
            case TimeoutException:
                Error(action, "The service did not answer in time. Please try again.");
                break;
            default:
                Error(action, ex.Message);
                break;
        }
    }

    public static void RequestElevation()
    {
        if (Confirm("Administrator permission needed",
                "Changing TheFirewall's settings requires administrator permission.\n\nRestart TheFirewall as administrator now?"))
        {
            if (Elevation.RestartElevated(showWindow: true))
            {
                // The elevated copy asks this instance to exit once it is running.
            }
        }
    }

    public static void ShowValidationErrors(IEnumerable<string> errors) =>
        Error("Settings not saved", "Please fix the following:\n\n• " + string.Join("\n• ", errors));
}
