using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using TheFirewall.App.Services;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Data;
using TheFirewall.Core.Geo;
using WinForms = System.Windows.Forms;

namespace TheFirewall.App.Tray;

public enum TrayState
{
    Offline,
    Protected,
    Paused,
    Alert,
}

/// <summary>
/// The notification-area icon. Its colour reflects the protection state, its menu offers quick actions and it
/// shows (grouped) notifications for bans and other events.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly WinForms.NotifyIcon notifyIcon;
    private readonly IFirewallClient client;
    private readonly SettingsSession settingsSession;
    private readonly Action<string?> openWindow;
    private readonly Action exit;
    private readonly Dictionary<TrayState, System.Drawing.Icon> icons = [];
    private readonly List<ActivityEntry> pendingBans = [];
    private readonly DispatcherTimer notifyTimer;
    private Window? helperWindow;
    private TrayState state = (TrayState)(-1);
    private NotificationSettings notifications = new();
    private DateTime lastBalloonUtc = DateTime.MinValue;
    private string? balloonTarget;
    private bool wasConnected;

    public TrayIcon(IFirewallClient client, SettingsSession settingsSession, Action<string?> openWindow, Action exit)
    {
        this.client = client;
        this.settingsSession = settingsSession;
        this.openWindow = openWindow;
        this.exit = exit;

        icons[TrayState.Offline] = LoadIcon("TrayOffline.ico");
        icons[TrayState.Protected] = LoadIcon("TrayProtected.ico");
        icons[TrayState.Paused] = LoadIcon("TrayPaused.ico");
        icons[TrayState.Alert] = LoadIcon("TrayAlert.ico");

        notifyIcon = new WinForms.NotifyIcon { Text = "TheFirewall", Icon = icons[TrayState.Offline], Visible = true };
        notifyIcon.MouseUp += OnMouseUp;
        notifyIcon.MouseDoubleClick += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Left)
            {
                openWindow(null);
            }
        };
        notifyIcon.BalloonTipClicked += (_, _) => openWindow(balloonTarget);

        notifyTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        notifyTimer.Tick += (_, _) => FlushNotifications();

        client.ConnectionChanged += (_, _) => OnConnectionChanged();
        client.StatusReceived += (_, _) => UpdateState();
        client.ActivityReceived += (_, entry) => OnActivity(entry);
        settingsSession.Changed += (_, _) => notifications = settingsSession.Current?.Notifications ?? new NotificationSettings();
        UpdateState();
    }

    private static System.Drawing.Icon LoadIcon(string name)
    {
        var info = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}"))
                   ?? throw new InvalidOperationException($"Missing icon {name}");
        using var stream = info.Stream;
        return new System.Drawing.Icon(stream, WinForms.SystemInformation.SmallIconSize);
    }

    private async void OnConnectionChanged()
    {
        UpdateState();
        if (client.IsConnected)
        {
            wasConnected = true;
            try
            {
                await settingsSession.LoadAsync(force: true);
            }
            catch (Exception)
            {
            }
        }
        else if (wasConnected && notifications.NotifyOnServiceProblems)
        {
            ShowBalloon("TheFirewall service stopped", "Failed logins are not being monitored and no new addresses are banned.", WinForms.ToolTipIcon.Warning, null);
        }
    }

    public void UpdateState()
    {
        var status = client.LastStatus;
        TrayState newState;
        string text;
        if (!client.IsConnected || status is null)
        {
            newState = TrayState.Offline;
            text = "TheFirewall - service not running";
        }
        else if (!status.ProtectionEnabled)
        {
            newState = TrayState.Paused;
            text = "TheFirewall - protection paused";
        }
        else if (status.Warnings.Count > 0)
        {
            newState = TrayState.Alert;
            text = $"TheFirewall - needs attention\n{status.ActiveBans:N0} addresses banned";
        }
        else
        {
            newState = TrayState.Protected;
            text = $"TheFirewall - protected\n{status.ActiveBans:N0} addresses banned";
        }

        notifyIcon.Text = text.Length > 63 ? text[..63] : text;
        if (newState != state)
        {
            state = newState;
            notifyIcon.Icon = icons[newState];
        }
    }

    private void OnActivity(ActivityEntry entry)
    {
        switch (entry.Type)
        {
            case ActivityType.Banned when notifications.NotifyOnBan:
                pendingBans.Add(entry);
                if (!notifyTimer.IsEnabled)
                {
                    notifyTimer.Start();
                }

                break;
            case ActivityType.Unbanned when notifications.NotifyOnUnban:
                ShowBalloon("Address unbanned", $"{entry.IPAddress} ({Countries.GetName(entry.Country)})\n{entry.Message}", WinForms.ToolTipIcon.Info, "bans");
                break;
            case ActivityType.SuccessfulLogin when notifications.NotifyOnSuccessfulLogin:
                ShowBalloon("New sign-in", $"{entry.UserName ?? "Someone"} signed in from {entry.IPAddress} ({Countries.GetName(entry.Country)}) via {entry.Source}.",
                    WinForms.ToolTipIcon.Info, "activity");
                break;
        }

        if (entry.Type is ActivityType.Banned or ActivityType.Unbanned)
        {
            UpdateState();
        }
    }

    private void FlushNotifications()
    {
        // Group bursts of bans into one notification and avoid flooding the screen.
        if (pendingBans.Count == 0)
        {
            notifyTimer.Stop();
            return;
        }

        if (DateTime.UtcNow - lastBalloonUtc < TimeSpan.FromSeconds(20))
        {
            return;
        }

        notifyTimer.Stop();
        var latest = pendingBans[^1];
        string title, body;
        if (pendingBans.Count == 1)
        {
            title = $"Banned {latest.IPAddress}";
            body = $"{Countries.GetName(latest.Country)} · {latest.Source}\n{latest.Message}";
        }
        else
        {
            title = $"Banned {pendingBans.Count} addresses";
            body = $"Latest: {latest.IPAddress} ({Countries.GetName(latest.Country)}) via {latest.Source}";
        }

        pendingBans.Clear();
        ShowBalloon(title, body, WinForms.ToolTipIcon.None, "bans");
    }

    /// <summary>Shows a notification from the tray icon; clicking it opens the dashboard.</summary>
    public void ShowNotification(string title, string text, bool warning) =>
        ShowBalloon(title, text, warning ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info, "dashboard");

    private void ShowBalloon(string title, string text, WinForms.ToolTipIcon icon, string? target)
    {
        balloonTarget = target;
        lastBalloonUtc = DateTime.UtcNow;
        notifyIcon.ShowBalloonTip(5000, title, text, icon);
    }

    // ------------------------------------------------------------------ Menu

    private void OnMouseUp(object? sender, WinForms.MouseEventArgs e)
    {
        if (e.Button == WinForms.MouseButtons.Left)
        {
            openWindow(null);
        }
        else if (e.Button == WinForms.MouseButtons.Right)
        {
            ShowMenu();
        }
    }

    private void ShowMenu()
    {
        EnsureHelperWindow();
        var menu = BuildMenu();

        // The menu only closes on outside clicks when our process owns the foreground window.
        SetForegroundWindow(new WindowInteropHelper(helperWindow!).Handle);
        menu.Placement = PlacementMode.MousePoint;
        menu.IsOpen = true;
    }

    private ContextMenu BuildMenu()
    {
        var menu = new ContextMenu { MinWidth = 260 };
        var status = client.LastStatus;

        var header = new MenuItem
        {
            Header = state switch
            {
                TrayState.Protected => "You're protected",
                TrayState.Paused => "Protection is paused",
                TrayState.Alert => "Protected, but needs attention",
                _ => "TheFirewall service is not running",
            },
            IsEnabled = false,
            FontWeight = FontWeights.SemiBold,
        };
        menu.Items.Add(header);
        if (status is not null && client.IsConnected)
        {
            menu.Items.Add(new MenuItem { Header = $"{status.ActiveBans:N0} addresses banned", IsEnabled = false });
        }

        menu.Items.Add(new Separator());
        menu.Items.Add(Item("Open TheFirewall", "", () => openWindow(null), bold: true));
        menu.Items.Add(Item("Live activity", "", () => openWindow("activity")));
        menu.Items.Add(Item("Banned addresses", "", () => openWindow("bans")));
        menu.Items.Add(new Separator());

        if (client.IsConnected && status is not null)
        {
            menu.Items.Add(status.ProtectionEnabled
                ? Item("Pause protection", "", () => _ = SetProtectionAsync(false))
                : Item("Resume protection", "", () => _ = SetProtectionAsync(true)));
        }
        else if (!client.IsDemo)
        {
            var serviceState = WindowsServiceControl.GetState();
            if (serviceState is ServiceInstallState.Stopped or ServiceInstallState.NotInstalled)
            {
                menu.Items.Add(Item(serviceState == ServiceInstallState.NotInstalled ? "Install and start the service" : "Start the service", "\uE768",
                    () => _ = EnsureServiceAsync()));
            }
        }

        if (!Elevation.IsElevated && !client.IsDemo)
        {
            menu.Items.Add(Item("Restart as administrator", "", () => Elevation.RestartElevated(showWindow: false)));
        }

        menu.Items.Add(new Separator());
        menu.Items.Add(Item("Exit (protection keeps running)", "", exit));
        return menu;
    }

    private static MenuItem Item(string text, string glyph, Action action, bool bold = false)
    {
        var item = new MenuItem
        {
            Header = text,
            Icon = new TextBlock { Text = glyph, FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"), FontSize = 14 },
        };
        if (bold)
        {
            item.FontWeight = FontWeights.SemiBold;
        }

        item.Click += (_, _) => action();
        return item;
    }

    private async Task SetProtectionAsync(bool enabled)
    {
        if (!client.CanMakeChanges)
        {
            UiDialogs.RequestElevation();
            return;
        }

        try
        {
            await client.SetProtectionAsync(enabled);
            await settingsSession.LoadAsync(force: true);
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, enabled ? "Unable to resume protection" : "Unable to pause protection");
        }

        UpdateState();
    }

    private static async Task EnsureServiceAsync()
    {
        var result = await ServiceBootstrapper.EnsureRunningAsync();
        if (!result.IsRunning && result.Outcome != EnsureServiceOutcome.Declined)
        {
            UiDialogs.Error("TheFirewall service", result.Message ?? "The service could not be started.");
        }
    }

    private void EnsureHelperWindow()
    {
        if (helperWindow is not null)
        {
            return;
        }

        helperWindow = new Window
        {
            Width = 1,
            Height = 1,
            Left = -32000,
            Top = -32000,
            WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize,
            ShowInTaskbar = false,
            ShowActivated = false,
            Title = "TheFirewall tray",
        };
        helperWindow.Show();
        helperWindow.Hide();
        new WindowInteropHelper(helperWindow).EnsureHandle();
    }

    public void Dispose()
    {
        notifyTimer.Stop();
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
        foreach (var icon in icons.Values)
        {
            icon.Dispose();
        }

        helperWindow?.Close();
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hwnd);
}
