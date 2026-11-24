using System.ComponentModel;
using System.Windows;
using TheFirewall.App.Services;
using TheFirewall.App.ViewModels;

namespace TheFirewall.App.Views;

public partial class MainWindow : Window
{
    private readonly AppPreferences preferences;
    private bool exiting;

    public MainWindow(MainViewModel viewModel, AppPreferences preferences)
    {
        this.preferences = preferences;
        InitializeComponent();
        DataContext = viewModel;
        Width = Math.Clamp(preferences.WindowWidth, MinWidth, SystemParameters.WorkArea.Width);
        Height = Math.Clamp(preferences.WindowHeight, MinHeight, SystemParameters.WorkArea.Height);
    }

    /// <summary>Closes the window for real (instead of hiding it to the tray).</summary>
    public void CloseForExit()
    {
        exiting = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (WindowState == WindowState.Normal)
        {
            preferences.WindowWidth = ActualWidth;
            preferences.WindowHeight = ActualHeight;
        }

        if (!exiting && !App.IsDemo)
        {
            // Closing the window keeps the tray icon (and of course the service) running.
            e.Cancel = true;
            Hide();
            if (!preferences.HasShownTrayHint)
            {
                preferences.HasShownTrayHint = true;
                UiDialogs.Info("TheFirewall is still running",
                    "TheFirewall keeps protecting this computer in the background. Open it again from the shield icon in the notification area.");
            }
        }

        preferences.Save();
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        if (App.IsDemo && !exiting)
        {
            ((App)Application.Current).ExitApplication();
        }
    }
}
