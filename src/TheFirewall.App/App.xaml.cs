using System.IO;
using System.Windows;
using System.Windows.Threading;
using TheFirewall.App.Services;
using TheFirewall.App.Tray;
using TheFirewall.App.ViewModels;
using TheFirewall.App.Views;

namespace TheFirewall.App;

public partial class App : Application
{
    private SingleInstance? singleInstance;
    private IFirewallClient? client;
    private TrayIcon? tray;
    private MainWindow? mainWindow;
    private MainViewModel? mainViewModel;
    private AppServices? services;

    public static bool IsDemo { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args.Select(a => a.ToLowerInvariant()).ToHashSet();
        IsDemo = args.Contains("--demo");
        var screenshotIndex = Array.FindIndex(e.Args, a => a.Equals("--screenshots", StringComparison.OrdinalIgnoreCase));
        bool screenshots = screenshotIndex >= 0;

        DispatcherUnhandledException += OnUnhandledException;
        Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/TheFirewall;component/Themes/Derived.xaml", UriKind.Relative) });

        var preferences = AppPreferences.Load();
        ApplyTheme(screenshots ? "Light" : preferences.Theme);

        if (!screenshots)
        {
            singleInstance = new SingleInstance();
            if (!singleInstance.TryAcquire(takeover: args.Contains("--takeover")))
            {
                SingleInstance.Send(SingleInstance.CommandShow);
                singleInstance = null;
                Shutdown(0);
                return;
            }

            singleInstance.CommandReceived += OnInstanceCommand;
            singleInstance.Listen();
        }

        client = IsDemo || screenshots ? new DemoClient(Dispatcher, live: !screenshots) : new ServiceClient(Dispatcher);
        var settingsSession = new SettingsSession(client);
        services = new AppServices(client, settingsSession, preferences);
        services.ShowAddressDetails = ip => new Views.Dialogs.AddressDetailsWindow(services, ip) { Owner = mainWindow }.Show();
        mainViewModel = new MainViewModel(services);
        client.Start();

        if (screenshots)
        {
            var output = screenshotIndex + 1 < e.Args.Length ? e.Args[screenshotIndex + 1] : Path.Combine(Environment.CurrentDirectory, "screenshots");
            _ = ScreenshotRunner.RunAsync(this, mainViewModel, output);
            return;
        }

        tray = new TrayIcon(client, settingsSession, page => ShowMainWindow(page), ExitApplication);

        if (!args.Contains("--tray") || args.Contains("--show"))
        {
            ShowMainWindow(null);
        }
    }

    public static void ApplyTheme(string theme)
    {
        Current.ThemeMode = theme switch
        {
            "Light" => ThemeMode.Light,
            "Dark" => ThemeMode.Dark,
            _ => ThemeMode.System,
        };
    }

    private void OnInstanceCommand(int command)
    {
        if (command == SingleInstance.CommandExit)
        {
            ExitApplication();
        }
        else
        {
            ShowMainWindow(null);
        }
    }

    public void ShowMainWindow(string? page)
    {
        if (mainViewModel is null || services is null)
        {
            return;
        }

        if (mainWindow is null)
        {
            mainWindow = new MainWindow(mainViewModel, services.Preferences);
            MainWindow = mainWindow;
            mainWindow.Closed += (_, _) => mainWindow = null;
            if (mainViewModel.CurrentPage is null)
            {
                mainViewModel.Navigate("dashboard");
            }
        }

        if (page is not null)
        {
            mainViewModel.Navigate(page);
        }

        mainWindow.Show();
        if (mainWindow.WindowState == WindowState.Minimized)
        {
            mainWindow.WindowState = WindowState.Normal;
        }

        mainWindow.Activate();
        mainWindow.Topmost = true;
        mainWindow.Topmost = false;
        mainWindow.Focus();
    }

    public void ExitApplication()
    {
        tray?.Dispose();
        tray = null;
        mainWindow?.CloseForExit();
        _ = Dispatcher.InvokeAsync(async () =>
        {
            if (client is not null)
            {
                await client.StopAsync();
            }

            singleInstance?.Dispose();
            singleInstance = null;
            Shutdown(0);
        });
    }

    protected override void OnExit(ExitEventArgs e)
    {
        tray?.Dispose();
        singleInstance?.Dispose();
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TheFirewall");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "app-errors.log"), $"{DateTime.Now:O} {e.Exception}{Environment.NewLine}");
        }
        catch (Exception)
        {
        }

        if (ScreenshotRunner.IsRunning)
        {
            Console.Error.WriteLine(e.Exception);
            Environment.Exit(3);
        }

        UiDialogs.Error("Something went wrong", e.Exception.Message);
        e.Handled = true;
    }
}
