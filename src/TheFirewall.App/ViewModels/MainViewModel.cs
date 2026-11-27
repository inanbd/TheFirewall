using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.ViewModels;

public enum ProtectionKind
{
    Offline,
    Protected,
    Paused,
    Attention,
}

public sealed partial class MainViewModel : ObservableObject
{
    private readonly AppServices services;

    public MainViewModel(AppServices services)
    {
        this.services = services;
        services.Navigate = Navigate;
        Pages =
        [
            new DashboardViewModel(services),
            new ActivityViewModel(services),
            new BansViewModel(services),
            new PortsViewModel(services),
            new RulesViewModel(services),
            new ListsViewModel(services),
            new SourcesViewModel(services),
            new CountriesViewModel(services),
            new FeedsViewModel(services),
        ];
        FooterPages =
        [
            new SettingsViewModel(services),
            new AboutViewModel(services),
        ];

        services.Client.ConnectionChanged += (_, _) => UpdateStatus();
        services.Client.StatusReceived += (_, _) => UpdateStatus();
        UpdateStatus();
    }

    public ObservableCollection<PageViewModel> Pages { get; }

    public ObservableCollection<PageViewModel> FooterPages { get; }

    [ObservableProperty]
    public partial PageViewModel? SelectedPage { get; set; }

    [ObservableProperty]
    public partial PageViewModel? SelectedFooterPage { get; set; }

    [ObservableProperty]
    public partial PageViewModel? CurrentPage { get; set; }

    [ObservableProperty]
    public partial ProtectionKind Protection { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Connecting…";

    [ObservableProperty]
    public partial bool IsConnected { get; set; }

    [ObservableProperty]
    public partial bool IsReadOnly { get; set; }

    [ObservableProperty]
    public partial ServiceStatusDto? Status { get; set; }

    public bool IsDemo => services.Client.IsDemo;

    public bool ShowElevationBanner => IsConnected && IsReadOnly && !IsDemo;

    /// <summary>The app is elevated but the service still treats it as read-only (e.g. an older service version).</summary>
    public bool ServiceRejectsAdmin => Elevation.IsElevated;

    public string ElevationBannerText => ServiceRejectsAdmin
        ? "The TheFirewall service did not recognise this app's administrator rights. Restart the service to fix this."
        : "You can look around, but changing settings needs administrator permission.";

    public string ElevationBannerButton => ServiceRejectsAdmin ? "Restart service" : "Restart as administrator";

    public string MachineName => Status?.MachineName ?? Environment.MachineName;

    partial void OnSelectedPageChanged(PageViewModel? value)
    {
        if (value is not null)
        {
            SelectedFooterPage = null;
            CurrentPage = value;
        }
    }

    partial void OnSelectedFooterPageChanged(PageViewModel? value)
    {
        if (value is not null)
        {
            SelectedPage = null;
            CurrentPage = value;
        }
    }

    partial void OnCurrentPageChanged(PageViewModel? oldValue, PageViewModel? newValue)
    {
        oldValue?.NavigatedFrom();
        if (newValue is not null)
        {
            _ = newValue.NavigatedToAsync();
        }
    }

    public void Navigate(string key)
    {
        var page = Pages.FirstOrDefault(p => p.Key == key);
        if (page is not null)
        {
            SelectedPage = page;
            return;
        }

        var footer = FooterPages.FirstOrDefault(p => p.Key == key);
        if (footer is not null)
        {
            SelectedFooterPage = footer;
        }
    }

    private void UpdateStatus()
    {
        var client = services.Client;
        bool wasConnected = IsConnected;
        IsConnected = client.IsConnected;
        IsReadOnly = !client.CanMakeChanges;
        Status = client.LastStatus;

        if (!client.IsConnected || Status is null)
        {
            Protection = ProtectionKind.Offline;
            StatusText = "Service not running";
        }
        else if (!Status.ProtectionEnabled)
        {
            Protection = ProtectionKind.Paused;
            StatusText = "Protection paused";
        }
        else if (Status.Warnings.Count > 0)
        {
            Protection = ProtectionKind.Attention;
            StatusText = "Needs attention";
        }
        else
        {
            Protection = ProtectionKind.Protected;
            StatusText = "Protected";
        }

        OnPropertyChanged(nameof(ShowElevationBanner));
        OnPropertyChanged(nameof(MachineName));

        // Reload the visible page once the service becomes reachable.
        if (!wasConnected && IsConnected && CurrentPage is not null)
        {
            services.Settings.Invalidate();
            _ = CurrentPage.NavigatedToAsync();
        }
    }

    [RelayCommand]
    private async Task RestartAsAdministratorAsync()
    {
        if (!ServiceRejectsAdmin)
        {
            Elevation.RestartElevated(showWindow: true);
            return;
        }

        var stop = await WindowsServiceControl.RunElevatedAsync("stop");
        var result = await ServiceBootstrapper.EnsureRunningAsync();
        if (!result.IsRunning)
        {
            UiDialogs.Error("TheFirewall service", result.Message ?? stop ?? "The service could not be restarted.");
        }
    }
}
