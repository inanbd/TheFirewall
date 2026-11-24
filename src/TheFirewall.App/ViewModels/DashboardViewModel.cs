using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.Core.Data;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.ViewModels;

public sealed record BarItem(string Name, string? Code, long Count, double Fraction, string? Detail = null);

public sealed partial class DashboardViewModel : PageViewModel
{
    private readonly DispatcherTimer refreshTimer;
    private bool refreshQueued;

    public DashboardViewModel(AppServices services) : base(services)
    {
        refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        refreshTimer.Tick += (_, _) => _ = RefreshAsync();
        Client.ActivityReceived += OnActivity;
        Client.StatusReceived += (_, status) => ApplyStatus(status);
        Client.ConnectionChanged += (_, _) => UpdateHero();
        ServiceBootstrapper.BusyChanged += () => System.Windows.Application.Current?.Dispatcher.InvokeAsync(UpdateHero);
    }

    public override string Key => "dashboard";

    public override string Title => "Dashboard";

    public override string Glyph => "";

    public ObservableCollection<ActivityEntry> Recent { get; } = [];

    public ObservableCollection<BarItem> TopCountries { get; } = [];

    public ObservableCollection<BarItem> TopUserNames { get; } = [];

    public ObservableCollection<BarItem> TopSources { get; } = [];

    [ObservableProperty]
    public partial DashboardStats? Stats { get; set; }

    [ObservableProperty]
    public partial ServiceStatusDto? Status { get; set; }

    [ObservableProperty]
    public partial IList<long>? ChartValues { get; set; }

    [ObservableProperty]
    public partial IList<long>? ChartLine { get; set; }

    [ObservableProperty]
    public partial IList<string>? ChartLabels { get; set; }

    [ObservableProperty]
    public partial bool ShowMonth { get; set; }

    [ObservableProperty]
    public partial string HeroTitle { get; set; } = "Connecting to TheFirewall…";

    [ObservableProperty]
    public partial string HeroText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial ProtectionKind Protection { get; set; }

    [ObservableProperty]
    public partial string? PrimaryActionText { get; set; }

    [ObservableProperty]
    public partial ServiceInstallState ServiceState { get; set; }

    public string ChartTitle => ShowMonth ? "Failed logins - last 30 days" : "Failed logins and bans - last 24 hours";

    partial void OnShowMonthChanged(bool value)
    {
        OnPropertyChanged(nameof(ChartTitle));
        UpdateChart();
    }

    partial void OnStatsChanged(DashboardStats? value) => UpdateChart();

    protected override async Task LoadAsync()
    {
        var statsTask = Client.GetStatsAsync();
        var statusTask = Client.GetStatusAsync();
        var recentTask = Client.QueryActivityAsync(new ActivityQuery { Limit = 8 });
        await Task.WhenAll(statsTask, statusTask, recentTask);

        Stats = statsTask.Result;
        ApplyStatus(statusTask.Result);
        Fill(Recent, recentTask.Result);
        FillBars(TopCountries, Stats.TopCountries, code => Countries.GetName(code), useCode: true);
        FillBars(TopUserNames, Stats.TopUserNames, name => name, useCode: false);
        FillBars(TopSources, Stats.TopSources, name => name, useCode: false);
        refreshTimer.Start();
    }

    protected override void OnNavigatedFrom() => refreshTimer.Stop();

    private void ApplyStatus(ServiceStatusDto status)
    {
        Status = status;
        UpdateHero();
    }

    private void UpdateHero()
    {
        var status = Status;
        ServiceState = Client.IsDemo ? ServiceInstallState.Running : WindowsServiceControl.GetState();
        if (!Client.IsConnected || status is null)
        {
            Protection = ProtectionKind.Offline;
            if (ServiceBootstrapper.IsBusy)
            {
                HeroTitle = "Starting TheFirewall service…";
                HeroText = ServiceState == ServiceInstallState.NotInstalled
                    ? "Installing the protection service. Windows may ask for administrator permission."
                    : "This only takes a moment.";
                PrimaryActionText = null;
                return;
            }

            switch (ServiceState)
            {
                case ServiceInstallState.NotInstalled:
                    HeroTitle = "TheFirewall service is not installed";
                    HeroText = "The service watches your logs and bans attackers in the background. Install it to start protecting this computer.";
                    PrimaryActionText = "Install service";
                    break;
                case ServiceInstallState.Starting:
                    HeroTitle = "TheFirewall service is starting…";
                    HeroText = "This only takes a moment.";
                    PrimaryActionText = null;
                    break;
                case ServiceInstallState.Running:
                    HeroTitle = "Connecting to TheFirewall service…";
                    HeroText = "The service is running; the app is establishing a connection.";
                    PrimaryActionText = null;
                    break;
                default:
                    HeroTitle = "TheFirewall service is not running";
                    HeroText = "Failed logins are not being monitored and no one is being banned.";
                    PrimaryActionText = "Start service";
                    break;
            }

            return;
        }

        var sources = status.ActiveSources == 1 ? "1 login monitor" : $"{status.ActiveSources} login monitors";
        if (!status.ProtectionEnabled)
        {
            Protection = ProtectionKind.Paused;
            HeroTitle = "Protection is paused";
            HeroText = $"{sources} still record failed logins, but nobody is banned and existing bans are not enforced.";
            PrimaryActionText = "Resume protection";
        }
        else
        {
            Protection = status.Warnings.Count > 0 ? ProtectionKind.Attention : ProtectionKind.Protected;
            HeroTitle = status.Warnings.Count > 0 ? "You're protected, but something needs attention" : "You're protected";
            HeroText = $"Watching {sources} on {status.MachineName}. {status.BlockedEntryCount.ToString("N0", CultureInfo.CurrentCulture)} addresses and ranges are blocked by {status.FirewallRuleCount} firewall rules.";
            PrimaryActionText = "Pause protection";
        }
    }

    [RelayCommand]
    private async Task PrimaryActionAsync()
    {
        if (Client.IsConnected && Status is not null)
        {
            bool enable = !Status.ProtectionEnabled;
            if (!enable && !UiDialogs.Confirm("Pause protection",
                    "While paused, TheFirewall keeps recording failed logins but does not ban anyone, and existing bans are lifted from the firewall until you resume.\n\nPause protection?"))
            {
                return;
            }

            if (await RunAsync(async () => ApplyStatus(await Client.SetProtectionAsync(enable)), "Unable to change protection"))
            {
                Services.Settings.Invalidate();
            }

            return;
        }

        var result = await ServiceBootstrapper.EnsureRunningAsync();
        if (!result.IsRunning && result.Outcome != EnsureServiceOutcome.Declined)
        {
            UiDialogs.Error("TheFirewall service", result.Message ?? "The service could not be started.");
        }

        UpdateHero();
    }

    [RelayCommand]
    private void OpenActivity() => Services.Navigate?.Invoke("activity");

    [RelayCommand]
    private void OpenBans() => Services.Navigate?.Invoke("bans");

    [RelayCommand]
    private void ShowAddress(string? ip)
    {
        if (!string.IsNullOrEmpty(ip))
        {
            Services.ShowAddressDetails?.Invoke(ip);
        }
    }

    private void OnActivity(object? sender, ActivityEntry entry)
    {
        if (!IsActive)
        {
            return;
        }

        Recent.Insert(0, entry);
        while (Recent.Count > 8)
        {
            Recent.RemoveAt(Recent.Count - 1);
        }

        // Refresh the numbers shortly after a burst of events rather than on every event.
        if (!refreshQueued)
        {
            refreshQueued = true;
            _ = Task.Delay(3000).ContinueWith(_ =>
            {
                refreshQueued = false;
                return RefreshStatsAsync();
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
    }

    private async Task RefreshStatsAsync()
    {
        try
        {
            Stats = await Client.GetStatsAsync();
            FillBars(TopCountries, Stats.TopCountries, code => Countries.GetName(code), useCode: true);
            FillBars(TopUserNames, Stats.TopUserNames, name => name, useCode: false);
            FillBars(TopSources, Stats.TopSources, name => name, useCode: false);
        }
        catch (Exception)
        {
        }
    }

    private void UpdateChart()
    {
        var stats = Stats;
        if (stats is null)
        {
            return;
        }

        var now = DateTime.Now;
        if (ShowMonth)
        {
            ChartValues = stats.DailyFailed;
            ChartLine = null;
            var start = DateTime.UtcNow.Date.AddDays(-(stats.DailyFailed.Count - 1));
            ChartLabels = Enumerable.Range(0, stats.DailyFailed.Count).Select(i => start.AddDays(i).ToString("MMM d", CultureInfo.CurrentCulture)).ToList();
        }
        else
        {
            ChartValues = stats.HourlyFailed;
            ChartLine = stats.HourlyBans;
            var start = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Local).AddHours(-(stats.HourlyFailed.Count - 1));
            ChartLabels = Enumerable.Range(0, stats.HourlyFailed.Count).Select(i => start.AddHours(i).ToString("HH:mm", CultureInfo.CurrentCulture)).ToList();
        }
    }

    private static void Fill<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var item in items)
        {
            target.Add(item);
        }
    }

    private static void FillBars(ObservableCollection<BarItem> target, List<NamedCount> counts, Func<string, string> name, bool useCode)
    {
        long max = counts.Count == 0 ? 1 : Math.Max(1, counts.Max(c => c.Count));
        Fill(target, counts.Take(6).Select(c => new BarItem(name(c.Name), useCode ? c.Name : null, c.Count, (double)c.Count / max)));
    }
}
