using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Data;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.ViewModels;

public sealed partial class BansViewModel : PageViewModel
{
    private bool reloadQueued;

    public BansViewModel(AppServices services) : base(services)
    {
        BannedView = CollectionViewSource.GetDefaultView(Banned);
        BannedView.Filter = Matches;
        WatchedView = CollectionViewSource.GetDefaultView(Watched);
        WatchedView.Filter = Matches;
        Client.ActivityReceived += OnActivity;
    }

    public override string Key => "bans";

    public override string Title => "Banned addresses";

    public override string Glyph => "";

    public ObservableCollection<IPRecord> Banned { get; } = [];

    public ObservableCollection<IPRecord> Watched { get; } = [];

    public ICollectionView BannedView { get; }

    public ICollectionView WatchedView { get; }

    [ObservableProperty]
    public partial string? Search { get; set; }

    [ObservableProperty]
    public partial int SelectedTab { get; set; }

    partial void OnSearchChanged(string? value)
    {
        BannedView.Refresh();
        WatchedView.Refresh();
    }

    private bool Matches(object item)
    {
        if (string.IsNullOrWhiteSpace(Search) || item is not IPRecord r)
        {
            return true;
        }

        var s = Search.Trim();
        return r.IPAddress.Contains(s, StringComparison.OrdinalIgnoreCase) ||
               (r.Source?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (r.UserNames?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (r.BanReason?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (r.Country is not null && (r.Country.Equals(s, StringComparison.OrdinalIgnoreCase) ||
                                          Countries.GetName(r.Country).Contains(s, StringComparison.OrdinalIgnoreCase)));
    }

    protected override async Task LoadAsync()
    {
        var bans = Client.GetBansAsync();
        var watched = Client.GetWatchedAsync();
        await Task.WhenAll(bans, watched);
        Replace(Banned, bans.Result);
        Replace(Watched, watched.Result);
    }

    private static void Replace(ObservableCollection<IPRecord> target, List<IPRecord> items)
    {
        target.Clear();
        foreach (var item in items)
        {
            target.Add(item);
        }
    }

    private void OnActivity(object? sender, ActivityEntry entry)
    {
        if (!IsActive || entry.Type is not (ActivityType.Banned or ActivityType.Unbanned or ActivityType.FailedLogin) || reloadQueued)
        {
            return;
        }

        reloadQueued = true;
        _ = Task.Delay(1500).ContinueWith(_ =>
        {
            reloadQueued = false;
            return RefreshAsync();
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    [RelayCommand]
    private async Task BanAddressAsync()
    {
        var dialog = new BanDialog { Owner = System.Windows.Application.Current.MainWindow };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        if (await RunAsync(() => Client.BanAsync(dialog.Request), "Unable to ban the address"))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task UnbanAsync(IList? selection)
    {
        var ips = Selected(selection);
        if (ips.Count == 0 || !UiDialogs.Confirm("Unban", ips.Count == 1 ? $"Unban {ips[0]}?" : $"Unban {ips.Count} addresses?"))
        {
            return;
        }

        if (await RunAsync(() => Client.UnbanAsync(new UnbanRequest { IPAddresses = ips }), "Unable to unban"))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task UnbanAndWhitelistAsync(IList? selection)
    {
        var ips = Selected(selection);
        if (ips.Count == 0 || !UiDialogs.Confirm("Unban and whitelist",
                (ips.Count == 1 ? ips[0] : $"{ips.Count} addresses") + " will be unbanned and added to the whitelist, so they are never banned again. Continue?"))
        {
            return;
        }

        if (await RunAsync(() => Client.UnbanAsync(new UnbanRequest { IPAddresses = ips, AddToWhitelist = true }), "Unable to whitelist"))
        {
            Services.Settings.Invalidate();
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task BanSelectedAsync(IList? selection)
    {
        var ips = Selected(selection);
        if (ips.Count == 0 || !UiDialogs.Confirm("Ban now", ips.Count == 1 ? $"Ban {ips[0]} now?" : $"Ban {ips.Count} addresses now?"))
        {
            return;
        }

        await RunAsync(async () =>
        {
            foreach (var ip in ips)
            {
                await Client.BanAsync(new BanRequest { IPAddress = ip, Reason = "Banned manually from the watch list" });
            }
        }, "Unable to ban");
        await RefreshAsync();
    }

    /// <summary>Bans the selected addresses permanently (also turns existing temporary bans into permanent ones).</summary>
    [RelayCommand]
    private async Task BanForeverAsync(IList? selection)
    {
        var ips = Selected(selection);
        if (ips.Count == 0)
        {
            UiDialogs.Info("Ban forever", "Select one or more addresses first.");
            return;
        }

        if (!UiDialogs.Confirm("Ban forever",
                (ips.Count == 1 ? ips[0] : $"{ips.Count} addresses") + " will be blocked permanently, until you unban them yourself. Continue?"))
        {
            return;
        }

        await RunAsync(async () =>
        {
            foreach (var ip in ips)
            {
                await Client.BanAsync(new BanRequest { IPAddress = ip, DurationMinutes = 0, Reason = "Banned forever by an administrator" });
            }
        }, "Unable to ban");
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task ClearAllAsync()
    {
        if (Banned.Count == 0 || !UiDialogs.Confirm("Unban everyone", $"Remove all {Banned.Count:N0} bans? Attackers will be able to try again.", destructive: true))
        {
            return;
        }

        if (await RunAsync(Client.ClearBansAsync, "Unable to clear bans"))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private void ShowDetails(IPRecord? record)
    {
        if (record is not null)
        {
            Services.ShowAddressDetails?.Invoke(record.IPAddress);
        }
    }

    [RelayCommand]
    private void Export()
    {
        var watching = SelectedTab == 1;
        var dialog = new SaveFileDialog
        {
            Title = watching ? "Export watched addresses" : "Export banned addresses",
            FileName = $"thefirewall-{(watching ? "watched" : "bans")}-{DateTime.Now:yyyyMMdd-HHmm}.csv",
            Filter = "CSV file (*.csv)|*.csv",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var csv = new StringBuilder("IP address,Country,Source,User names,Failed attempts,Banned at,Ban ends,Reason\r\n");
        foreach (var r in (watching ? WatchedView : BannedView).Cast<IPRecord>())
        {
            csv.Append(Csv.Row(r.IPAddress, r.Country, r.Source, r.UserNames, r.FailedCount.ToString(CultureInfo.InvariantCulture),
                r.BanStartUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
                r.IsBanned ? (r.BanEndUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "Forever") : string.Empty,
                r.BanReason));
        }

        File.WriteAllText(dialog.FileName, csv.ToString(), Encoding.UTF8);
    }

    private static List<string> Selected(IList? selection) =>
        selection?.OfType<IPRecord>().Select(r => r.IPAddress).ToList() ?? [];
}
