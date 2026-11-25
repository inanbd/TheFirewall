using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using TheFirewall.App.Services;
using TheFirewall.Core.Data;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.ViewModels;

public enum ActivityFilter
{
    All,
    FailedLogins,
    Bans,
    SignIns,
    System,
}

public sealed partial class ActivityViewModel : PageViewModel
{
    private const int MaxItems = 2000;

    public ActivityViewModel(AppServices services) : base(services)
    {
        Client.ActivityReceived += OnActivity;
        Client.ActivityUpdated += (_, entry) => ActivityListUpdates.Replace(Items, entry);
        Client.ActivityRemoved += (_, ids) => ActivityListUpdates.Remove(Items, ids);
    }

    public override string Key => "activity";

    public override string Title => "Live activity";

    public override string Glyph => "";

    public ObservableCollection<ActivityEntry> Items { get; } = [];

    public IReadOnlyList<KeyValuePair<ActivityFilter, string>> Filters { get; } =
    [
        new(ActivityFilter.All, "Everything"),
        new(ActivityFilter.FailedLogins, "Failed logins"),
        new(ActivityFilter.Bans, "Bans and unbans"),
        new(ActivityFilter.SignIns, "Successful sign-ins"),
        new(ActivityFilter.System, "Service messages"),
    ];

    [ObservableProperty]
    public partial ActivityFilter Filter { get; set; }

    [ObservableProperty]
    public partial string? Search { get; set; }

    [ObservableProperty]
    public partial bool IsLive { get; set; } = true;

    [ObservableProperty]
    public partial ActivityEntry? Selected { get; set; }

    [ObservableProperty]
    public partial int NewWhilePaused { get; set; }

    partial void OnFilterChanged(ActivityFilter value) => _ = RefreshAsync();

    partial void OnSearchChanged(string? value) => _ = RefreshAsync();

    partial void OnIsLiveChanged(bool value)
    {
        if (value && NewWhilePaused > 0)
        {
            NewWhilePaused = 0;
            _ = RefreshAsync();
        }
    }

    protected override async Task LoadAsync()
    {
        var items = await Client.QueryActivityAsync(BuildQuery(null));
        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }
    }

    [RelayCommand]
    private Task ApplySearchAsync() => RefreshAsync();

    [RelayCommand]
    private async Task LoadMoreAsync()
    {
        if (Items.Count == 0)
        {
            return;
        }

        try
        {
            var more = await Client.QueryActivityAsync(BuildQuery(Items[^1].Id));
            foreach (var item in more)
            {
                Items.Add(item);
            }
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Unable to load more activity");
        }
    }

    private ActivityQuery BuildQuery(long? beforeId) => new()
    {
        Limit = 300,
        BeforeId = beforeId,
        Search = string.IsNullOrWhiteSpace(Search) ? null : Search.Trim(),
        Types = TypesFor(Filter),
    };

    private static List<ActivityType>? TypesFor(ActivityFilter filter) => filter switch
    {
        ActivityFilter.FailedLogins => [ActivityType.FailedLogin, ActivityType.Ignored],
        ActivityFilter.Bans => [ActivityType.Banned, ActivityType.Unbanned],
        ActivityFilter.SignIns => [ActivityType.SuccessfulLogin],
        ActivityFilter.System => [ActivityType.Info, ActivityType.Warning],
        _ => null,
    };

    private void OnActivity(object? sender, ActivityEntry entry)
    {
        var types = TypesFor(Filter);
        if (types is not null && !types.Contains(entry.Type))
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(Search))
        {
            var s = Search.Trim();
            bool match = (entry.IPAddress?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                         (entry.UserName?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                         (entry.Source?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                         (entry.Message?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                         (entry.Country?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                         Countries.Matches(entry.Country, s);
            if (!match)
            {
                return;
            }
        }

        if (!IsLive)
        {
            NewWhilePaused++;
            return;
        }

        Items.Insert(0, entry);
        while (Items.Count > MaxItems)
        {
            Items.RemoveAt(Items.Count - 1);
        }
    }

    [RelayCommand]
    private void CopyAddress(ActivityEntry? entry)
    {
        var ip = (entry ?? Selected)?.IPAddress;
        if (!string.IsNullOrEmpty(ip))
        {
            Clipboard.SetText(ip);
        }
    }

    [RelayCommand]
    private void ShowDetails(ActivityEntry? entry)
    {
        var ip = (entry ?? Selected)?.IPAddress;
        if (!string.IsNullOrEmpty(ip))
        {
            Services.ShowAddressDetails?.Invoke(ip);
        }
    }

    [RelayCommand]
    private async Task BanAsync(ActivityEntry? entry)
    {
        var ip = (entry ?? Selected)?.IPAddress;
        if (string.IsNullOrEmpty(ip) || !UiDialogs.Confirm("Ban address", $"Ban {ip} now using the normal ban duration?"))
        {
            return;
        }

        await RunAsync(() => Client.BanAsync(new BanRequest { IPAddress = ip, Reason = "Banned from the activity feed" }), "Unable to ban the address");
    }

    [RelayCommand]
    private async Task BanForeverAsync(ActivityEntry? entry)
    {
        var ip = (entry ?? Selected)?.IPAddress;
        if (string.IsNullOrEmpty(ip) || !UiDialogs.Confirm("Ban forever", $"Block {ip} permanently, until you unban it yourself?"))
        {
            return;
        }

        await RunAsync(() => Client.BanAsync(new BanRequest { IPAddress = ip, DurationMinutes = 0, Reason = "Banned forever from the activity feed" }),
            "Unable to ban the address");
    }

    /// <summary>Blocks every address from the country of the entry (or the selected row).</summary>
    [RelayCommand]
    private async Task BlockCountryAsync(ActivityEntry? entry) => await CountryBlocker.BlockAsync(Services, [(entry ?? Selected)?.Country]);

    [RelayCommand]
    private async Task WhitelistAsync(ActivityEntry? entry)
    {
        var ip = (entry ?? Selected)?.IPAddress;
        if (string.IsNullOrEmpty(ip) || !UiDialogs.Confirm("Never ban this address",
                $"Add {ip} to the whitelist? It will be unbanned if needed and never banned again."))
        {
            return;
        }

        await RunAsync(() => Client.UnbanAsync(new UnbanRequest { IPAddresses = [ip], AddToWhitelist = true, Comment = "Added from the activity feed" }),
            "Unable to whitelist the address");
        Services.Settings.Invalidate();
    }

    [RelayCommand]
    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export activity",
            FileName = $"thefirewall-activity-{DateTime.Now:yyyyMMdd-HHmm}.csv",
            Filter = "CSV file (*.csv)|*.csv",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var csv = new StringBuilder("Time,Type,IP address,Country,Source,User name,Details\r\n");
        foreach (var item in Items)
        {
            csv.Append(Csv.Row(item.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), item.Type.ToString(),
                item.IPAddress, item.Country, item.Source, item.UserName, item.Message));
        }

        File.WriteAllText(dialog.FileName, csv.ToString(), Encoding.UTF8);
    }
}

internal static class ActivityListUpdates
{
    public static void Replace(System.Collections.ObjectModel.ObservableCollection<ActivityEntry> items, ActivityEntry entry)
    {
        for (int i = 0; i < items.Count; i++)
        {
            if (items[i].Id == entry.Id)
            {
                items[i] = entry;
                return;
            }
        }
    }

    public static void Remove(System.Collections.ObjectModel.ObservableCollection<ActivityEntry> items, IReadOnlyList<long> ids)
    {
        var set = ids.ToHashSet();
        for (int i = items.Count - 1; i >= 0; i--)
        {
            if (set.Contains(items[i].Id))
            {
                items.RemoveAt(i);
            }
        }
    }
}

internal static class Csv
{
    public static string Row(params string?[] values) =>
        string.Join(',', values.Select(v => "\"" + (v ?? string.Empty).Replace("\"", "\"\"", StringComparison.Ordinal) + "\"")) + "\r\n";
}
