using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.ViewModels;

public sealed partial class FeedItem : ObservableObject
{
    private static readonly HashSet<string> DefaultIds = new(ThreatFeed.CreateDefaults().Select(f => f.Id), StringComparer.OrdinalIgnoreCase);

    public FeedItem(FeedInfoDto info)
    {
        Info = info;
        Enabled = info.Feed.Enabled;
    }

    public FeedInfoDto Info { get; }

    public ThreatFeed Feed => Info.Feed;

    public bool IsDefault => DefaultIds.Contains(Feed.Id);

    public string StatusText
    {
        get
        {
            var s = Info.Status;
            if (!Feed.Enabled)
            {
                return "Off";
            }

            if (s.LastError is not null)
            {
                return "Problem: " + s.LastError;
            }

            return s.LastUpdatedUtc is { } updated
                ? $"{s.EntryCount:N0} entries blocked · updated {Converters.RelativeTimeConverter.Format(updated)} · refreshes every {Feed.RefreshHours} h"
                : "Waiting for the first download…";
        }
    }

    public bool HasError => Feed.Enabled && Info.Status.LastError is not null;

    [ObservableProperty]
    public partial bool Enabled { get; set; }
}

public sealed partial class FeedsViewModel(AppServices services) : PageViewModel(services)
{
    public override string Key => "feeds";

    public override string Title => "Threat feeds";

    public override string Glyph => "";

    public ObservableCollection<FeedItem> Feeds { get; } = [];

    protected override async Task LoadAsync()
    {
        var feeds = await Client.GetFeedsAsync();
        Feeds.Clear();
        foreach (var feed in feeds)
        {
            Feeds.Add(new FeedItem(feed));
        }
    }

    [RelayCommand]
    private async Task ToggleAsync(FeedItem? item)
    {
        if (item is null)
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            await RefreshAsync();
            return;
        }

        var enabled = item.Enabled;
        await Services.Settings.SaveAsync(s =>
        {
            var feed = s.ThreatFeeds.FirstOrDefault(f => f.Id == item.Feed.Id);
            if (feed is not null)
            {
                feed.Enabled = enabled;
            }
        });
        await Task.Delay(1500);
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task AddAsync()
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var dialog = new FeedDialog { Owner = System.Windows.Application.Current.MainWindow };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var feed = dialog.Result;
        if (await Services.Settings.SaveAsync(s => s.ThreatFeeds.Add(feed)))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task DeleteAsync(FeedItem? item)
    {
        if (item is null || !UiDialogs.Confirm("Remove feed", $"Remove \"{item.Feed.Name}\"? Addresses from this list are unblocked.", destructive: true))
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        if (await Services.Settings.SaveAsync(s => s.ThreatFeeds.RemoveAll(f => f.Id == item.Feed.Id)))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task RefreshNowAsync()
    {
        IsLoading = true;
        try
        {
            if (await RunAsync(Client.RefreshFeedsAsync, "Unable to refresh feeds"))
            {
                await RefreshAsync();
            }
        }
        finally
        {
            IsLoading = false;
        }
    }
}
