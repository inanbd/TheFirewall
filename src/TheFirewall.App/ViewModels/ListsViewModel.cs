using System.Collections;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Configuration;

namespace TheFirewall.App.ViewModels;

/// <summary>Whitelist ("never ban") and blacklist ("always block").</summary>
public sealed partial class ListsViewModel(AppServices services) : PageViewModel(services)
{
    public override string Key => "lists";

    public override string Title => "Allow & block lists";

    public override string Glyph => "";

    public ObservableCollection<AddressEntry> Whitelist { get; } = [];

    public ObservableCollection<AddressEntry> Blacklist { get; } = [];

    [ObservableProperty]
    public partial string WhitelistRegex { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string BlacklistRegex { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int SelectedTab { get; set; }

    protected override async Task LoadAsync()
    {
        var settings = await Services.Settings.LoadAsync(force: true);
        Fill(Whitelist, settings.Whitelist);
        Fill(Blacklist, settings.Blacklist);
        WhitelistRegex = settings.WhitelistRegex;
        BlacklistRegex = settings.BlacklistRegex;
    }

    private static void Fill(ObservableCollection<AddressEntry> target, IEnumerable<AddressEntry> items)
    {
        target.Clear();
        foreach (var item in items.OrderByDescending(i => i.AddedUtc))
        {
            target.Add(item);
        }
    }

    [RelayCommand]
    private Task AddWhitelistAsync() => AddAsync(whitelist: true);

    [RelayCommand]
    private Task AddBlacklistAsync() => AddAsync(whitelist: false);

    private async Task AddAsync(bool whitelist)
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var dialog = new AddressDialog(whitelist) { Owner = System.Windows.Application.Current.MainWindow };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var entries = dialog.Entries;
        if (await Services.Settings.SaveAsync(s =>
            {
                var list = whitelist ? s.Whitelist : s.Blacklist;
                foreach (var entry in entries.Where(e => !list.Any(x => string.Equals(x.Value, e.Value, StringComparison.OrdinalIgnoreCase))))
                {
                    list.Add(entry);
                }
            }))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private Task RemoveWhitelistAsync(IList? selection) => RemoveAsync(selection, whitelist: true);

    [RelayCommand]
    private Task RemoveBlacklistAsync(IList? selection) => RemoveAsync(selection, whitelist: false);

    private async Task RemoveAsync(IList? selection, bool whitelist)
    {
        var values = selection?.OfType<AddressEntry>().Select(e => e.Value).ToList() ?? [];
        if (values.Count == 0)
        {
            return;
        }

        if (!UiDialogs.Confirm("Remove", values.Count == 1 ? $"Remove {values[0]} from the {(whitelist ? "whitelist" : "blacklist")}?" : $"Remove {values.Count} entries?"))
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        if (await Services.Settings.SaveAsync(s => (whitelist ? s.Whitelist : s.Blacklist).RemoveAll(e => values.Contains(e.Value))))
        {
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task SavePatternsAsync()
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var white = WhitelistRegex ?? string.Empty;
        var black = BlacklistRegex ?? string.Empty;
        if (await Services.Settings.SaveAsync(s =>
            {
                s.WhitelistRegex = white;
                s.BlacklistRegex = black;
            }))
        {
            UiDialogs.Info("Patterns saved", "The patterns are now in effect.");
        }
    }
}
