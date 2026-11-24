using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;

namespace TheFirewall.App.ViewModels;

public sealed partial class CountryItem(string code, string name, string region, int rangeCount, bool selected) : ObservableObject
{
    public string Code { get; } = code;

    public string Name { get; } = name;

    public string Region { get; } = region;

    public int RangeCount { get; } = rangeCount;

    [ObservableProperty]
    public partial bool IsSelected { get; set; } = selected;
}

public sealed partial class CountriesViewModel : PageViewModel
{
    private bool loading;

    public CountriesViewModel(AppServices services) : base(services)
    {
        View = CollectionViewSource.GetDefaultView(Countries);
        View.Filter = o => o is CountryItem c &&
                           (Region is null or "All regions" || c.Region == Region) &&
                           (!ShowSelectedOnly || c.IsSelected) &&
                           (string.IsNullOrWhiteSpace(Search) || c.Name.Contains(Search.Trim(), StringComparison.CurrentCultureIgnoreCase) ||
                            c.Code.Equals(Search.Trim(), StringComparison.OrdinalIgnoreCase));
        Region = "All regions";
    }

    public override string Key => "countries";

    public override string Title => "Countries";

    public override string Glyph => "\uE909";

    public ObservableCollection<CountryItem> Countries { get; } = [];

    public ICollectionView View { get; }

    public IReadOnlyList<string> Regions { get; } = ["All regions", "Africa", "Americas", "Asia", "Europe", "Oceania", "Other"];

    [ObservableProperty]
    public partial CountryBlockingMode Mode { get; set; }

    [ObservableProperty]
    public partial string Ports { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool AutoUpdate { get; set; }

    [ObservableProperty]
    public partial string? Search { get; set; }

    [ObservableProperty]
    public partial string? Region { get; set; }

    [ObservableProperty]
    public partial bool ShowSelectedOnly { get; set; }

    [ObservableProperty]
    public partial bool IsDirty { get; set; }

    [ObservableProperty]
    public partial string DatabaseText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SelectionSummary { get; set; } = string.Empty;

    public bool IsModeOff => Mode == CountryBlockingMode.Off;

    partial void OnModeChanged(CountryBlockingMode value)
    {
        MarkDirty();
        OnPropertyChanged(nameof(IsModeOff));
        UpdateSummary();
    }

    partial void OnPortsChanged(string value) => MarkDirty();

    partial void OnAutoUpdateChanged(bool value) => MarkDirty();

    partial void OnSearchChanged(string? value) => View.Refresh();

    partial void OnRegionChanged(string? value) => View.Refresh();

    partial void OnShowSelectedOnlyChanged(bool value) => View.Refresh();

    private void MarkDirty()
    {
        if (!loading)
        {
            IsDirty = true;
        }
    }

    protected override async Task LoadAsync()
    {
        loading = true;
        try
        {
            var settingsTask = Services.Settings.LoadAsync(force: true);
            var countriesTask = Client.GetCountriesAsync();
            var statusTask = Client.GetStatusAsync();
            await Task.WhenAll(settingsTask, countriesTask, statusTask);

            var settings = settingsTask.Result.CountryBlocking;
            Mode = settings.Mode;
            Ports = settings.Ports;
            AutoUpdate = settings.AutoUpdateDatabase;
            var selected = new HashSet<string>(settings.Countries, StringComparer.OrdinalIgnoreCase);

            foreach (var item in Countries)
            {
                item.PropertyChanged -= OnCountryChanged;
            }

            Countries.Clear();
            foreach (var c in countriesTask.Result)
            {
                var item = new CountryItem(c.Code, c.Name, c.Region, c.RangeCount, selected.Contains(c.Code));
                item.PropertyChanged += OnCountryChanged;
                Countries.Add(item);
            }

            var status = statusTask.Result;
            DatabaseText = status.GeoDatabaseAvailable
                ? $"Country database: {status.GeoDatabaseVersion} edition"
                : status.GeoDatabaseError ?? "The country database has not been downloaded yet. It is fetched automatically when the service has internet access.";
            IsDirty = false;
            UpdateSummary();
        }
        finally
        {
            loading = false;
        }
    }

    private void OnCountryChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CountryItem.IsSelected))
        {
            MarkDirty();
            UpdateSummary();
        }
    }

    private void UpdateSummary()
    {
        var selected = Countries.Where(c => c.IsSelected).Select(c => c.Name).ToList();
        SelectionSummary = selected.Count switch
        {
            0 => Mode == CountryBlockingMode.AllowOnlySelected ? "Select the countries that may connect." : "No countries selected.",
            <= 6 => string.Join(", ", selected),
            _ => string.Join(", ", selected.Take(6)) + $" and {selected.Count - 6} more",
        };
    }

    [RelayCommand]
    private void ClearSelection()
    {
        foreach (var item in Countries.Where(c => c.IsSelected))
        {
            item.IsSelected = false;
        }
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var codes = Countries.Where(c => c.IsSelected).Select(c => c.Code).ToList();
        if (Mode == CountryBlockingMode.AllowOnlySelected)
        {
            if (codes.Count == 0)
            {
                UiDialogs.Error("Choose at least one country", "In \"allow only\" mode at least one country must be selected, otherwise every address outside your local network would be blocked.");
                return;
            }

            if (!UiDialogs.Confirm("Allow only these countries",
                    $"Connections from every country except {SelectionSummary} will be blocked{(string.IsNullOrWhiteSpace(Ports) ? string.Empty : $" on port(s) {Ports}")}.\n\n" +
                    "Make sure the country you connect from is selected (or that your address is on the whitelist) so you do not lock yourself out.\n\nApply?"))
            {
                return;
            }
        }

        if (!FirewallPlanner.TryNormalizePorts(Ports, out _, out var portError))
        {
            UiDialogs.Error("Invalid ports", portError ?? "Invalid port list.");
            return;
        }

        var mode = Mode;
        var ports = Ports;
        var auto = AutoUpdate;
        if (await Services.Settings.SaveAsync(s =>
            {
                s.CountryBlocking.Mode = mode;
                s.CountryBlocking.Countries = codes;
                s.CountryBlocking.Ports = ports;
                s.CountryBlocking.AutoUpdateDatabase = auto;
            }))
        {
            IsDirty = false;
        }
    }

    [RelayCommand]
    private Task DiscardAsync() => RefreshAsync();

    [RelayCommand]
    private async Task UpdateDatabaseAsync()
    {
        if (await RunAsync(Client.UpdateGeoAsync, "Unable to update the country database"))
        {
            await RefreshAsync();
        }
    }
}
