using System.Windows;
using TheFirewall.App.Converters;
using TheFirewall.App.Services;
using TheFirewall.App.ViewModels;
using TheFirewall.Core.Engine;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.Views.Dialogs;

public partial class AddressDetailsWindow : Window
{
    private readonly AppServices services;
    private readonly string address;
    private string? country;

    public AddressDetailsWindow(AppServices services, string address)
    {
        this.services = services;
        this.address = address;
        InitializeComponent();
        Title = $"Address {address}";
        AddressText.Text = address;
        Loaded += async (_, _) => await LoadAsync();
    }

    private async Task LoadAsync()
    {
        try
        {
            var result = await services.Client.LookupAsync(address);
            country = result.IsInternal ? null : result.Country;
            Flag.Code = country;
            CountryText.Text = result.IsInternal ? "Local network address" : Countries.GetName(result.Country);
            BlockCountryButton.IsEnabled = Countries.IsValidCode(country);
            BlockCountryButton.ToolTip = Countries.IsValidCode(country) ? $"Block every address from {Countries.GetName(country)}" : null;
            ActivityGrid.ItemsSource = result.RecentActivity;
            EmptyText.Visibility = result.RecentActivity.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            var record = result.Record;
            string title, detail;
            if (result.IsWhitelisted)
            {
                title = "Whitelisted - never banned";
                detail = "This address matches an entry on your whitelist.";
                StatusBar.Style = (Style)FindResource("SuccessBar");
            }
            else if (record is { IsBanned: true })
            {
                title = record.BanEndUtc is { } end ? $"Banned until {end.ToLocalTime():g} ({RelativeTimeConverter.FormatFuture(end)})" : "Banned forever";
                detail = $"{record.BanReason}. Ban #{record.BanLevel}. User names tried: {record.UserNames ?? "none recorded"}.";
                StatusBar.Style = (Style)FindResource("ErrorBar");
            }
            else if (record is { FailedCount: > 0 })
            {
                title = $"Being watched: {record.FailedCount} failed login{(record.FailedCount == 1 ? string.Empty : "s")}";
                detail = $"Last attempt {RelativeTimeConverter.Format(record.LastFailedUtc ?? DateTimeOffset.UtcNow)} via {record.Source}. User names: {record.UserNames ?? "none recorded"}.";
                StatusBar.Style = (Style)FindResource("WarningBar");
            }
            else if (result.IsBlacklisted)
            {
                title = "On the blacklist - always blocked";
                detail = "This address matches an entry on your blacklist.";
                StatusBar.Style = (Style)FindResource("ErrorBar");
            }
            else
            {
                title = "Not banned";
                detail = record?.BanLevel > 0 ? $"Banned {record.BanLevel} time(s) before." : "No failed logins on record.";
            }

            StatusTitle.Text = title;
            StatusDetail.Text = detail;
            BanButton.IsEnabled = record is not { IsBanned: true } && !result.IsWhitelisted;
            UnbanButton.IsEnabled = record is { IsBanned: true };
            BanForeverButton.IsEnabled = !result.IsWhitelisted && !(record is { IsBanned: true, BanEndUtc: null });
            WhitelistButton.IsEnabled = !result.IsWhitelisted;
        }
        catch (Exception ex)
        {
            StatusTitle.Text = "Details are not available";
            StatusDetail.Text = ex.Message;
        }
    }

    private async void OnBan(object sender, RoutedEventArgs e)
    {
        if (!Confirm($"Ban {address} using the normal ban duration?"))
        {
            return;
        }

        await RunAsync(() => services.Client.BanAsync(new BanRequest { IPAddress = address, Reason = "Banned manually" }));
    }

    private async void OnBanForever(object sender, RoutedEventArgs e)
    {
        if (!Confirm($"Block {address} permanently, until you unban it yourself?"))
        {
            return;
        }

        await RunAsync(() => services.Client.BanAsync(new BanRequest { IPAddress = address, DurationMinutes = 0, Reason = "Banned forever by an administrator" }));
    }

    private async void OnUnban(object sender, RoutedEventArgs e) =>
        await RunAsync(() => services.Client.UnbanAsync(new UnbanRequest { IPAddresses = [address] }));

    private async void OnWhitelist(object sender, RoutedEventArgs e)
    {
        if (!Confirm($"Add {address} to the whitelist? It is unbanned if needed and never banned again."))
        {
            return;
        }

        await RunAsync(() => services.Client.UnbanAsync(new UnbanRequest { IPAddresses = [address], AddToWhitelist = true }));
        services.Settings.Invalidate();
    }

    private async void OnBlockCountry(object sender, RoutedEventArgs e)
    {
        try
        {
            await CountryBlocker.BlockAsync(services, [country]);
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Unable to block the country");
        }
    }

    private bool Confirm(string message) => MessageBox.Show(this, message, Title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

    private async Task RunAsync(Func<Task> action)
    {
        if (!services.Client.CanMakeChanges)
        {
            UiDialogs.RequestElevation();
            return;
        }

        try
        {
            await action();
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "The change could not be made");
        }

        await LoadAsync();
    }

    private void OnCopy(object sender, RoutedEventArgs e) => Clipboard.SetText(address);

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
