using System.Windows;
using System.Windows.Controls;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Networking;

namespace TheFirewall.App.Views.Dialogs;

public partial class AddressDialog : Window
{
    public AddressDialog(bool whitelist)
    {
        InitializeComponent();
        Title = whitelist ? "Add to whitelist" : "Add to blacklist";
        TitleText.Text = whitelist ? "Never ban these addresses" : "Always block these addresses";
        DescriptionText.Text = whitelist
            ? "Whitelisted addresses are never banned, even after many failed logins. Banned addresses you add here are released immediately."
            : "Blacklisted addresses are blocked on every port, all the time.";
        Loaded += (_, _) => AddressesBox.Focus();
    }

    public List<AddressEntry> Entries { get; } = [];

    private IEnumerable<string> Lines => AddressesBox.Text.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private void OnChanged(object sender, TextChangedEventArgs e)
    {
        var lines = Lines.ToList();
        var invalid = lines.Where(l => !IPAddressRange.TryParse(l, out _)).ToList();
        OkButton.IsEnabled = lines.Count > 0 && invalid.Count == 0;
        ErrorText.Text = invalid.Count == 0 ? string.Empty : "Not valid: " + string.Join(", ", invalid.Take(5)) + (invalid.Count > 5 ? "…" : string.Empty);
        ErrorText.Visibility = invalid.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var comment = CommentBox.Text.Trim();
        foreach (var line in Lines.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            Entries.Add(new AddressEntry { Value = line, Comment = comment, AddedUtc = DateTimeOffset.UtcNow });
        }

        DialogResult = true;
    }
}
