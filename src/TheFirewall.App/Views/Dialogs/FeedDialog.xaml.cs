using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using TheFirewall.Core.Configuration;

namespace TheFirewall.App.Views.Dialogs;

public partial class FeedDialog : Window
{
    public FeedDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => NameBox.Focus();
    }

    public ThreatFeed Result { get; private set; } = new();

    private void OnChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded)
        {
            return;
        }

        string? error = null;
        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            error = string.Empty;
        }
        else if (!Uri.TryCreate(UrlBox.Text.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            error = UrlBox.Text.Length == 0 ? string.Empty : "Enter a full http:// or https:// URL.";
        }
        else if (!int.TryParse(RefreshBox.Text, NumberStyles.None, CultureInfo.CurrentCulture, out int hours) || hours < 1)
        {
            error = "Refresh interval must be a whole number of hours.";
        }
        else if (!int.TryParse(MaxBox.Text, NumberStyles.None, CultureInfo.CurrentCulture, out int max) || max < 1)
        {
            error = "Maximum entries must be a positive number.";
        }

        ErrorText.Text = error ?? string.Empty;
        OkButton.IsEnabled = error is null;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        Result = new ThreatFeed
        {
            Name = NameBox.Text.Trim(),
            Url = UrlBox.Text.Trim(),
            Enabled = true,
            RefreshHours = int.Parse(RefreshBox.Text, CultureInfo.CurrentCulture),
            MaxEntries = int.Parse(MaxBox.Text, CultureInfo.CurrentCulture),
        };
        DialogResult = true;
    }
}
