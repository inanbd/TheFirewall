using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using TheFirewall.Core.Data;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Monitoring;
using TheFirewall.Core.Ports;

namespace TheFirewall.App.Converters;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = value is true;
        if (Invert || parameter is "invert")
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is Visibility.Visible;
}

public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool visible = value is not null && (value is not string s || s.Length > 0);
        return visible ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Visible when the number/collection count is greater than zero (or zero when Invert).</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        long count = value switch
        {
            int i => i,
            long l => l,
            System.Collections.ICollection c => c.Count,
            _ => 0,
        };
        return (count > 0) ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Binds radio buttons to an enum: ConverterParameter is the enum member name.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not null && parameter is string name && string.Equals(value.ToString(), name, StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true && parameter is string name ? Enum.Parse(targetType, name) : Binding.DoNothing;
}

public sealed class NumberConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        int i => i.ToString("N0", culture),
        long l => l.ToString("N0", culture),
        double d => d.ToString("N0", culture),
        _ => "0",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class RelativeTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is DateTimeOffset time ? Format(time) : string.Empty;

    public static string Format(DateTimeOffset time)
    {
        var delta = DateTimeOffset.UtcNow - time.ToUniversalTime();
        if (delta < TimeSpan.Zero)
        {
            return FormatFuture(time);
        }

        if (delta.TotalSeconds < 45)
        {
            return "just now";
        }

        if (delta.TotalMinutes < 60)
        {
            return $"{Math.Max(1, (int)delta.TotalMinutes)} min ago";
        }

        if (delta.TotalHours < 24)
        {
            return $"{(int)delta.TotalHours} h ago";
        }

        var local = time.ToLocalTime();
        return delta.TotalDays < 7 ? local.ToString("ddd HH:mm", CultureInfo.CurrentCulture) : local.ToString("d", CultureInfo.CurrentCulture);
    }

    public static string FormatFuture(DateTimeOffset time)
    {
        var delta = time.ToUniversalTime() - DateTimeOffset.UtcNow;
        if (delta.TotalMinutes < 1)
        {
            return "in under a minute";
        }

        if (delta.TotalMinutes < 60)
        {
            return $"in {(int)Math.Ceiling(delta.TotalMinutes)} min";
        }

        if (delta.TotalHours < 48)
        {
            return $"in {(int)Math.Round(delta.TotalHours)} h";
        }

        return $"in {(int)Math.Round(delta.TotalDays)} days";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTimeOffset time ? time.ToLocalTime().ToString(parameter as string ?? "G", CultureInfo.CurrentCulture) : string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Formats a ban end time: "Forever", "in 3 h"...</summary>
public sealed class ExpiryConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTimeOffset end ? RelativeTimeConverter.FormatFuture(end) : "Forever";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>
/// Country code to its English name ("Unknown location" when empty). A ConverterParameter such as "Block {0}" formats the
/// name into a sentence, with "this country" standing in for an unknown one.
/// </summary>
public sealed class CountryNameConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool known = value is string code && code.Length > 0;
        if (parameter is string format)
        {
            return string.Format(CultureInfo.CurrentCulture, format, known ? Countries.GetName((string)value!) : "this country");
        }

        return known ? Countries.GetName((string)value!) : "Unknown location";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Country code to its flag image (null when the code is empty or no flag is available).</summary>
public sealed class CountryFlagConverter : IValueConverter
{
    private static readonly ConcurrentDictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string code ? Get(code) : null;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();

    public static ImageSource? Get(string? code) =>
        code is { Length: 2 } && code.All(char.IsAsciiLetter) ? Cache.GetOrAdd(code, Load) : null;

    private static ImageSource? Load(string code)
    {
        try
        {
            var uri = new Uri($"pack://application:,,,/TheFirewall;component/Assets/Flags/{code.ToLowerInvariant()}.png", UriKind.Absolute);
            using var stream = Application.GetResourceStream(uri)?.Stream;
            if (stream is null)
            {
                return null;
            }

            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.StreamSource = stream;
            image.EndInit();
            image.Freeze();
            return image;
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or InvalidOperationException or UriFormatException)
        {
            return null;
        }
    }
}

internal static class ThemeBrushes
{
    public static Brush Get(string key, Color fallback) =>
        Application.Current?.TryFindResource(key) as Brush ?? new SolidColorBrush(fallback);

    public static Brush Danger => Get("SystemFillColorCriticalBrush", Color.FromRgb(0xC4, 0x2B, 0x1C));

    public static Brush Warning => Get("SystemFillColorCautionBrush", Color.FromRgb(0x9D, 0x5D, 0x00));

    public static Brush Success => Get("SystemFillColorSuccessBrush", Color.FromRgb(0x0F, 0x7B, 0x0F));

    public static Brush Accent => Get("AccentFillColorDefaultBrush", Color.FromRgb(0x00, 0x5F, 0xB8));

    public static Brush Neutral => Get("TextFillColorSecondaryBrush", Color.FromRgb(0x60, 0x60, 0x60));
}

/// <summary>Colour for how reachable a port is: open (amber), some addresses (blue), blocked (green), local only (grey).</summary>
public sealed class PortExposureToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        PortExposure.Open => ThemeBrushes.Warning,
        PortExposure.OpenToSome => ThemeBrushes.Accent,
        PortExposure.Blocked => ThemeBrushes.Success,
        _ => ThemeBrushes.Neutral,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class PortExposureToGlyphConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        PortExposure.Open => "\uE785",        // unlocked
        PortExposure.OpenToSome => "\uE8D7",  // permissions
        PortExposure.Blocked => "\uE72E",     // locked
        PortExposure.LocalOnly => "\uE770",   // this computer
        _ => "\uE9CE",                        // unknown
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class ActivityTypeToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ActivityType.Banned => ThemeBrushes.Danger,
        ActivityType.FailedLogin => ThemeBrushes.Warning,
        ActivityType.SuccessfulLogin => ThemeBrushes.Success,
        ActivityType.Unbanned => ThemeBrushes.Accent,
        ActivityType.Warning => ThemeBrushes.Warning,
        _ => ThemeBrushes.Neutral,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class ActivityTypeToGlyphConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ActivityType.Banned => "",
        ActivityType.FailedLogin => "",
        ActivityType.SuccessfulLogin => "",
        ActivityType.Unbanned => "",
        ActivityType.Warning => "",
        ActivityType.Ignored => "\uE738",
        _ => "",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class ActivityTypeToTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ActivityType.Banned => "Banned",
        ActivityType.FailedLogin => "Failed login",
        ActivityType.SuccessfulLogin => "Signed in",
        ActivityType.Unbanned => "Unbanned",
        ActivityType.Warning => "Warning",
        ActivityType.Ignored => "Not counted",
        _ => "Info",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class SourceStateToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        SourceState.Active => ThemeBrushes.Success,
        SourceState.Error => ThemeBrushes.Danger,
        _ => ThemeBrushes.Neutral,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class SourceStateToTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        SourceState.Active => "Watching",
        SourceState.NotDetected => "Not installed here",
        SourceState.Error => "Problem",
        _ => "Off",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
