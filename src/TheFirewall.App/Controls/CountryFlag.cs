using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TheFirewall.App.Converters;

namespace TheFirewall.App.Controls;

/// <summary>
/// A country's flag (4:3) with a hairline border so white flags stay visible. Shows a globe when the country is unknown.
/// </summary>
public sealed class CountryFlag : Border
{
    public static readonly DependencyProperty CodeProperty = DependencyProperty.Register(
        nameof(Code), typeof(string), typeof(CountryFlag), new PropertyMetadata(null, (d, _) => ((CountryFlag)d).Update()));

    public static readonly DependencyProperty FlagWidthProperty = DependencyProperty.Register(
        nameof(FlagWidth), typeof(double), typeof(CountryFlag), new PropertyMetadata(20d, (d, _) => ((CountryFlag)d).Update()));

    private readonly Image image = new() { Stretch = Stretch.Fill };
    private readonly TextBlock globe = new()
    {
        Text = "",
        HorizontalAlignment = HorizontalAlignment.Center,
        VerticalAlignment = VerticalAlignment.Center,
        TextAlignment = TextAlignment.Center,
    };

    public CountryFlag()
    {
        VerticalAlignment = VerticalAlignment.Center;
        HorizontalAlignment = HorizontalAlignment.Left;
        SnapsToDevicePixels = true;
        RenderOptions.SetBitmapScalingMode(image, BitmapScalingMode.HighQuality);
        SetResourceReference(BorderBrushProperty, "ControlStrokeColorDefaultBrush");
        globe.SetResourceReference(TextBlock.FontFamilyProperty, "IconFont");
        globe.SetResourceReference(TextBlock.ForegroundProperty, "TextFillColorTertiaryBrush");
        Update();
    }

    /// <summary>ISO 3166-1 alpha-2 country code.</summary>
    public string? Code
    {
        get => (string?)GetValue(CodeProperty);
        set => SetValue(CodeProperty, value);
    }

    /// <summary>Width of the flag in device-independent pixels; the height is three quarters of it.</summary>
    public double FlagWidth
    {
        get => (double)GetValue(FlagWidthProperty);
        set => SetValue(FlagWidthProperty, value);
    }

    private void Update()
    {
        double width = FlagWidth;
        double height = Math.Round(width * 3 / 4);
        var source = CountryFlagConverter.Get(Code);
        if (source is not null)
        {
            image.Source = source;
            image.Width = width;
            image.Height = height;
            BorderThickness = new Thickness(1);
            Child = image;
        }
        else
        {
            image.Source = null;
            globe.Width = width + 2;
            globe.FontSize = Math.Round(height * 0.95);
            BorderThickness = new Thickness(0);
            Child = globe;
        }
    }
}
