using CommunityToolkit.Mvvm.ComponentModel;

namespace TheFirewall.App.ViewModels;

public enum DurationUnit
{
    Minutes,
    Hours,
    Days,
    Weeks,
}

/// <summary>Edits a TimeSpan as "amount + unit" (and optionally "permanent").</summary>
public sealed partial class DurationField : ObservableObject
{
    public static IReadOnlyList<DurationUnit> Units { get; } = [DurationUnit.Minutes, DurationUnit.Hours, DurationUnit.Days, DurationUnit.Weeks];

    [ObservableProperty]
    public partial double Amount { get; set; }

    [ObservableProperty]
    public partial DurationUnit Unit { get; set; }

    [ObservableProperty]
    public partial bool Permanent { get; set; }

    public bool AllowPermanent { get; init; }

    public static DurationField From(TimeSpan value, bool allowPermanent = false)
    {
        var field = new DurationField { AllowPermanent = allowPermanent };
        if (value <= TimeSpan.Zero)
        {
            field.Permanent = allowPermanent;
            field.Amount = 1;
            field.Unit = DurationUnit.Days;
        }
        else if (value.TotalDays >= 7 && value.TotalDays % 7 == 0)
        {
            field.Amount = value.TotalDays / 7;
            field.Unit = DurationUnit.Weeks;
        }
        else if (value.TotalDays >= 1 && value.TotalHours % 24 == 0)
        {
            field.Amount = value.TotalDays;
            field.Unit = DurationUnit.Days;
        }
        else if (value.TotalHours >= 1 && value.TotalMinutes % 60 == 0)
        {
            field.Amount = value.TotalHours;
            field.Unit = DurationUnit.Hours;
        }
        else
        {
            field.Amount = Math.Max(1, Math.Round(value.TotalMinutes));
            field.Unit = DurationUnit.Minutes;
        }

        return field;
    }

    public TimeSpan ToTimeSpan()
    {
        if (Permanent && AllowPermanent)
        {
            return TimeSpan.Zero;
        }

        var amount = Math.Max(0.01, Amount);
        return Unit switch
        {
            DurationUnit.Minutes => TimeSpan.FromMinutes(amount),
            DurationUnit.Hours => TimeSpan.FromHours(amount),
            DurationUnit.Weeks => TimeSpan.FromDays(amount * 7),
            _ => TimeSpan.FromDays(amount),
        };
    }
}

/// <summary>Displays zero-based indexes as 1, 2, 3...</summary>
public sealed class PlusOneConverter : System.Windows.Data.IValueConverter
{
    public static PlusOneConverter Instance { get; } = new();

    public object Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        value is int i ? (i + 1).ToString(culture) : string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) => throw new NotSupportedException();
}
