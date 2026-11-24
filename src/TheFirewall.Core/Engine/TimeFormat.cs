using System.Globalization;

namespace TheFirewall.Core.Engine;

public static class TimeFormat
{
    /// <summary>Formats a ban duration for people: "permanently", "30 minutes", "1 day", "2 weeks".</summary>
    public static string Duration(TimeSpan? duration)
    {
        if (duration is null || duration <= TimeSpan.Zero)
        {
            return "permanently";
        }

        var d = duration.Value;
        static string Unit(double value, string unit) =>
            string.Create(CultureInfo.InvariantCulture, $"{value:0.#} {unit}{(Math.Abs(value - 1) < 0.05 ? string.Empty : "s")}");

        if (d.TotalDays >= 7 && d.TotalDays % 7 == 0)
        {
            return Unit(d.TotalDays / 7, "week");
        }

        if (d.TotalDays >= 1)
        {
            return Unit(d.TotalDays, "day");
        }

        if (d.TotalHours >= 1)
        {
            return Unit(d.TotalHours, "hour");
        }

        if (d.TotalMinutes >= 1)
        {
            return Unit(d.TotalMinutes, "minute");
        }

        return Unit(Math.Max(1, d.TotalSeconds), "second");
    }
}
