using System.Globalization;

namespace TheFirewall.Core.Geo;

public sealed record CountryInfo(string Code, string Name, string Region);

/// <summary>ISO 3166-1 alpha-2 countries grouped by region (English names come from .NET globalization data).</summary>
public static class Countries
{
    private static readonly (string Region, string Codes)[] Regions =
    [
        ("Africa", "AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN GQ GW KE KM LR LS LY MA MG ML MR MU MW MZ NA NE NG RE RW SC SD SH SL SN SO SS ST SZ TD TG TN TZ UG YT ZA ZM ZW"),
        ("Americas", "AG AI AR AW BB BL BM BO BQ BR BS BZ CA CL CO CR CU CW DM DO EC FK GD GF GL GP GT GY HN HT JM KN KY LC MF MQ MS MX NI PA PE PM PR PY SR SV SX TC TT US UY VC VE VG VI"),
        ("Asia", "AE AF AM AZ BD BH BN BT CN CY GE HK ID IL IN IO IQ IR JO JP KG KH KP KR KW KZ LA LB LK MM MN MO MV MY NP OM PH PK PS QA SA SG SY TH TJ TL TM TR TW UZ VN YE"),
        ("Europe", "AD AL AT AX BA BE BG BY CH CZ DE DK EE ES FI FO FR GB GG GI GR HR HU IE IM IS IT JE LI LT LU LV MC MD ME MK MT NL NO PL PT RO RS RU SE SI SJ SK SM UA VA XK"),
        ("Oceania", "AS AU CK FJ FM GU KI MH MP NC NF NR NU NZ PF PG PN PW SB TK TO TV UM VU WF WS"),
        ("Other", "AQ BV GS HM TF"),
    ];

    private static readonly Lazy<IReadOnlyList<CountryInfo>> AllCountries = new(Build);

    public static IReadOnlyList<CountryInfo> All => AllCountries.Value;

    public static string GetName(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return "Unknown";
        }

        var match = All.FirstOrDefault(c => string.Equals(c.Code, code, StringComparison.OrdinalIgnoreCase));
        return match?.Name ?? code.ToUpperInvariant();
    }

    public static bool IsValidCode(string? code) =>
        code is { Length: 2 } && All.Any(c => string.Equals(c.Code, code, StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<CountryInfo> Build()
    {
        var list = new List<CountryInfo>();
        foreach (var (region, codes) in Regions)
        {
            foreach (var code in codes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                list.Add(new CountryInfo(code, LookupName(code), region));
            }
        }

        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCulture));
        return list;
    }

    private static string LookupName(string code)
    {
        if (code == "XK")
        {
            return "Kosovo";
        }

        try
        {
            var name = new RegionInfo(code).EnglishName;
            return string.IsNullOrWhiteSpace(name) ? code : name;
        }
        catch (ArgumentException)
        {
            return code;
        }
    }
}
