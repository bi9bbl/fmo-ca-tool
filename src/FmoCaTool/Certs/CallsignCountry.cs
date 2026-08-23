namespace FmoCaTool.Certs;

public static class CallsignCountry
{
    private static readonly (string Prefix, string Country)[] Prefixes =
    [
        ("9M6", "MY"), ("9M2", "MY"), ("2E", "GB"), ("2M", "GB"),
        ("AA", "US"), ("AB", "US"), ("AC", "US"), ("AD", "US"), ("AE", "US"),
        ("AF", "US"), ("AG", "US"), ("AI", "US"), ("AJ", "US"), ("AK", "US"),
        ("AL", "US"), ("BV", "TW"), ("BY", "CN"), ("DS", "KR"), ("DU", "PH"),
        ("EA", "ES"), ("EB", "ES"), ("EC", "ES"), ("ED", "ES"), ("EE", "ES"),
        ("EF", "ES"), ("EG", "ES"), ("EH", "ES"), ("HB", "CH"), ("HL", "KR"),
        ("HS", "TH"), ("JA", "JP"), ("JE", "JP"), ("JF", "JP"), ("JG", "JP"),
        ("JH", "JP"), ("JI", "JP"), ("JJ", "JP"), ("JK", "JP"), ("JL", "JP"),
        ("JM", "JP"), ("JN", "JP"), ("JO", "JP"), ("JP", "JP"), ("JQ", "JP"),
        ("JR", "JP"), ("JS", "JP"), ("LA", "NO"), ("LU", "AR"), ("OH", "FI"),
        ("ON", "BE"), ("OO", "BE"), ("OP", "BE"), ("OQ", "BE"), ("OR", "BE"),
        ("OS", "BE"), ("OT", "BE"), ("OZ", "DK"), ("PA", "NL"), ("PB", "NL"),
        ("PC", "NL"), ("PD", "NL"), ("PE", "NL"), ("PF", "NL"), ("PG", "NL"),
        ("PH", "NL"), ("PI", "NL"), ("PJ", "NL"), ("PY", "BR"), ("SM", "SE"),
        ("SP", "PL"), ("UA", "RU"), ("UB", "RU"), ("UC", "RU"), ("UD", "RU"),
        ("UE", "RU"), ("UF", "RU"), ("UG", "RU"), ("UH", "RU"), ("UI", "RU"),
        ("VE", "CA"), ("VA", "CA"), ("VK", "AU"), ("VR", "HK"), ("VU", "IN"),
        ("XE", "MX"), ("XS", "CN"), ("YB", "ID"), ("ZL", "NZ"), ("7J", "JP"),
        ("7K", "JP"), ("7L", "JP"), ("7M", "JP"), ("7N", "JP"), ("8J", "JP"),
        ("8K", "JP"), ("8L", "JP"), ("8M", "JP"), ("8N", "JP"),
        ("F", "FR"), ("G", "GB"), ("I", "IT"), ("M", "GB"), ("N", "US"),
        ("R", "RU"), ("W", "US"), ("B", "CN"), ("D", "DE"), ("K", "US")
    ];

    public static string? Infer(string callsign)
    {
        var normalized = CertificateValidation.NormalizeCallsign(callsign);
        foreach (var (prefix, country) in Prefixes)
        {
            if (normalized.StartsWith(prefix, StringComparison.Ordinal))
            {
                return country;
            }
        }

        return null;
    }
}
