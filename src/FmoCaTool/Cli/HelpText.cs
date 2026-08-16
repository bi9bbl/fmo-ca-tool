namespace FmoCaTool.Cli;

internal static class HelpText
{
    public static void WriteGeneral(TextWriter writer) => writer.WriteLine(
        """
        fmo-ca-tool - offline FMO V4 custom PKI certificate authority

        Usage:
          fmo-ca-tool <command> [options]

        Commands:
          init-root          Create a self-signed FMO Root CA
          issue-intermediate Issue an Intermediate CA from a Root CA
          issue-user         Issue a User Certificate from an Intermediate CA
          fingerprint        Compute SHA-256 over a certificate's TBS CBOR

        Global options:
          --help             Show this help
          --version          Show version

        Run 'fmo-ca-tool <command> --help' for command-specific help.
        """);

    public static void WriteInitRoot(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool init-root --name NAME --email EMAIL (--sn SN | --random-sn)
            --key-id ID --crl URL --license URL (--valid-days N | --exp UNIX)
            [--iat UNIX] --out DIRECTORY [--force]

        Creates DIRECTORY/root.key.json and DIRECTORY/root.cert.json.
        Empty --crl and --license values are allowed.
        """);

    public static void WriteIssueIntermediate(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool issue-intermediate --root-cert FILE --root-key FILE
            --name NAME --email EMAIL (--sn SN | --random-sn) --key-id ID
            --uid-start UID --uid-end UID --countries CN,US --crl URL --license URL
            (--valid-days N | --exp UNIX) [--iat UNIX] --out DIRECTORY [--force]

        Creates DIRECTORY/intermediate.key.json and DIRECTORY/intermediate.cert.json.
        """);

    public static void WriteIssueUser(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool issue-user --intermediate-cert FILE --intermediate-key FILE
            [--root-cert FILE] --callsign CALLSIGN --uid UID
            (--public-key BASE64URL | --public-key-file FILE | --generate-key)
            (--valid-days N | --exp UNIX) [--iat UNIX] --out PATH [--force]

        With --public-key, --out may be a certificate .json file or a directory.
        With --generate-key, --out must be a directory and both key and certificate are created.
        """);

    public static void WriteFingerprint(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool fingerprint [--format base64url|hex] [--quiet] CERTIFICATE.json

        Fingerprints SHA-256(ToTbsCbor()), never the JSON file bytes.
        """);
}
