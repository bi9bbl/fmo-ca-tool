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
          verify             Verify certificates, chains, CRLs, and revocation status
          issue-root-crl     Issue a Root CRL for Intermediate CA revocation
          issue-intermediate-crl
                             Issue an Intermediate CRL for User revocation
          generate-key       Generate an endpoint-owned Ed25519 key pair
          qr                 Generate a QR code PNG from text or a file
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

    public static void WriteVerify(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool verify [--root ROOT.json]
            [--intermediate INTERMEDIATE.json] [--user USER.json]
            [--root-crl ROOT-CRL.json] [--intermediate-crl INTERMEDIATE-CRL.json]
            [--at UNIX]

        Dependencies are explicit: --intermediate requires --root, --user requires
        --intermediate, and each CRL requires its issuer certificate. A stale CRL
        produces a warning; a bad signature, invalid chain, or effective revocation
        produces exit code 3.
        """);

    public static void WriteIssueRootCrl(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool issue-root-crl --root-cert FILE --root-key FILE
            --crl-number N (--valid-days N | --next-update UNIX)
            [--this-update UNIX]
            [--revoke INTERMEDIATE.json ... --reason 0..5 [--revoked-at UNIX]
             | --entries ENTRIES.json]
            --out FILE [--force]

        With repeated --revoke, one reason and revokedAt apply to all certificates.
        For per-entry values, ENTRIES.json is an array of objects containing
        certificate, revokedAt, and reason. An empty CRL needs neither option.
        """);

    public static void WriteIssueIntermediateCrl(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool issue-intermediate-crl --intermediate-cert FILE
            --intermediate-key FILE --crl-number N
            (--valid-days N | --next-update UNIX) [--this-update UNIX]
            [--revoke USER.json ... --reason 0..4 [--revoked-at UNIX]
             | --entries ENTRIES.json]
            --out FILE [--force]

        With repeated --revoke, one reason and revokedAt apply to all certificates.
        For per-entry values, ENTRIES.json is an array of objects containing
        certificate, revokedAt, and reason. An empty CRL needs neither option.
        """);

    public static void WriteGenerateKey(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool generate-key [--name STEM] --out DIRECTORY [--force]

        Creates STEM.key.json containing the plaintext 32-byte Ed25519 seed and
        STEM.public.key containing only the unpadded Base64URL public key.
        Generate endpoint keys on the endpoint; do not centralize User private keys.
        """);

    public static void WriteQr(TextWriter writer) => writer.WriteLine(
        """
        Usage:
          fmo-ca-tool qr (--text TEXT | --file FILE) --out QR.png
            [--ecc L|M|Q|H] [--pixels N] [--force]

        UTF-8 files are encoded as text. Other files are encoded as Base64. The
        command never truncates input: content exceeding QR capacity is rejected.
        Private-key files are not selected or embedded automatically.
        """);
}
