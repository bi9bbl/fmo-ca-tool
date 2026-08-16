using FmoCaTool.Certs;
using FmoCaTool.Crypto;

namespace FmoCaTool.Tests;

internal static class TestCertificates
{
    public static readonly byte[] RootSeed = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
    public static readonly byte[] IntermediateSeed = Enumerable.Range(32, 32).Select(value => (byte)value).ToArray();
    public static readonly byte[] UserSeed = Enumerable.Range(64, 32).Select(value => (byte)value).ToArray();

    public static KeyFile RootKey => KeyFile.FromSeed(RootSeed);
    public static KeyFile IntermediateKey => KeyFile.FromSeed(IntermediateSeed);
    public static KeyFile UserKey => KeyFile.FromSeed(UserSeed);

    public static RootCaCert Root()
    {
        var certificate = new RootCaCert
        {
            Sn = 900000001,
            IssuerName = "BI9BBL FMO Root CA",
            IssuerEmail = "ca@example.com",
            SubjectName = "BI9BBL FMO Root CA",
            SubjectPublicKey = RootKey.PublicKey,
            Crl = "",
            License = "",
            KeyId = "bi9bbl-root-2026",
            Iat = 1783291391,
            Exp = 2098651391,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(RootSeed, certificate.ToTbsCbor());
        return certificate;
    }

    public static IntermediateCaCert Intermediate(RootCaCert? root = null)
    {
        root ??= Root();
        var certificate = new IntermediateCaCert
        {
            Sn = 900001001,
            IssuerSn = root.Sn,
            IssuerName = root.SubjectName,
            IssuerPublicKey = root.SubjectPublicKey,
            SubjectName = "BI9BBL FMO Issuing CA",
            SubjectEmail = "ca@example.com",
            SubjectPublicKey = IntermediateKey.PublicKey,
            KeyId = "bi9bbl-intermediate-2026",
            Crl = "",
            License = "",
            UidRangeStart = 1,
            UidRangeEnd = 99999999,
            IssuingCountries = ["CN", "JP", "US"],
            Iat = 1783291491,
            Exp = 1940971391,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(RootSeed, certificate.ToTbsCbor());
        return certificate;
    }

    public static UserCert User(IntermediateCaCert? intermediate = null)
    {
        intermediate ??= Intermediate();
        var certificate = new UserCert
        {
            IssuerSn = intermediate.Sn,
            Callsign = "BI9BBL",
            Uid = 12345,
            PublicKey = UserKey.PublicKey,
            Iat = 1783291591,
            Exp = 1814827591,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(IntermediateSeed, certificate.ToTbsCbor());
        return certificate;
    }

    public static string CreateFixtureDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "fmo-ca-tool-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    public static (string RootCert, string RootKey, string IntermediateCert, string IntermediateKey) WriteChain(string directory)
    {
        var root = Root();
        var intermediate = Intermediate(root);
        var rootCertPath = Path.Combine(directory, "root.cert.json");
        var rootKeyPath = Path.Combine(directory, "root.key.json");
        var intermediateCertPath = Path.Combine(directory, "intermediate.cert.json");
        var intermediateKeyPath = Path.Combine(directory, "intermediate.key.json");
        File.WriteAllText(rootCertPath, CertificateJson.Serialize(root));
        File.WriteAllText(rootKeyPath, RootKey.ToJson());
        File.WriteAllText(intermediateCertPath, CertificateJson.Serialize(intermediate));
        File.WriteAllText(intermediateKeyPath, IntermediateKey.ToJson());
        return (rootCertPath, rootKeyPath, intermediateCertPath, intermediateKeyPath);
    }
}
