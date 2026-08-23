using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crls;
using FmoCaTool.Crypto;

namespace FmoCaTool.Tests;

public sealed class CliTests
{
    [Fact]
    public void UserUidOutsideIntermediateRangeIsRejected()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var result = Run(
            "issue-user", "--intermediate-cert", chain.IntermediateCert,
            "--intermediate-key", chain.IntermediateKey, "--callsign", "BI9BBL", "--uid", "100000000",
            "--public-key", Base64Url.Encode(TestCertificates.UserKey.PublicKey), "--iat", "1783291591",
            "--exp", "1814827591", "--out", Path.Combine(directory, "user.cert.json"));

        Assert.NotEqual(0, result.Code);
        Assert.Contains("outside Intermediate range", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void UserExpirationBeyondIntermediateIsRejected()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var result = Run(
            "issue-user", "--intermediate-cert", chain.IntermediateCert,
            "--intermediate-key", chain.IntermediateKey, "--callsign", "BI9BBL", "--uid", "12345",
            "--public-key", Base64Url.Encode(TestCertificates.UserKey.PublicKey), "--iat", "1783291591",
            "--exp", "1940971392", "--out", Path.Combine(directory, "user.cert.json"));

        Assert.NotEqual(0, result.Code);
        Assert.Contains("exceeds Intermediate expiration", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void IntermediateExpirationBeyondRootIsRejected()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var result = Run(
            "issue-intermediate", "--root-cert", chain.RootCert, "--root-key", chain.RootKey,
            "--name", "Issuing CA", "--email", "ca@example.com", "--sn", "900001002",
            "--key-id", "issuing", "--uid-start", "1", "--uid-end", "10", "--countries", "CN",
            "--crl", "", "--license", "", "--iat", "1783291591", "--exp", "2098651392",
            "--out", Path.Combine(directory, "other"));

        Assert.NotEqual(0, result.Code);
        Assert.Contains("exceeds Root expiration", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void MismatchedIntermediatePrivateKeyIsRejected()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var wrongKeyPath = Path.Combine(directory, "wrong.key.json");
        File.WriteAllText(wrongKeyPath, KeyFile.FromSeed(Enumerable.Repeat((byte)0x44, 32).ToArray()).ToJson());
        var result = Run(
            "issue-user", "--intermediate-cert", chain.IntermediateCert,
            "--intermediate-key", wrongKeyPath, "--callsign", "BI9BBL", "--uid", "12345",
            "--public-key", Base64Url.Encode(TestCertificates.UserKey.PublicKey), "--iat", "1783291591",
            "--exp", "1814827591", "--out", Path.Combine(directory, "user.cert.json"));

        Assert.NotEqual(0, result.Code);
        Assert.Contains("does not match", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void ForceIsRequiredToReplaceRootKey()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        string[] arguments =
        [
            "init-root", "--name", "Test Root", "--email", "ca@example.com", "--sn", "901",
            "--key-id", "test", "--crl", "", "--license", "", "--iat", "1700000000",
            "--exp", "2000000000", "--out", directory
        ];

        Assert.Equal(0, Run(arguments).Code);
        var rejected = Run(arguments);
        Assert.NotEqual(0, rejected.Code);
        Assert.Contains("--force", rejected.Error, StringComparison.Ordinal);
        var forced = Run([.. arguments, "--force"]);
        Assert.Equal(0, forced.Code);
        Assert.Contains("WARNING", forced.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void QuietFingerprintWritesOnlySelectedValue()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var certificate = TestCertificates.User();
        var path = Path.Combine(directory, "user.cert.json");
        File.WriteAllText(path, CertificateJson.Serialize(certificate));

        var result = Run("fingerprint", "--quiet", path);

        Assert.Equal(0, result.Code);
        Assert.Equal(Base64Url.Encode(certificate.Fingerprint()) + Environment.NewLine, result.Output);
        Assert.Equal("", result.Error);
    }

    [Fact]
    public void PublicKeyModeCreatesOnlyCertificate()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var outputDirectory = Path.Combine(directory, "user");
        var result = Run(
            "issue-user", "--intermediate-cert", chain.IntermediateCert,
            "--intermediate-key", chain.IntermediateKey, "--root-cert", chain.RootCert,
            "--callsign", "bi9bbl", "--uid", "12345",
            "--public-key", Base64Url.Encode(TestCertificates.UserKey.PublicKey), "--iat", "1783291591",
            "--exp", "1814827591", "--out", outputDirectory);

        Assert.Equal(0, result.Code);
        var certificatePath = Path.Combine(outputDirectory, "BI9BBL-12345.cert.json");
        Assert.True(File.Exists(certificatePath));
        Assert.Empty(Directory.GetFiles(outputDirectory, "*.key.json"));
        var certificate = CertificateJson.Load<UserCert>(certificatePath);
        Assert.True(certificate.VerifyBy(TestCertificates.Intermediate()));
    }

    [Fact]
    public void VerifyAcceptsAValidFullChain()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var userPath = Path.Combine(directory, "user.cert.json");
        File.WriteAllText(userPath, CertificateJson.Serialize(TestCertificates.User()));

        var result = Run(
            "verify", "--root", chain.RootCert, "--intermediate", chain.IntermediateCert,
            "--user", userPath, "--at", "1783291700");

        Assert.Equal(0, result.Code);
        Assert.Contains("VALID", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("ERROR:", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void RootCrlIssuanceAndRevocationCheckFormAClosedLoop()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var crlPath = Path.Combine(directory, "root.crl.json");
        var issued = Run(
            "issue-root-crl", "--root-cert", chain.RootCert, "--root-key", chain.RootKey,
            "--crl-number", "1", "--this-update", "1783291700", "--next-update", "1783378100",
            "--revoke", chain.IntermediateCert, "--reason", "1", "--revoked-at", "1783291800",
            "--out", crlPath);

        Assert.Equal(0, issued.Code);
        var crl = CrlJson.Load<RootCrl>(crlPath);
        Assert.True(crl.VerifyBy(TestCertificates.RootKey.PublicKey));

        var verified = Run(
            "verify", "--root", chain.RootCert, "--intermediate", chain.IntermediateCert,
            "--root-crl", crlPath, "--at", "1783291800");

        Assert.Equal(3, verified.Code);
        Assert.Contains("Intermediate is revoked", verified.Output, StringComparison.Ordinal);
        Assert.Contains("INVALID", verified.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void RootCrlSerialMatchWithoutFingerprintMatchDoesNotRevokeReissuedCertificate()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var root = TestCertificates.Root();
        var original = TestCertificates.Intermediate(root);
        var replacementKey = KeyFile.FromSeed(Enumerable.Repeat((byte)0x71, 32).ToArray());
        var replacement = new IntermediateCaCert
        {
            Sn = original.Sn,
            IssuerSn = original.IssuerSn,
            IssuerName = original.IssuerName,
            IssuerPublicKey = original.IssuerPublicKey,
            SubjectName = original.SubjectName,
            SubjectEmail = original.SubjectEmail,
            SubjectPublicKey = replacementKey.PublicKey,
            KeyId = original.KeyId,
            Crl = original.Crl,
            License = original.License,
            UidRangeStart = original.UidRangeStart,
            UidRangeEnd = original.UidRangeEnd,
            IssuingCountries = original.IssuingCountries,
            Iat = original.Iat,
            Exp = original.Exp,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        replacement.Signature = Ed25519Helper.Sign(TestCertificates.RootSeed, replacement.ToTbsCbor());
        var crl = new RootCrl
        {
            IssuerSn = root.Sn,
            CrlNumber = 1,
            ThisUpdate = 1783291700,
            NextUpdate = 1783378100,
            Entries =
            [
                new RootCrlEntry
                {
                    Sn = original.Sn,
                    CertFingerprint = original.Fingerprint(),
                    RevokedAt = 1783291800,
                    Reason = 3
                }
            ],
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        crl.Signature = Ed25519Helper.Sign(TestCertificates.RootSeed, crl.ToTbsCbor());
        var rootPath = Path.Combine(directory, "root.cert.json");
        var replacementPath = Path.Combine(directory, "replacement.cert.json");
        var crlPath = Path.Combine(directory, "root.crl.json");
        File.WriteAllText(rootPath, CertificateJson.Serialize(root));
        File.WriteAllText(replacementPath, CertificateJson.Serialize(replacement));
        File.WriteAllText(crlPath, CrlJson.Serialize(crl));

        var result = Run(
            "verify", "--root", rootPath, "--intermediate", replacementPath,
            "--root-crl", crlPath, "--at", "1783291800");

        Assert.Equal(0, result.Code);
        Assert.Contains("no matching certificate fingerprint", result.Output, StringComparison.Ordinal);
        Assert.Contains("VALID", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void IntermediateCrlIssuanceAndRevocationCheckFormAClosedLoop()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var chain = TestCertificates.WriteChain(directory);
        var userPath = Path.Combine(directory, "user.cert.json");
        File.WriteAllText(userPath, CertificateJson.Serialize(TestCertificates.User()));
        var crlPath = Path.Combine(directory, "intermediate.crl.json");
        var issued = Run(
            "issue-intermediate-crl", "--intermediate-cert", chain.IntermediateCert,
            "--intermediate-key", chain.IntermediateKey, "--crl-number", "1",
            "--this-update", "1783291700", "--next-update", "1783378100",
            "--revoke", userPath, "--reason", "2", "--revoked-at", "1783291800",
            "--out", crlPath);

        Assert.Equal(0, issued.Code);
        var crl = CrlJson.Load<IntermediateCrl>(crlPath);
        Assert.True(crl.VerifyBy(TestCertificates.IntermediateKey.PublicKey));

        var verified = Run(
            "verify", "--root", chain.RootCert, "--intermediate", chain.IntermediateCert,
            "--user", userPath, "--intermediate-crl", crlPath, "--at", "1783291800");

        Assert.Equal(3, verified.Code);
        Assert.Contains("User Certificate is revoked", verified.Output, StringComparison.Ordinal);
        Assert.Contains("INVALID", verified.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateKeyCreatesPrivateJsonAndPublicKeyOnlyFile()
    {
        var directory = TestCertificates.CreateFixtureDirectory();

        var result = Run("generate-key", "--name", "endpoint", "--out", directory);

        Assert.Equal(0, result.Code);
        var key = KeyFile.Load(Path.Combine(directory, "endpoint.key.json"));
        var publicText = File.ReadAllText(Path.Combine(directory, "endpoint.public.key")).Trim();
        Assert.Equal(Base64Url.Encode(key.PublicKey), publicText);
        Assert.DoesNotContain(Base64Url.Encode(key.Seed), publicText, StringComparison.Ordinal);
    }

    [Fact]
    public void QrCommandCreatesAPngWithoutReadingAnyKeyAutomatically()
    {
        var directory = TestCertificates.CreateFixtureDirectory();
        var outputPath = Path.Combine(directory, "certificate.png");

        var result = Run("qr", "--text", "FMO V4 certificate", "--out", outputPath);

        Assert.Equal(0, result.Code);
        var png = File.ReadAllBytes(outputPath);
        Assert.True(png.AsSpan().StartsWith(new byte[] { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a }));
        Assert.Contains("QR code generated", result.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("init-root")]
    [InlineData("issue-intermediate")]
    [InlineData("issue-user")]
    [InlineData("verify")]
    [InlineData("issue-root-crl")]
    [InlineData("issue-intermediate-crl")]
    [InlineData("generate-key")]
    [InlineData("qr")]
    [InlineData("fingerprint")]
    public void EveryPublicCommandHasHelp(string command)
    {
        var result = Run(command, "--help");
        Assert.Equal(0, result.Code);
        Assert.Contains("Usage:", result.Output, StringComparison.Ordinal);
        Assert.Equal("", result.Error);
    }

    private static CliResult Run(params string[] arguments)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = CliApplication.Run(arguments, output, error);
        return new CliResult(code, output.ToString(), error.ToString());
    }

    private sealed record CliResult(int Code, string Output, string Error);
}
