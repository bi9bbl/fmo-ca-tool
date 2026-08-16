using FmoCaTool.Certs;
using FmoCaTool.Cli;
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

    [Theory]
    [InlineData("init-root")]
    [InlineData("issue-intermediate")]
    [InlineData("issue-user")]
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
