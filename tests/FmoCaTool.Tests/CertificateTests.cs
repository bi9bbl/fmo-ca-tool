using System.Security.Cryptography;
using System.Text.Json;
using FmoCaTool.Certs;
using FmoCaTool.Crypto;

namespace FmoCaTool.Tests;

public sealed class CertificateTests
{
    [Fact]
    public void RootSelfSignatureIsValid()
    {
        Assert.True(TestCertificates.Root().VerifySelfSignature());
    }

    [Fact]
    public void TamperingWithRootSignedFieldFailsVerification()
    {
        var original = TestCertificates.Root();
        var tampered = new RootCaCert
        {
            Sn = original.Sn,
            IssuerName = original.IssuerName,
            IssuerEmail = original.IssuerEmail,
            SubjectName = original.SubjectName + " tampered",
            SubjectPublicKey = original.SubjectPublicKey,
            Crl = original.Crl,
            License = original.License,
            KeyId = original.KeyId,
            Iat = original.Iat,
            Exp = original.Exp,
            Signature = original.Signature
        };

        Assert.False(tampered.VerifySelfSignature());
    }

    [Fact]
    public void IntermediateIsVerifiedByRoot()
    {
        var root = TestCertificates.Root();
        Assert.True(TestCertificates.Intermediate(root).VerifyBy(root));
    }

    [Fact]
    public void WrongRootCannotVerifyIntermediate()
    {
        var intermediate = TestCertificates.Intermediate();
        var wrongKey = KeyFile.FromSeed(Enumerable.Repeat((byte)0xa5, 32).ToArray());
        var wrongRoot = new RootCaCert
        {
            Sn = 777,
            IssuerName = "Wrong",
            IssuerEmail = "wrong@example.com",
            SubjectName = "Wrong",
            SubjectPublicKey = wrongKey.PublicKey,
            Crl = "",
            License = "",
            KeyId = "wrong",
            Iat = intermediate.Iat,
            Exp = intermediate.Exp + 1,
            Signature = new byte[64]
        };

        Assert.False(intermediate.VerifyBy(wrongRoot));
    }

    [Fact]
    public void UserIsVerifiedByIntermediate()
    {
        var intermediate = TestCertificates.Intermediate();
        Assert.True(TestCertificates.User(intermediate).VerifyBy(intermediate));
    }

    [Fact]
    public void WrongIntermediateCannotVerifyUser()
    {
        var user = TestCertificates.User();
        var original = TestCertificates.Intermediate();
        var wrong = new IntermediateCaCert
        {
            Sn = original.Sn,
            IssuerSn = original.IssuerSn,
            IssuerName = original.IssuerName,
            IssuerPublicKey = original.IssuerPublicKey,
            SubjectName = original.SubjectName,
            SubjectEmail = original.SubjectEmail,
            SubjectPublicKey = KeyFile.FromSeed(Enumerable.Repeat((byte)0x5a, 32).ToArray()).PublicKey,
            KeyId = original.KeyId,
            Crl = original.Crl,
            License = original.License,
            UidRangeStart = original.UidRangeStart,
            UidRangeEnd = original.UidRangeEnd,
            IssuingCountries = original.IssuingCountries,
            Iat = original.Iat,
            Exp = original.Exp,
            Signature = original.Signature
        };

        Assert.False(user.VerifyBy(wrong));
    }

    [Fact]
    public void Base64UrlOutputHasNoPaddingAndRoundtrips()
    {
        byte[] bytes = [0xff, 0xee];
        var encoded = Base64Url.Encode(bytes);

        Assert.DoesNotContain("=", encoded, StringComparison.Ordinal);
        Assert.Equal(bytes, Base64Url.Decode(encoded));
    }

    [Fact]
    public void Base64UrlDecoderAcceptsPadding()
    {
        Assert.Equal(new byte[] { 0xff, 0xee }, Base64Url.Decode("_-4="));
    }

    [Fact]
    public void FingerprintIsSha256OfTbsCbor()
    {
        var certificate = TestCertificates.User();
        Assert.Equal(SHA256.HashData(certificate.ToTbsCbor()), certificate.Fingerprint());
    }

    [Fact]
    public void FingerprintDoesNotDependOnJsonFormatting()
    {
        var certificate = TestCertificates.User();
        var indented = CertificateJson.Serialize(certificate);
        using var document = JsonDocument.Parse(indented);
        var minified = JsonSerializer.Serialize(document.RootElement);

        Assert.Equal(
            CertificateJson.Parse(indented).Fingerprint(),
            CertificateJson.Parse(minified).Fingerprint());
    }

    [Fact]
    public void CertificateJsonRoundtripPreservesTbs()
    {
        CertBase[] certificates = [TestCertificates.Root(), TestCertificates.Intermediate(), TestCertificates.User()];
        foreach (var certificate in certificates)
        {
            Assert.Equal(certificate.ToTbsCbor(), CertificateJson.Parse(CertificateJson.Serialize(certificate)).ToTbsCbor());
        }
    }

    [Fact]
    public void CountriesAreUppercasedSortedAndDeduplicated()
    {
        Assert.Equal(["CN", "JP", "US"], CertificateValidation.NormalizeCountries("us,CN,jp,cn"));
    }

    [Theory]
    [InlineData("C")]
    [InlineData("CHN")]
    [InlineData("C1")]
    [InlineData("中国")]
    public void InvalidCountryIsRejected(string country)
    {
        Assert.Throws<CliException>(() => CertificateValidation.NormalizeCountries(country));
    }
}
