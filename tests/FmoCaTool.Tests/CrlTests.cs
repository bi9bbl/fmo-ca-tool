using FmoCaTool.Certs;
using FmoCaTool.Crls;
using FmoCaTool.Crypto;

namespace FmoCaTool.Tests;

public sealed class CrlTests
{
    [Fact]
    public void RootCrlTbsMatchesOfficialReferenceImplementation()
    {
        var crl = new RootCrl
        {
            IssuerSn = 1,
            CrlNumber = 3,
            ThisUpdate = 1783291391,
            NextUpdate = 1783377791,
            Entries =
            [
                new RootCrlEntry
                {
                    Sn = 1001,
                    CertFingerprint = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(),
                    RevokedAt = 1783291400,
                    Reason = 2
                }
            ]
        };

        Assert.Equal(
            "8863464d4f0467726f6f7443524c01031a6a4addff1a6a4c2f7f81841903e95820" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1a6a4ade0802",
            Convert.ToHexString(crl.ToTbsCbor()).ToLowerInvariant());
    }

    [Fact]
    public void IntermediateCrlTbsMatchesOfficialReferenceImplementation()
    {
        var crl = new IntermediateCrl
        {
            IssuerSn = 1,
            CrlNumber = 3,
            ThisUpdate = 1783291391,
            NextUpdate = 1783377791,
            Entries =
            [
                new IntermediateCrlEntry
                {
                    Uid = 12345,
                    CertFingerprint = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(),
                    RevokedAt = 1783291400,
                    Reason = 2
                }
            ]
        };

        Assert.Equal(
            "8863464d4f046f696e7465726d65646961746543524c01031a6a4addff1a6a4c2f7f81841930395820" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1a6a4ade0802",
            Convert.ToHexString(crl.ToTbsCbor()).ToLowerInvariant());
    }

    [Fact]
    public void RootCrlJsonRoundtripPreservesSignedBytesAndSignature()
    {
        var intermediate = TestCertificates.Intermediate();
        var crl = new RootCrl
        {
            IssuerSn = TestCertificates.Root().Sn,
            CrlNumber = 7,
            ThisUpdate = 1783291700,
            NextUpdate = 1783378100,
            Entries =
            [
                new RootCrlEntry
                {
                    Sn = intermediate.Sn,
                    CertFingerprint = intermediate.Fingerprint(),
                    RevokedAt = 1783291800,
                    Reason = 1
                }
            ],
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        crl.Signature = Ed25519Helper.Sign(TestCertificates.RootSeed, crl.ToTbsCbor());

        var parsed = Assert.IsType<RootCrl>(CrlJson.Parse(CrlJson.Serialize(crl)));

        Assert.Equal(crl.ToTbsCbor(), parsed.ToTbsCbor());
        Assert.Equal(crl.Signature, parsed.Signature);
        Assert.True(parsed.VerifyBy(TestCertificates.RootKey.PublicKey));
    }

    [Fact]
    public void NonCanonicalRootCrlEntryOrderIsRejected()
    {
        var fingerprintA = Enumerable.Repeat((byte)0xff, 32).ToArray();
        var fingerprintB = Enumerable.Repeat((byte)0x00, 32).ToArray();
        var crl = new RootCrl
        {
            IssuerSn = 1,
            CrlNumber = 1,
            ThisUpdate = 1,
            NextUpdate = 2,
            Entries =
            [
                new RootCrlEntry { Sn = 5, CertFingerprint = fingerprintA, RevokedAt = 1, Reason = 0 },
                new RootCrlEntry { Sn = 5, CertFingerprint = fingerprintB, RevokedAt = 1, Reason = 0 }
            ],
            Signature = new byte[Ed25519Helper.SignatureSize]
        };

        var exception = Assert.Throws<CliException>(() => CrlValidation.Validate(crl));
        Assert.Contains("raw certFingerprint bytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedNonCanonicalReferenceCrlCanStillBeParsedForCompatibility()
    {
        var crl = new RootCrl
        {
            IssuerSn = TestCertificates.Root().Sn,
            CrlNumber = 1,
            ThisUpdate = 1783291700,
            NextUpdate = 1783378100,
            Entries =
            [
                new RootCrlEntry
                {
                    Sn = 5,
                    CertFingerprint = Enumerable.Repeat((byte)0xff, 32).ToArray(),
                    RevokedAt = 1783291700,
                    Reason = 0
                },
                new RootCrlEntry
                {
                    Sn = 5,
                    CertFingerprint = Enumerable.Repeat((byte)0x00, 32).ToArray(),
                    RevokedAt = 1783291700,
                    Reason = 0
                }
            ],
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        crl.Signature = Ed25519Helper.Sign(TestCertificates.RootSeed, crl.ToTbsCbor());

        var parsed = Assert.IsType<RootCrl>(CrlJson.Parse(CrlJson.Serialize(crl)));

        Assert.Equal(crl.ToTbsCbor(), parsed.ToTbsCbor());
        Assert.True(parsed.VerifyBy(TestCertificates.RootKey.PublicKey));
    }
}
