using System.Text.Json;
using FmoCaTool.Certs;

namespace FmoCaTool.Tests;

public sealed class VectorTests
{
    [Theory]
    [InlineData("root-vector.json")]
    [InlineData("intermediate-vector.json")]
    [InlineData("user-vector.json")]
    public void FixedCompatibilityVectorMatchesCertificateImplementation(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "vectors", fileName);
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var certificate = CertificateJson.Parse(root.GetProperty("certificate").GetRawText());

        Assert.Equal(
            root.GetProperty("expectedTbsCborHex").GetString(),
            Convert.ToHexString(certificate.ToTbsCbor()).ToLowerInvariant());
        Assert.Equal(
            root.GetProperty("expectedFingerprint").GetString(),
            Base64Url.Encode(certificate.Fingerprint()));

        var expectedSignature = root.GetProperty("expectedSignature").GetString();
        var actualSignature = certificate switch
        {
            RootCaCert rootCertificate => Base64Url.Encode(rootCertificate.Signature),
            IntermediateCaCert intermediate => Base64Url.Encode(intermediate.Signature),
            UserCert user => Base64Url.Encode(user.Signature),
            _ => throw new InvalidOperationException()
        };
        Assert.Equal(expectedSignature, actualSignature);
    }
}
