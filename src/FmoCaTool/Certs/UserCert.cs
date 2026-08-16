using FmoCaTool.Crypto;

namespace FmoCaTool.Certs;

public sealed class UserCert : CertBase
{
    public override string Type => "userCert";
    public long IssuerSn { get; init; }
    public string Callsign { get; init; } = "";
    public long Uid { get; init; }
    public byte[] PublicKey { get; init; } = [];
    public long Iat { get; init; }
    public long Exp { get; init; }
    public byte[] Signature { get; set; } = [];

    public override byte[] ToTbsCbor()
    {
        var writer = CreateWriter();
        writer.WriteStartArray(9);
        EncodeText(writer, "FMO");
        EncodeInt(writer, 4);
        EncodeText(writer, Type);
        EncodeInt(writer, IssuerSn);
        EncodeText(writer, Callsign);
        EncodeInt(writer, Uid);
        EncodeBytes(writer, PublicKey);
        EncodeInt(writer, Iat);
        EncodeInt(writer, Exp);
        writer.WriteEndArray();
        return Finish(writer);
    }

    public bool VerifyBy(IntermediateCaCert issuer) =>
        Ed25519Helper.Verify(issuer.SubjectPublicKey, ToTbsCbor(), Signature);

    public bool IsExpired(long nowUtc) => nowUtc >= Exp;
}
