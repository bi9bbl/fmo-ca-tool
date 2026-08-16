using FmoCaTool.Crypto;

namespace FmoCaTool.Certs;

public sealed class RootCaCert : CertBase
{
    public override string Type => "rootCA";
    public long Sn { get; init; }
    public string IssuerName { get; init; } = "";
    public string IssuerEmail { get; init; } = "";
    public string SubjectName { get; init; } = "";
    public byte[] SubjectPublicKey { get; init; } = [];
    public bool IsCa => true;
    public long PathLen => 1;
    public string Crl { get; init; } = "";
    public string License { get; init; } = "";
    public string KeyId { get; init; } = "";
    public long Iat { get; init; }
    public long Exp { get; init; }
    public byte[] Signature { get; set; } = [];

    public override byte[] ToTbsCbor()
    {
        var writer = CreateWriter();
        writer.WriteStartArray(15);
        EncodeText(writer, "FMO");
        EncodeInt(writer, 4);
        EncodeText(writer, Type);
        EncodeInt(writer, Sn);
        EncodeText(writer, IssuerName);
        EncodeText(writer, IssuerEmail);
        EncodeText(writer, SubjectName);
        EncodeBytes(writer, SubjectPublicKey);
        EncodeBool(writer, IsCa);
        EncodeInt(writer, PathLen);
        EncodeText(writer, Crl);
        EncodeText(writer, License);
        EncodeText(writer, KeyId);
        EncodeInt(writer, Iat);
        EncodeInt(writer, Exp);
        writer.WriteEndArray();
        return Finish(writer);
    }

    public bool VerifySelfSignature() => Ed25519Helper.Verify(SubjectPublicKey, ToTbsCbor(), Signature);

    public bool IsExpired(long nowUtc) => nowUtc >= Exp;
}
