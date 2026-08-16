using FmoCaTool.Crypto;

namespace FmoCaTool.Certs;

public sealed class IntermediateCaCert : CertBase
{
    public override string Type => "intermediateCA";
    public long Sn { get; init; }
    public long IssuerSn { get; init; }
    public string IssuerName { get; init; } = "";
    public byte[] IssuerPublicKey { get; init; } = [];
    public string SubjectName { get; init; } = "";
    public string SubjectEmail { get; init; } = "";
    public byte[] SubjectPublicKey { get; init; } = [];
    public bool IsCa => true;
    public long PathLen => 0;
    public string KeyId { get; init; } = "";
    public string Crl { get; init; } = "";
    public string License { get; init; } = "";
    public long UidRangeStart { get; init; }
    public long UidRangeEnd { get; init; }
    public string[] IssuingCountries { get; init; } = [];
    public long Iat { get; init; }
    public long Exp { get; init; }
    public byte[] Signature { get; set; } = [];

    public override byte[] ToTbsCbor()
    {
        var writer = CreateWriter();
        writer.WriteStartArray(20);
        EncodeText(writer, "FMO");
        EncodeInt(writer, 4);
        EncodeText(writer, Type);
        EncodeInt(writer, Sn);
        EncodeInt(writer, IssuerSn);
        EncodeText(writer, IssuerName);
        EncodeBytes(writer, IssuerPublicKey);
        EncodeText(writer, SubjectName);
        EncodeText(writer, SubjectEmail);
        EncodeBytes(writer, SubjectPublicKey);
        EncodeBool(writer, IsCa);
        EncodeInt(writer, PathLen);
        EncodeText(writer, KeyId);
        EncodeText(writer, Crl);
        EncodeText(writer, License);
        EncodeInt(writer, UidRangeStart);
        EncodeInt(writer, UidRangeEnd);
        EncodeTextArray(writer, IssuingCountries);
        EncodeInt(writer, Iat);
        EncodeInt(writer, Exp);
        writer.WriteEndArray();
        return Finish(writer);
    }

    public bool VerifyBy(RootCaCert root) => Ed25519Helper.Verify(root.SubjectPublicKey, ToTbsCbor(), Signature);

    public bool CanIssueFor(long uid) => uid >= UidRangeStart && uid <= UidRangeEnd;

    public bool IsExpired(long nowUtc) => nowUtc >= Exp;
}
