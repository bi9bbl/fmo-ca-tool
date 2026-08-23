using FmoCaTool.Crypto;

namespace FmoCaTool.Crls;

public sealed class IntermediateCrl : CrlBase
{
    public override string Type => "intermediateCRL";
    public long IssuerSn { get; init; }
    public long CrlNumber { get; init; }
    public long ThisUpdate { get; init; }
    public long NextUpdate { get; init; }
    public IntermediateCrlEntry[] Entries { get; init; } = [];
    public byte[] Signature { get; set; } = [];

    public override byte[] ToTbsCbor()
    {
        var writer = CreateWriter();
        writer.WriteStartArray(8);
        writer.WriteTextString("FMO");
        writer.WriteInt64(4);
        writer.WriteTextString(Type);
        writer.WriteInt64(IssuerSn);
        writer.WriteInt64(CrlNumber);
        writer.WriteInt64(ThisUpdate);
        writer.WriteInt64(NextUpdate);
        writer.WriteStartArray(Entries.Length);
        foreach (var entry in Entries)
        {
            writer.WriteStartArray(4);
            writer.WriteInt64(entry.Uid);
            writer.WriteByteString(entry.CertFingerprint);
            writer.WriteInt64(entry.RevokedAt);
            writer.WriteInt64(entry.Reason);
            writer.WriteEndArray();
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        return Finish(writer);
    }

    public bool VerifyBy(byte[] intermediatePublicKey) =>
        Ed25519Helper.Verify(intermediatePublicKey, ToTbsCbor(), Signature);
}

public sealed class IntermediateCrlEntry
{
    public long Uid { get; init; }
    public byte[] CertFingerprint { get; init; } = [];
    public long RevokedAt { get; init; }
    public long Reason { get; init; }
}
