using System.Formats.Cbor;
using System.Security.Cryptography;

namespace FmoCaTool.Certs;

public abstract class CertBase
{
    public abstract string Type { get; }

    public abstract byte[] ToTbsCbor();

    public byte[] Fingerprint() => SHA256.HashData(ToTbsCbor());

    protected static CborWriter CreateWriter() => new(CborConformanceMode.Lax);

    protected static void EncodeText(CborWriter writer, string value) => writer.WriteTextString(value);

    protected static void EncodeInt(CborWriter writer, long value) => writer.WriteInt64(value);

    protected static void EncodeBytes(CborWriter writer, byte[] value) => writer.WriteByteString(value);

    protected static void EncodeBool(CborWriter writer, bool value) => writer.WriteBoolean(value);

    protected static void EncodeTextArray(CborWriter writer, string[] values)
    {
        writer.WriteStartArray(values.Length);
        foreach (var value in values)
        {
            writer.WriteTextString(value);
        }

        writer.WriteEndArray();
    }

    protected static byte[] Finish(CborWriter writer)
    {
        var bytes = new byte[writer.BytesWritten];
        writer.Encode(bytes);
        return bytes;
    }
}
