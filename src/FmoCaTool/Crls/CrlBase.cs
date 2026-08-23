using System.Formats.Cbor;

namespace FmoCaTool.Crls;

public abstract class CrlBase
{
    public abstract string Type { get; }

    public abstract byte[] ToTbsCbor();

    protected static CborWriter CreateWriter() => new(CborConformanceMode.Lax);

    protected static byte[] Finish(CborWriter writer)
    {
        var bytes = new byte[writer.BytesWritten];
        writer.Encode(bytes);
        return bytes;
    }
}
