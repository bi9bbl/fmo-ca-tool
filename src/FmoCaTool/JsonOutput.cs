using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace FmoCaTool;

internal static class JsonOutput
{
    public static JsonWriterOptions WriterOptions { get; } = new()
    {
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string Finish(MemoryStream stream) => Encoding.UTF8.GetString(stream.ToArray()) + "\n";
}
