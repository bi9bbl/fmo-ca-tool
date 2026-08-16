namespace FmoCaTool.Certs;

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    public static byte[] Decode(string encoded, string fieldName = "base64url value")
    {
        if (encoded is null)
        {
            throw new CliException($"{fieldName} is missing.");
        }

        var value = encoded.Trim().Replace('-', '+').Replace('_', '/');
        switch (value.Length % 4)
        {
            case 0:
                break;
            case 2:
                value += "==";
                break;
            case 3:
                value += "=";
                break;
            default:
                throw new CliException($"{fieldName} is not valid base64url.");
        }

        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new CliException($"{fieldName} is not valid base64url.", ex);
        }
    }
}
