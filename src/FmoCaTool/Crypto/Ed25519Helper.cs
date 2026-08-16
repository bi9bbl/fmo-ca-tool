using System.Security.Cryptography;

namespace FmoCaTool.Crypto;

public static class Ed25519Helper
{
    public const int SeedSize = 32;
    public const int PublicKeySize = 32;
    public const int ExpandedPrivateKeySize = 64;
    public const int SignatureSize = 64;

    public static KeyMaterial Generate()
    {
        var seed = RandomNumberGenerator.GetBytes(SeedSize);
        return FromSeed(seed);
    }

    public static KeyMaterial FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != SeedSize)
        {
            throw new CliException($"Ed25519 private key seed must be exactly {SeedSize} bytes.");
        }

        Chaos.NaCl.Ed25519.KeyPairFromSeed(out var publicKey, out _, seed);
        return new KeyMaterial(seed.ToArray(), publicKey);
    }

    public static byte[] DerivePublicKey(byte[] seed)
    {
        var material = FromSeed(seed);
        return material.PublicKey;
    }

    public static byte[] Sign(byte[] seed, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        Chaos.NaCl.Ed25519.KeyPairFromSeed(out _, out var expandedPrivateKey, seed);
        try
        {
            return Chaos.NaCl.Ed25519.Sign(data, expandedPrivateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expandedPrivateKey);
        }
    }

    public static bool Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        if (publicKey.Length != PublicKeySize || signature.Length != SignatureSize)
        {
            return false;
        }

        return Chaos.NaCl.Ed25519.Verify(signature, data, publicKey);
    }
}

public sealed record KeyMaterial(byte[] Seed, byte[] PublicKey);
