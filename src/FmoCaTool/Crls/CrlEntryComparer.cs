namespace FmoCaTool.Crls;

internal static class CrlEntryComparer
{
    public static RootCrlEntry[] Sort(IEnumerable<RootCrlEntry> entries) => entries
        .OrderBy(entry => entry.Sn)
        .ThenBy(entry => entry.CertFingerprint, ByteArrayComparer.Instance)
        .ToArray();

    public static IntermediateCrlEntry[] Sort(IEnumerable<IntermediateCrlEntry> entries) => entries
        .OrderBy(entry => entry.Uid)
        .ThenBy(entry => entry.CertFingerprint, ByteArrayComparer.Instance)
        .ToArray();

    public static bool IsSorted(IReadOnlyList<RootCrlEntry> entries) =>
        entries.SequenceEqual(Sort(entries), RootEntryEqualityComparer.Instance);

    public static bool IsSorted(IReadOnlyList<IntermediateCrlEntry> entries) =>
        entries.SequenceEqual(Sort(entries), IntermediateEntryEqualityComparer.Instance);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public int Compare(byte[]? left, byte[]? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            if (right is null)
            {
                return 1;
            }

            return left.AsSpan().SequenceCompareTo(right);
        }
    }

    private sealed class RootEntryEqualityComparer : IEqualityComparer<RootCrlEntry>
    {
        public static RootEntryEqualityComparer Instance { get; } = new();

        public bool Equals(RootCrlEntry? left, RootCrlEntry? right) => left is not null && right is not null
            && left.Sn == right.Sn
            && left.RevokedAt == right.RevokedAt
            && left.Reason == right.Reason
            && left.CertFingerprint.AsSpan().SequenceEqual(right.CertFingerprint);

        public int GetHashCode(RootCrlEntry value) => HashCode.Combine(value.Sn, value.RevokedAt, value.Reason);
    }

    private sealed class IntermediateEntryEqualityComparer : IEqualityComparer<IntermediateCrlEntry>
    {
        public static IntermediateEntryEqualityComparer Instance { get; } = new();

        public bool Equals(IntermediateCrlEntry? left, IntermediateCrlEntry? right) => left is not null && right is not null
            && left.Uid == right.Uid
            && left.RevokedAt == right.RevokedAt
            && left.Reason == right.Reason
            && left.CertFingerprint.AsSpan().SequenceEqual(right.CertFingerprint);

        public int GetHashCode(IntermediateCrlEntry value) => HashCode.Combine(value.Uid, value.RevokedAt, value.Reason);
    }
}
