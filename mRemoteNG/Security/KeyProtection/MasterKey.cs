using System;
using System.Security.Cryptography;

namespace mRemoteNG.Security.KeyProtection
{
    /// <summary>
    /// The random symmetric key that protects the secrets inside a single connection file.
    /// </summary>
    public static class MasterKey
    {
        /// <summary>
        /// Matches AeadCryptographyProvider.KeyBitSize; AES-256-GCM rejects any other length.
        /// </summary>
        public const int KeySizeInBytes = 32;

        /// <summary>
        /// Creates a new master key from a cryptographically secure source.
        /// </summary>
        /// <remarks>
        /// Random, never derived from a passphrase: nothing the user knows or reuses can weaken it, and
        /// there is nothing to brute force. Confidentiality rests entirely on how the key is wrapped.
        /// </remarks>
        public static byte[] Generate()
        {
            return RandomNumberGenerator.GetBytes(KeySizeInBytes);
        }

        /// <summary>
        /// Overwrites key material once it is no longer needed.
        /// </summary>
        /// <remarks>
        /// Best effort only. The runtime may already have copied the array during a GC compaction, so
        /// this narrows the window rather than closing it.
        /// </remarks>
        public static void Clear(byte[]? key)
        {
            if (key == null) return;
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
