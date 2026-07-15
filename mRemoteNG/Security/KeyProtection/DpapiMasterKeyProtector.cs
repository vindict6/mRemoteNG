using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace mRemoteNG.Security.KeyProtection
{
    /// <summary>
    /// Binds a connection file's master key to the current Windows user account via DPAPI.
    /// </summary>
    /// <remarks>
    /// A wrapped key is only recoverable by the same Windows account on the same machine, so a copied
    /// connection file is inert: there is no passphrase to guess and no shared constant to look up.
    /// Moving a file between machines deliberately goes through export, which re-keys the copy under a
    /// passphrase the user chooses, rather than exposing this key.
    ///
    /// CurrentUser rather than LocalMachine: LocalMachine would let any account on the same box, including
    /// low-privilege service accounts, recover every stored credential.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public sealed class DpapiMasterKeyProtector : IMasterKeyProtector
    {
        /// <summary>
        /// Additional entropy, mixed in so that a blob taken from this application cannot be unwrapped by
        /// simply handing it to ProtectedData from another application running as the same user. It is a
        /// domain separator, not a secret, and must never change: an altered value strands existing files.
        /// </summary>
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("mRemoteNG.ConnectionFile.MasterKey.v1");

        public byte[] Protect(byte[] masterKey)
        {
            if (masterKey == null || masterKey.Length == 0)
                throw new ArgumentException(@"A master key is required.", nameof(masterKey));

            try
            {
                return ProtectedData.Protect(masterKey, Entropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException ex)
            {
                throw new EncryptionException("Could not protect the master key with DPAPI.", ex);
            }
        }

        public byte[] Unprotect(byte[] protectedKey)
        {
            if (protectedKey == null || protectedKey.Length == 0)
                throw new ArgumentException(@"A protected key is required.", nameof(protectedKey));

            try
            {
                return ProtectedData.Unprotect(protectedKey, Entropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException ex)
            {
                // The expected path when a file is copied from another machine or another Windows account.
                // The caller turns this into "import this file instead", so the message has to stay accurate.
                throw new EncryptionException(
                    "This connection file's master key belongs to a different Windows user or machine. " +
                    "Use an exported copy and its export key to move connections between machines.", ex);
            }
        }
    }
}
