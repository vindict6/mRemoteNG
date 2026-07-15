using System;
using System.Runtime.Versioning;
using System.Security;
using mRemoteNG.Security.KeyProtection;

namespace mRemoteNG.Security.SymmetricEncryption
{
    /// <summary>
    /// Encrypts secrets with a master key that was already recovered for the file, rather than deriving
    /// a key from a password on every call.
    /// </summary>
    /// <remarks>
    /// This exists to fit a master key into call sites that were written around a password. The
    /// serializers encrypt each secret individually via <see cref="ICryptographyProvider"/>, passing the
    /// file password every time; with a password-derived key that means one PBKDF2 run per secret, which
    /// is why the iteration count had to stay low enough to be brute-forceable. Handing those call sites
    /// this provider instead removes the per-secret derivation entirely.
    ///
    /// The SecureString arguments are IGNORED. That is safe only because the key for these files is the
    /// master key and nothing else: the callers pass RootNodeInfo.PasswordString, which for a
    /// master-keyed file is not what protects anything. It would NOT be safe to hand this provider to a
    /// caller that expects a user-supplied password to matter — such a caller would believe it had
    /// encrypted under that password. Export deliberately uses a passphrase-derived provider instead.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public sealed class MasterKeyCryptographyProvider : ICryptographyProvider
    {
        private readonly AeadCryptographyProvider _provider;
        private readonly byte[] _masterKey;

        public MasterKeyCryptographyProvider(AeadCryptographyProvider provider, byte[] masterKey)
        {
            if (masterKey == null || masterKey.Length != MasterKey.KeySizeInBytes)
                throw new ArgumentException($"Master key must be {MasterKey.KeySizeInBytes} bytes.", nameof(masterKey));

            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _masterKey = masterKey;
        }

        public int BlockSizeInBytes => _provider.BlockSizeInBytes;

        public BlockCipherEngines CipherEngine => _provider.CipherEngine;

        public BlockCipherModes CipherMode => _provider.CipherMode;

        /// <summary>
        /// Always zero: a random master key is not derived from anything, so there is nothing to iterate.
        /// </summary>
        /// <remarks>
        /// The setter is a no-op rather than a throw because callers copy this across from a file's
        /// KdfIterations attribute without knowing which protection is in use.
        /// </remarks>
        public int KeyDerivationIterations
        {
            get => 0;
            set { }
        }

        /// <param name="encryptionKey">Ignored. See the remarks on the class.</param>
        public string Encrypt(string plainText, SecureString encryptionKey)
        {
            return _provider.EncryptWithKey(plainText, _masterKey);
        }

        /// <param name="decryptionKey">Ignored. See the remarks on the class.</param>
        public string Decrypt(string cipherText, SecureString decryptionKey)
        {
            return _provider.DecryptWithKey(cipherText, _masterKey);
        }
    }
}
