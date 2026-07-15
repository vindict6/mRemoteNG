using System;
using System.Runtime.Versioning;
using mRemoteNG.Security.KeyProtection;
using mRemoteNG.Security.SymmetricEncryption;

namespace mRemoteNG.Security.Factories
{
    /// <summary>
    /// Creates and recovers the master-keyed providers used by machine-bound connection files.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class MasterKeyProviderFactory
    {
        private readonly IMasterKeyProtector _protector;

        public MasterKeyProviderFactory()
            : this(new DpapiMasterKeyProtector())
        {
        }

        public MasterKeyProviderFactory(IMasterKeyProtector protector)
        {
            _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        }

        /// <summary>
        /// Mints a master key for a new file and wraps it for this machine and Windows account.
        /// </summary>
        public MasterKeyedProvider CreateNew(BlockCipherEngines engine, BlockCipherModes mode)
        {
            byte[] masterKey = MasterKey.Generate();
            byte[] protectedKey = _protector.Protect(masterKey);
            return Build(engine, mode, masterKey, protectedKey);
        }

        /// <summary>
        /// Recovers the provider for an existing file from its stored wrapped key.
        /// </summary>
        /// <exception cref="EncryptionException">
        /// The key belongs to another machine or Windows account, so the file cannot be read here.
        /// </exception>
        public MasterKeyedProvider FromProtectedKey(string protectedKeyBase64, BlockCipherEngines engine, BlockCipherModes mode)
        {
            if (string.IsNullOrWhiteSpace(protectedKeyBase64))
                throw new EncryptionException("This connection file claims machine-bound protection but carries no key.");

            byte[] protectedKey;
            try
            {
                protectedKey = Convert.FromBase64String(protectedKeyBase64);
            }
            catch (FormatException ex)
            {
                throw new EncryptionException("This connection file's protected key is corrupt.", ex);
            }

            byte[] masterKey = _protector.Unprotect(protectedKey);
            return Build(engine, mode, masterKey, protectedKey);
        }

        private static MasterKeyedProvider Build(BlockCipherEngines engine, BlockCipherModes mode, byte[] masterKey, byte[] protectedKey)
        {
            // Reuses the engine/mode selection so a master-keyed file honours the configured cipher.
            AeadCryptographyProvider aead = (AeadCryptographyProvider)new CryptoProviderFactory(engine, mode).Build();
            MasterKeyCryptographyProvider provider = new(aead, masterKey);
            return new MasterKeyedProvider(provider, Convert.ToBase64String(protectedKey));
        }
    }

    /// <summary>
    /// A master-keyed provider together with the wrapped key that has to be written beside the file.
    /// </summary>
    /// <remarks>
    /// The two travel together because a file is unreadable without both: losing the wrapped key
    /// strands every secret in the file.
    /// </remarks>
    public sealed class MasterKeyedProvider(MasterKeyCryptographyProvider provider, string protectedKeyBase64)
    {
        public MasterKeyCryptographyProvider Provider { get; } = provider;

        /// <summary>
        /// The wrapped master key, for the root node's ProtectedKey attribute.
        /// </summary>
        public string ProtectedKeyBase64 { get; } = protectedKeyBase64;
    }
}
