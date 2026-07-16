using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using mRemoteNG.Security.KeyDerivation;
using mRemoteNG.Security.KeyProtection;
using mRemoteNG.Security.SymmetricEncryption;

namespace mRemoteNG.Security.Factories
{
    /// <summary>
    /// Creates and recovers the master-keyed providers used by machine-bound and exported connection files.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class MasterKeyProviderFactory
    {
        /// <summary>
        /// 128 bits, matching the salt the password scheme already uses.
        /// </summary>
        private const int SaltSizeInBytes = 16;

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

        /// <summary>
        /// Derives an export's key from a passphrase, minting a fresh salt.
        /// </summary>
        /// <remarks>
        /// A new salt per export is what makes every export a different key even when the user types the
        /// same passphrase, so two exported copies share no key material. The internal DPAPI-wrapped key
        /// is never involved: an export is a re-encrypted copy, so handing one out cannot weaken the
        /// file it came from.
        /// </remarks>
        public ExportKeyedProvider CreateForExport(string passphrase, BlockCipherEngines engine, BlockCipherModes mode)
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new ArgumentException(@"An export key is required.", nameof(passphrase));

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeInBytes);
            Argon2idKeyGenerator kdf = new();
            byte[] key = kdf.DeriveKey(passphrase, salt);

            return new ExportKeyedProvider(BuildProvider(engine, mode, key), Convert.ToBase64String(salt),
                                           kdf.MemoryKb, kdf.Parallelism, kdf.Iterations);
        }

        /// <summary>
        /// Re-derives an export's key on the importing machine.
        /// </summary>
        /// <remarks>
        /// Uses the parameters recorded in the file rather than the current defaults, so an export stays
        /// importable after those defaults change.
        /// </remarks>
        public MasterKeyCryptographyProvider FromPassphrase(string passphrase, string saltBase64, int memoryKb,
                                                            int parallelism, int iterations,
                                                            BlockCipherEngines engine, BlockCipherModes mode)
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new ArgumentException(@"An export key is required.", nameof(passphrase));

            byte[] salt;
            try
            {
                salt = Convert.FromBase64String(saltBase64 ?? "");
            }
            catch (FormatException ex)
            {
                throw new EncryptionException("This exported file's key derivation salt is corrupt.", ex);
            }

            if (salt.Length == 0)
                throw new EncryptionException("This exported file carries no key derivation salt.");

            byte[] key = new Argon2idKeyGenerator(256, memoryKb, iterations, parallelism).DeriveKey(passphrase, salt);
            return BuildProvider(engine, mode, key);
        }

        private static MasterKeyCryptographyProvider BuildProvider(BlockCipherEngines engine, BlockCipherModes mode, byte[] key)
        {
            AeadCryptographyProvider aead = (AeadCryptographyProvider)new CryptoProviderFactory(engine, mode).Build();
            return new MasterKeyCryptographyProvider(aead, key);
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

    /// <summary>
    /// A passphrase-keyed provider together with the derivation parameters an importer needs.
    /// </summary>
    /// <remarks>
    /// Carries no key material: an export records only how to re-derive the key from the passphrase,
    /// never the key itself, so the file discloses nothing to someone who does not know the passphrase.
    /// </remarks>
    public sealed class ExportKeyedProvider(MasterKeyCryptographyProvider provider, string saltBase64,
                                            int memoryKb, int parallelism, int iterations)
    {
        public MasterKeyCryptographyProvider Provider { get; } = provider;

        public string SaltBase64 { get; } = saltBase64;

        public int MemoryKb { get; } = memoryKb;

        public int Parallelism { get; } = parallelism;

        public int Iterations { get; } = iterations;
    }
}
