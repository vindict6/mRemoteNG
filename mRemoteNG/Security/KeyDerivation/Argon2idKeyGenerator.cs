using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace mRemoteNG.Security.KeyDerivation
{
    /// <summary>
    /// Derives a key from a passphrase using Argon2id, for exported connection files.
    /// </summary>
    /// <remarks>
    /// Only exports need this. A machine-bound file's key is random and wrapped by DPAPI, so nothing
    /// is derived and there is nothing to guess. An export has to travel to another machine, so its
    /// key can only come from what the user types, which makes it the one place where an attacker who
    /// holds the file can mount an offline guessing attack. It is therefore worth being slow.
    ///
    /// Argon2id rather than PBKDF2 because the cost is memory as well as time, which is what denies a
    /// GPU or ASIC the parallelism that makes PBKDF2 cheap to attack at scale. The existing
    /// per-secret scheme uses PBKDF2-HMAC-SHA1 at 10,000 iterations, which is far below current
    /// guidance; it can only be raised at all here because export derives once for the whole file
    /// rather than once per secret.
    /// </remarks>
    public class Argon2idKeyGenerator : IKeyDerivationFunction
    {
        /// <summary>
        /// 64 MiB. OWASP's 2023 baseline for Argon2id (19 MiB) is a floor for server-side login, where
        /// many derivations run at once. This derives once when a human exports or imports a file, so a
        /// larger cost is affordable and buys real margin against offline guessing.
        /// </summary>
        public const int DefaultMemoryKb = 65536;

        /// <summary>
        /// Time cost. Paired with the memory above, keeps a derivation in the low hundreds of ms.
        /// </summary>
        public const int DefaultIterations = 3;

        /// <summary>
        /// Fixed rather than taken from the CPU: the same value has to be used to re-derive the key on
        /// whatever machine imports the file, so it cannot depend on local hardware.
        /// </summary>
        public const int DefaultParallelism = 4;

        private readonly int _keyBitSize;
        private readonly int _memoryKb;
        private readonly int _iterations;
        private readonly int _parallelism;

        public Argon2idKeyGenerator(int keyBitSize = 256,
                                    int memoryKb = DefaultMemoryKb,
                                    int iterations = DefaultIterations,
                                    int parallelism = DefaultParallelism)
        {
            if (keyBitSize <= 0 || keyBitSize % 8 != 0)
                throw new ArgumentOutOfRangeException(nameof(keyBitSize), @"Key size must be a positive multiple of 8.");
            if (memoryKb < 8)
                throw new ArgumentOutOfRangeException(nameof(memoryKb), @"Argon2 requires at least 8 KiB of memory.");
            if (iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(iterations), @"Argon2 requires at least one iteration.");
            if (parallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(parallelism), @"Argon2 requires parallelism of at least 1.");

            _keyBitSize = keyBitSize;
            _memoryKb = memoryKb;
            _iterations = iterations;
            _parallelism = parallelism;
        }

        public int MemoryKb => _memoryKb;

        public int Iterations => _iterations;

        public int Parallelism => _parallelism;

        public byte[] DeriveKey(string password, byte[] salt)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt == null || salt.Length == 0)
                throw new ArgumentException(@"A salt is required.", nameof(salt));

            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                                          .WithVersion(Argon2Parameters.Version13)
                                          .WithIterations(_iterations)
                                          .WithMemoryAsKB(_memoryKb)
                                          .WithParallelism(_parallelism)
                                          .WithSalt(salt)
                                          .Build();

            Argon2BytesGenerator generator = new();
            generator.Init(parameters);

            byte[] key = new byte[_keyBitSize / 8];
            generator.GenerateBytes(password.ToCharArray(), key);
            return key;
        }
    }
}
