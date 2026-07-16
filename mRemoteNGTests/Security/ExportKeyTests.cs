using System;
using System.Diagnostics;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Security.KeyDerivation;
using mRemoteNG.Security.SymmetricEncryption;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class ExportKeyTests
    {
        private MasterKeyProviderFactory _factory;

        [SetUp]
        public void Setup()
        {
            _factory = new MasterKeyProviderFactory();
        }

        [Test]
        public void AnExportCanBeReopenedWithItsExportKey()
        {
            // The core promise: any machine holding the file and the key can read it.
            ExportKeyedProvider export = _factory.CreateForExport("correct horse battery", BlockCipherEngines.AES, BlockCipherModes.GCM);
            string cipherText = export.Provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());

            MasterKeyCryptographyProvider imported = _factory.FromPassphrase(
                "correct horse battery", export.SaltBase64, export.MemoryKb, export.Parallelism, export.Iterations,
                BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(imported.Decrypt(cipherText, "ignored".ConvertToSecureString()), Is.EqualTo("MySecret!"));
        }

        [Test]
        public void TheWrongExportKeyCannotReadTheExport()
        {
            ExportKeyedProvider export = _factory.CreateForExport("correct horse battery", BlockCipherEngines.AES, BlockCipherModes.GCM);
            string cipherText = export.Provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());

            MasterKeyCryptographyProvider wrong = _factory.FromPassphrase(
                "wrong horse battery", export.SaltBase64, export.MemoryKb, export.Parallelism, export.Iterations,
                BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(() => wrong.Decrypt(cipherText, "ignored".ConvertToSecureString()), Throws.Exception);
        }

        [Test]
        public void EveryExportUsesADifferentKeyEvenWithTheSamePassphrase()
        {
            // Explicitly required: exporting twice must not produce two files sharing a key, so that
            // disclosing one export's key cannot unlock another.
            ExportKeyedProvider first = _factory.CreateForExport("same passphrase", BlockCipherEngines.AES, BlockCipherModes.GCM);
            ExportKeyedProvider second = _factory.CreateForExport("same passphrase", BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(first.SaltBase64, Is.Not.EqualTo(second.SaltBase64));

            // And concretely: the second export's derived key cannot read the first export.
            string cipherText = first.Provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());
            Assert.That(() => second.Provider.Decrypt(cipherText, "ignored".ConvertToSecureString()), Throws.Exception);
        }

        [Test]
        public void AnExportRecordsItsDerivationParametersSoFutureDefaultsCannotStrandIt()
        {
            ExportKeyedProvider export = _factory.CreateForExport("passphrase", BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(export.SaltBase64, Is.Not.Empty);
            Assert.That(export.MemoryKb, Is.EqualTo(Argon2idKeyGenerator.DefaultMemoryKb));
            Assert.That(export.Parallelism, Is.EqualTo(Argon2idKeyGenerator.DefaultParallelism));
            Assert.That(export.Iterations, Is.EqualTo(Argon2idKeyGenerator.DefaultIterations));
        }

        [Test]
        public void AnExportWrittenWithOlderParametersStillImports()
        {
            // Simulates a file exported before the defaults changed: importing must honour what the file
            // says, not what the current build would choose.
            const int oldMemory = 8192;
            const int oldIterations = 2;
            const int oldParallelism = 1;

            byte[] salt = new byte[16];
            new Random(1).NextBytes(salt);
            string saltB64 = Convert.ToBase64String(salt);

            byte[] key = new Argon2idKeyGenerator(256, oldMemory, oldIterations, oldParallelism).DeriveKey("passphrase", salt);
            MasterKeyCryptographyProvider writer = new(new AeadCryptographyProvider(), key);
            string cipherText = writer.Encrypt("MySecret!", "ignored".ConvertToSecureString());

            MasterKeyCryptographyProvider reader = _factory.FromPassphrase(
                "passphrase", saltB64, oldMemory, oldParallelism, oldIterations,
                BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(reader.Decrypt(cipherText, "ignored".ConvertToSecureString()), Is.EqualTo("MySecret!"));
        }

        [Test]
        public void AnEmptyExportKeyIsRefused()
        {
            Assert.That(() => _factory.CreateForExport("", BlockCipherEngines.AES, BlockCipherModes.GCM),
                        Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void ACorruptSaltIsReportedClearly()
        {
            Assert.That(() => _factory.FromPassphrase("passphrase", "not base64!!", 8192, 1, 2,
                                                      BlockCipherEngines.AES, BlockCipherModes.GCM),
                        Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void AMissingSaltIsReportedClearly()
        {
            Assert.That(() => _factory.FromPassphrase("passphrase", "", 8192, 1, 2,
                                                      BlockCipherEngines.AES, BlockCipherModes.GCM),
                        Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void Argon2idIsDeterministicForTheSamePassphraseAndSalt()
        {
            byte[] salt = new byte[16];
            new Random(7).NextBytes(salt);
            Argon2idKeyGenerator kdf = new(256, 8192, 2, 1);

            Assert.That(kdf.DeriveKey("passphrase", salt), Is.EqualTo(kdf.DeriveKey("passphrase", salt)));
        }

        [Test]
        public void Argon2idSeparatesDifferentPassphrases()
        {
            byte[] salt = new byte[16];
            new Random(9).NextBytes(salt);
            Argon2idKeyGenerator kdf = new(256, 8192, 2, 1);

            Assert.That(kdf.DeriveKey("passphrase a", salt), Is.Not.EqualTo(kdf.DeriveKey("passphrase b", salt)));
        }

        [Test]
        public void Argon2idProducesAnAes256SizedKey()
        {
            byte[] salt = new byte[16];
            new Random(11).NextBytes(salt);

            Assert.That(new Argon2idKeyGenerator(256, 8192, 2, 1).DeriveKey("passphrase", salt).Length, Is.EqualTo(32));
        }

        [Test]
        public void DerivingAtTheDefaultCostIsSlowEnoughToBeWorthSomething()
        {
            // Guards the point of Argon2id here. If a defaults change ever made derivation trivially
            // fast, offline guessing against an exported file would get cheap again, and nothing else
            // in the suite would notice.
            byte[] salt = new byte[16];
            new Random(13).NextBytes(salt);

            Stopwatch stopwatch = Stopwatch.StartNew();
            new Argon2idKeyGenerator().DeriveKey("passphrase", salt);
            stopwatch.Stop();

            Assert.That(stopwatch.ElapsedMilliseconds, Is.GreaterThan(20),
                        "Argon2id derivation finished suspiciously fast; check the cost parameters.");
        }

        [Test]
        public void RejectsNonsensicalCostParameters()
        {
            Assert.That(() => new Argon2idKeyGenerator(256, 0, 1, 1), Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => new Argon2idKeyGenerator(256, 8192, 0, 1), Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => new Argon2idKeyGenerator(256, 8192, 1, 0), Throws.TypeOf<ArgumentOutOfRangeException>());
        }
    }
}
