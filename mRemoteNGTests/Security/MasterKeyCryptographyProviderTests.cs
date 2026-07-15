using System;
using mRemoteNG.Security;
using mRemoteNG.Security.KeyProtection;
using mRemoteNG.Security.SymmetricEncryption;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class MasterKeyCryptographyProviderTests
    {
        private byte[] _masterKey;
        private MasterKeyCryptographyProvider _provider;

        [SetUp]
        public void Setup()
        {
            _masterKey = MasterKey.Generate();
            _provider = new MasterKeyCryptographyProvider(new AeadCryptographyProvider(), _masterKey);
        }

        [Test]
        public void SecretRoundTripsThroughTheProviderInterface()
        {
            const string plainText = "MySecret!";

            string cipherText = _provider.Encrypt(plainText, "ignored".ConvertToSecureString());

            Assert.That(_provider.Decrypt(cipherText, "ignored".ConvertToSecureString()), Is.EqualTo(plainText));
        }

        [Test]
        public void PassedPasswordIsIgnored()
        {
            // The serializers hand over RootNodeInfo.PasswordString on every call. For a master-keyed
            // file that value is irrelevant, and decryption must not depend on it.
            string cipherText = _provider.Encrypt("MySecret!", "one password".ConvertToSecureString());

            string decrypted = _provider.Decrypt(cipherText, "a completely different password".ConvertToSecureString());

            Assert.That(decrypted, Is.EqualTo("MySecret!"));
        }

        [Test]
        public void AProviderHoldingADifferentMasterKeyCannotDecrypt()
        {
            string cipherText = _provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());
            MasterKeyCryptographyProvider other =
                new(new AeadCryptographyProvider(), MasterKey.Generate());

            Assert.That(() => other.Decrypt(cipherText, "ignored".ConvertToSecureString()), Throws.Exception);
        }

        [Test]
        public void ReportsTheUnderlyingCipher()
        {
            // The root node records these, so they must reflect what actually encrypted the file.
            Assert.That(_provider.CipherEngine, Is.EqualTo(BlockCipherEngines.AES));
            Assert.That(_provider.CipherMode, Is.EqualTo(BlockCipherModes.GCM));
        }

        [Test]
        public void ReportsNoKeyDerivationIterations()
        {
            // A random master key is not derived, so there is no iteration count to report.
            Assert.That(_provider.KeyDerivationIterations, Is.EqualTo(0));
        }

        [Test]
        public void SettingKeyDerivationIterationsIsHarmless()
        {
            // Callers copy this from the file's KdfIterations attribute without checking the mode.
            Assert.That(() => _provider.KeyDerivationIterations = 10000, Throws.Nothing);
            Assert.That(_provider.KeyDerivationIterations, Is.EqualTo(0));
        }

        [Test]
        public void RejectsAKeyOfTheWrongLength()
        {
            Assert.That(() => new MasterKeyCryptographyProvider(new AeadCryptographyProvider(), new byte[16]),
                        Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void RejectsANullKey()
        {
            Assert.That(() => new MasterKeyCryptographyProvider(new AeadCryptographyProvider(), null),
                        Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void OutputIsNotReadableByThePasswordPath()
        {
            // Guards the format split: a master-keyed file must never be mistaken for a password one.
            string cipherText = _provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());
            AeadCryptographyProvider passwordProvider = new();

            Assert.That(() => passwordProvider.Decrypt(cipherText, "mR3m".ConvertToSecureString()),
                        Throws.Exception);
        }
    }
}
