using System;
using mRemoteNG.Security;
using mRemoteNG.Security.KeyProtection;
using mRemoteNG.Security.SymmetricEncryption;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class KeyedCryptographyTests
    {
        private AeadCryptographyProvider _provider;
        private byte[] _key;

        [SetUp]
        public void Setup()
        {
            _provider = new AeadCryptographyProvider();
            _key = MasterKey.Generate();
        }

        [Test]
        public void SecretRoundTripsWithTheSameKey()
        {
            const string plainText = "MySecret!";

            string cipherText = _provider.EncryptWithKey(plainText, _key);

            Assert.That(_provider.DecryptWithKey(cipherText, _key), Is.EqualTo(plainText));
        }

        [Test]
        public void CipherTextDoesNotContainThePlainText()
        {
            const string plainText = "MySecret!";

            string cipherText = _provider.EncryptWithKey(plainText, _key);

            Assert.That(cipherText, Does.Not.Contain(plainText));
        }

        [Test]
        public void EncryptingTheSameSecretTwiceProducesDifferentCipherText()
        {
            // A fresh nonce per call; equal outputs would reveal which connections share a password.
            string first = _provider.EncryptWithKey("MySecret!", _key);
            string second = _provider.EncryptWithKey("MySecret!", _key);

            Assert.That(first, Is.Not.EqualTo(second));
        }

        [Test]
        public void DecryptingWithTheWrongKeyFails()
        {
            string cipherText = _provider.EncryptWithKey("MySecret!", _key);
            byte[] otherKey = MasterKey.Generate();

            // GCM authenticates, so a wrong key must throw rather than return garbage.
            Assert.That(() => _provider.DecryptWithKey(cipherText, otherKey), Throws.Exception);
        }

        [Test]
        public void TamperedCipherTextIsRejected()
        {
            string cipherText = _provider.EncryptWithKey("MySecret!", _key);
            byte[] raw = Convert.FromBase64String(cipherText);
            raw[raw.Length - 1] ^= 0xFF;
            string tampered = Convert.ToBase64String(raw);

            Assert.That(() => _provider.DecryptWithKey(tampered, _key), Throws.Exception);
        }

        [Test]
        public void UnicodeSecretsSurviveTheRoundTrip()
        {
            const string plainText = "pässwörd-日本語-🔐";

            string cipherText = _provider.EncryptWithKey(plainText, _key);

            Assert.That(_provider.DecryptWithKey(cipherText, _key), Is.EqualTo(plainText));
        }

        [Test]
        public void EmptyInputRoundTripsToEmpty()
        {
            // Matches the password overloads, which return "" rather than throwing. Connection files are
            // full of empty optional secrets, so this is the common case, not an edge case.
            Assert.That(_provider.EncryptWithKey("", _key), Is.EqualTo(""));
            Assert.That(_provider.DecryptWithKey("", _key), Is.EqualTo(""));
        }

        [Test]
        public void KeyedOutputIsShorterThanPasswordOutputBecauseItCarriesNoSalt()
        {
            string keyed = _provider.EncryptWithKey("MySecret!", _key);
            string passworded = _provider.Encrypt("MySecret!", "mypassword111111".ConvertToSecureString());

            // Guards the format difference the file format has to record: keyed output omits the
            // 16-byte salt that the password form prepends.
            Assert.That(Convert.FromBase64String(keyed).Length,
                        Is.EqualTo(Convert.FromBase64String(passworded).Length - 16));
        }

        [Test]
        public void DecryptingPasswordCipherTextWithAKeyDoesNotSilentlySucceed()
        {
            string passworded = _provider.Encrypt("MySecret!", "mypassword111111".ConvertToSecureString());

            // The two formats must never be confused for one another.
            Assert.That(() => _provider.DecryptWithKey(passworded, _key), Throws.Exception);
        }

        [Test]
        public void WrongLengthKeyIsRejected()
        {
            Assert.That(() => _provider.EncryptWithKey("MySecret!", new byte[16]),
                        Throws.TypeOf<ArgumentException>());
        }
    }
}
