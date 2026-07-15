using System;
using mRemoteNG.Security;
using mRemoteNG.Security.KeyProtection;
using NUnit.Framework;

namespace mRemoteNGTests.Security.KeyProtection
{
    public class DpapiMasterKeyProtectorTests
    {
        private DpapiMasterKeyProtector _protector;

        [SetUp]
        public void Setup()
        {
            _protector = new DpapiMasterKeyProtector();
        }

        [Test]
        public void ProtectedKeyRoundTripsBackToTheOriginal()
        {
            byte[] masterKey = MasterKey.Generate();

            byte[] recovered = _protector.Unprotect(_protector.Protect(masterKey));

            Assert.That(recovered, Is.EqualTo(masterKey));
        }

        [Test]
        public void ProtectDoesNotLeaveTheKeyInTheClear()
        {
            byte[] masterKey = MasterKey.Generate();

            byte[] protectedKey = _protector.Protect(masterKey);

            // The wrapped blob must not simply contain the key bytes.
            Assert.That(IndexOfSequence(protectedKey, masterKey), Is.EqualTo(-1));
        }

        [Test]
        public void TamperedBlobIsRejectedRatherThanReturningWrongKey()
        {
            byte[] protectedKey = _protector.Protect(MasterKey.Generate());
            protectedKey[protectedKey.Length / 2] ^= 0xFF;

            // Silently returning corrupted key material would surface as unreadable secrets later,
            // so this has to fail loudly at unwrap time.
            Assert.That(() => _protector.Unprotect(protectedKey), Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void ProtectingTheSameKeyTwiceProducesDifferentBlobs()
        {
            byte[] masterKey = MasterKey.Generate();

            byte[] first = _protector.Protect(masterKey);
            byte[] second = _protector.Protect(masterKey);

            Assert.That(first, Is.Not.EqualTo(second));
        }

        [Test]
        public void ProtectRejectsAnEmptyKey()
        {
            Assert.That(() => _protector.Protect(Array.Empty<byte>()), Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void UnprotectRejectsAnEmptyBlob()
        {
            Assert.That(() => _protector.Unprotect(Array.Empty<byte>()), Throws.TypeOf<ArgumentException>());
        }

        private static int IndexOfSequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] == needle[j]) continue;
                    match = false;
                    break;
                }

                if (match) return i;
            }

            return -1;
        }
    }
}
