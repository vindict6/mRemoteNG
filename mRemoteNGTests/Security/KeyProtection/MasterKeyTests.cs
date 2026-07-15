using System.Linq;
using mRemoteNG.Security.KeyProtection;
using NUnit.Framework;

namespace mRemoteNGTests.Security.KeyProtection
{
    public class MasterKeyTests
    {
        [Test]
        public void GeneratedKeyIsTheSizeAes256Requires()
        {
            Assert.That(MasterKey.Generate().Length, Is.EqualTo(32));
        }

        [Test]
        public void GeneratedKeysAreNotRepeated()
        {
            // A repeat here would mean the key source is broken, which no amount of wrapping survives.
            byte[][] keys = Enumerable.Range(0, 50).Select(_ => MasterKey.Generate()).ToArray();
            int distinct = keys.Select(System.Convert.ToBase64String).Distinct().Count();

            Assert.That(distinct, Is.EqualTo(keys.Length));
        }

        [Test]
        public void GeneratedKeyIsNotAllZeroes()
        {
            Assert.That(MasterKey.Generate().All(b => b == 0), Is.False);
        }

        [Test]
        public void ClearOverwritesTheKeyMaterial()
        {
            byte[] key = MasterKey.Generate();

            MasterKey.Clear(key);

            Assert.That(key.All(b => b == 0), Is.True);
        }

        [Test]
        public void ClearToleratesNull()
        {
            Assert.That(() => MasterKey.Clear(null), Throws.Nothing);
        }
    }
}
