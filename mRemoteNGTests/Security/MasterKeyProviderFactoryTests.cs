using System;
using System.Xml.Linq;
using mRemoteNG.Config.Serializers.ConnectionSerializers.Xml;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Security.SymmetricEncryption;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class MasterKeyProviderFactoryTests
    {
        private MasterKeyProviderFactory _factory;

        [SetUp]
        public void Setup()
        {
            _factory = new MasterKeyProviderFactory();
        }

        [Test]
        public void ANewFileGetsAProviderAndAWrappedKey()
        {
            MasterKeyedProvider created = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(created.Provider, Is.Not.Null);
            Assert.That(created.ProtectedKeyBase64, Is.Not.Empty);
        }

        [Test]
        public void SecretsSurviveARoundTripThroughTheWrappedKey()
        {
            // The whole point: what one session writes, a later session must be able to read back using
            // only what was stored in the file.
            MasterKeyedProvider created = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);
            string cipherText = created.Provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());

            MasterKeyedProvider reopened =
                _factory.FromProtectedKey(created.ProtectedKeyBase64, BlockCipherEngines.AES, BlockCipherModes.GCM);

            Assert.That(reopened.Provider.Decrypt(cipherText, "ignored".ConvertToSecureString()),
                        Is.EqualTo("MySecret!"));
        }

        [Test]
        public void EachNewFileGetsItsOwnKey()
        {
            MasterKeyedProvider first = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);
            MasterKeyedProvider second = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);

            string cipherText = first.Provider.Encrypt("MySecret!", "ignored".ConvertToSecureString());

            Assert.That(() => second.Provider.Decrypt(cipherText, "ignored".ConvertToSecureString()),
                        Throws.Exception);
        }

        [Test]
        public void AMissingKeyIsReportedRatherThanAssumed()
        {
            Assert.That(() => _factory.FromProtectedKey("", BlockCipherEngines.AES, BlockCipherModes.GCM),
                        Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void ACorruptKeyIsReportedAsSuch()
        {
            Assert.That(() => _factory.FromProtectedKey("not base64 at all!!", BlockCipherEngines.AES, BlockCipherModes.GCM),
                        Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void XmlHeaderDeclaringDpapiYieldsAMasterKeyedProvider()
        {
            MasterKeyedProvider created = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);
            XElement root = BuildRoot(ConnectionFileProtection.Dpapi, created.ProtectedKeyBase64);

            ICryptographyProvider provider = new CryptoProviderFactoryFromXml(root).Build();

            Assert.That(provider, Is.TypeOf<MasterKeyCryptographyProvider>());
        }

        [Test]
        public void XmlHeaderWithoutKeyProtectionStaysOnTheLegacyPasswordPath()
        {
            // Existing files carry no KeyProtection attribute and must keep opening exactly as before.
            XElement root = BuildRoot(null, null);

            ICryptographyProvider provider = new CryptoProviderFactoryFromXml(root).Build();

            Assert.That(provider, Is.TypeOf<AeadCryptographyProvider>());
        }

        [Test]
        public void XmlHeaderClaimingDpapiWithoutAKeyFailsLoudly()
        {
            // Must not degrade to a provider that cannot read the file: that would surface as corrupt
            // secrets rather than as a clear "this file is not yours".
            XElement root = BuildRoot(ConnectionFileProtection.Dpapi, null);

            Assert.That(() => new CryptoProviderFactoryFromXml(root).Build(),
                        Throws.TypeOf<EncryptionException>());
        }

        [Test]
        public void XmlRootNodeCarriesTheProtectionModeAndKey()
        {
            MasterKeyedProvider created = _factory.CreateNew(BlockCipherEngines.AES, BlockCipherModes.GCM);
            XmlRootNodeSerializer serializer = new();

            XElement root = serializer.SerializeRootNodeInfo(
                new mRemoteNG.Tree.Root.RootNodeInfo(mRemoteNG.Tree.Root.RootNodeType.Connection),
                created.Provider, new Version(2, 6), false, created.ProtectedKeyBase64);

            Assert.That(root.Attribute(ConnectionFileProtection.AttributeName)?.Value,
                        Is.EqualTo(ConnectionFileProtection.Dpapi));
            Assert.That(root.Attribute(ConnectionFileProtection.ProtectedKeyAttributeName)?.Value,
                        Is.EqualTo(created.ProtectedKeyBase64));
        }

        [Test]
        public void XmlRootNodeOmitsTheProtectionModeForLegacyFiles()
        {
            XmlRootNodeSerializer serializer = new();

            XElement root = serializer.SerializeRootNodeInfo(
                new mRemoteNG.Tree.Root.RootNodeInfo(mRemoteNG.Tree.Root.RootNodeType.Connection),
                new AeadCryptographyProvider(), new Version(2, 6));

            Assert.That(root.Attribute(ConnectionFileProtection.AttributeName), Is.Null);
            Assert.That(root.Attribute(ConnectionFileProtection.ProtectedKeyAttributeName), Is.Null);
        }

        private static XElement BuildRoot(string keyProtection, string protectedKey)
        {
            XElement root = new("Connections",
                                new XAttribute("EncryptionEngine", "AES"),
                                new XAttribute("BlockCipherMode", "GCM"),
                                new XAttribute("KdfIterations", "1000"));

            if (keyProtection != null)
                root.Add(new XAttribute(ConnectionFileProtection.AttributeName, keyProtection));
            if (protectedKey != null)
                root.Add(new XAttribute(ConnectionFileProtection.ProtectedKeyAttributeName, protectedKey));

            return root;
        }
    }
}
