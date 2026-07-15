using System;
using System.Runtime.Versioning;
using System.Xml.Linq;
using mRemoteNG.Config.Serializers.ConnectionSerializers.Xml;
using mRemoteNG.Security.SymmetricEncryption;

namespace mRemoteNG.Security.Factories
{
    [SupportedOSPlatform("windows")]
    public class CryptoProviderFactoryFromXml : ICryptoProviderFactory
    {
        private readonly XElement _element;

        public CryptoProviderFactoryFromXml(XElement element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            _element = element;
        }

        public ICryptographyProvider Build()
        {
            ICryptographyProvider cryptoProvider;
            BlockCipherEngines engine;
            BlockCipherModes mode;

            try
            {
                engine = (BlockCipherEngines)Enum.Parse(typeof(BlockCipherEngines),
                                                        _element?.Attribute("EncryptionEngine")?.Value ?? "");
                mode = (BlockCipherModes)Enum.Parse(typeof(BlockCipherModes),
                                                    _element?.Attribute("BlockCipherMode")?.Value ?? "");
                cryptoProvider = new CryptoProviderFactory(engine, mode).Build();

                int keyDerivationIterations = int.Parse(_element?.Attribute("KdfIterations")?.Value ?? "");
                cryptoProvider.KeyDerivationIterations = keyDerivationIterations;
            }
            catch (Exception)
            {
                return new LegacyRijndaelCryptographyProvider();
            }

            // Deliberately outside the catch above. That catch treats an unreadable header as "this is
            // an ancient file, fall back to Rijndael", which is right for a missing attribute but wrong
            // here: a file that says it is machine-bound and then fails to yield its key must report
            // that, not silently degrade to a provider that cannot read it and will look like corruption.
            string protection = _element?.Attribute(ConnectionFileProtection.AttributeName)?.Value
                                ?? ConnectionFileProtection.Legacy;

            if (protection == ConnectionFileProtection.Dpapi)
            {
                string protectedKey = _element?.Attribute(ConnectionFileProtection.ProtectedKeyAttributeName)?.Value ?? "";
                return new MasterKeyProviderFactory().FromProtectedKey(protectedKey, engine, mode).Provider;
            }

            return cryptoProvider;
        }
    }
}