using System;
using System.Runtime.Versioning;
using System.Xml.Linq;
using mRemoteNG.Security;
using mRemoteNG.Tree.Root;

namespace mRemoteNG.Config.Serializers.ConnectionSerializers.Xml
{
    [SupportedOSPlatform("windows")]
    public class XmlRootNodeSerializer
    {
        /// <param name="protectedKeyBase64">
        /// The wrapped master key, when the file is machine-bound. Null for the legacy password scheme.
        /// Without it a machine-bound file cannot be reopened, so it is written before anything else can
        /// fail.
        /// </param>
        public XElement SerializeRootNodeInfo(RootNodeInfo rootNodeInfo, ICryptographyProvider cryptographyProvider, Version version, bool fullFileEncryption = false, string? protectedKeyBase64 = null)
        {
            XNamespace xmlNamespace = "http://mremoteng.org";
            XElement element = new(xmlNamespace + "Connections");
            element.Add(new XAttribute(XNamespace.Xmlns + "mrng", xmlNamespace));
            element.Add(new XAttribute(XName.Get("Name"), rootNodeInfo.Name));
            element.Add(new XAttribute(XName.Get("Export"), "false"));
            element.Add(new XAttribute(XName.Get("EncryptionEngine"), cryptographyProvider.CipherEngine));
            element.Add(new XAttribute(XName.Get("BlockCipherMode"), cryptographyProvider.CipherMode));
            element.Add(new XAttribute(XName.Get("KdfIterations"), cryptographyProvider.KeyDerivationIterations));
            element.Add(new XAttribute(XName.Get("FullFileEncryption"), fullFileEncryption.ToString().ToLowerInvariant()));

            if (!string.IsNullOrEmpty(protectedKeyBase64))
            {
                element.Add(new XAttribute(XName.Get(ConnectionFileProtection.AttributeName), ConnectionFileProtection.Dpapi));
                element.Add(new XAttribute(XName.Get(ConnectionFileProtection.ProtectedKeyAttributeName), protectedKeyBase64));
            }

            element.Add(CreateProtectedAttribute(rootNodeInfo, cryptographyProvider));
            element.Add(new XAttribute(XName.Get("ConfVersion"), version.ToString(2)));
            return element;
        }

        private XAttribute CreateProtectedAttribute(RootNodeInfo rootNodeInfo, ICryptographyProvider cryptographyProvider)
        {
            XAttribute attribute = new(XName.Get("Protected"), "");
            string plainText = (rootNodeInfo.PasswordString != rootNodeInfo.DefaultPassword) ? "ThisIsProtected" : "ThisIsNotProtected";
            System.Security.SecureString encryptionPassword = rootNodeInfo.PasswordString.ConvertToSecureString();
            attribute.Value = cryptographyProvider.Encrypt(plainText, encryptionPassword);
            return attribute;
        }
    }
}