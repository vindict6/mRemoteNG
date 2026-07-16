namespace mRemoteNG.Config.Serializers.ConnectionSerializers.Xml
{
    /// <summary>
    /// How a connection file's secrets are keyed. Recorded in the root node's KeyProtection attribute.
    /// </summary>
    /// <remarks>
    /// The modes are not interchangeable at the ciphertext level: the password form prepends a
    /// per-secret salt that the master-keyed form does not have. A reader must know which it is holding
    /// before it decrypts anything, which is why this is recorded per file rather than inferred.
    /// </remarks>
    public static class ConnectionFileProtection
    {
        /// <summary>
        /// The attribute name on the Connections root element.
        /// </summary>
        public const string AttributeName = "KeyProtection";

        /// <summary>
        /// The attribute holding the wrapped master key, base64 encoded.
        /// </summary>
        public const string ProtectedKeyAttributeName = "ProtectedKey";

        /// <summary>
        /// Secrets are keyed by a random master key wrapped to this Windows user via DPAPI.
        /// </summary>
        public const string Dpapi = "Dpapi";

        /// <summary>
        /// Secrets are keyed by a passphrase the user supplied when exporting.
        /// </summary>
        public const string Passphrase = "Passphrase";

        /// <summary>
        /// Base64 salt for the export's key derivation. Fresh per export, so exporting the same
        /// connections twice with the same passphrase still yields two files with different keys.
        /// </summary>
        public const string KdfSaltAttributeName = "KdfSalt";

        /// <summary>
        /// Argon2 memory cost in KiB, recorded so a future change of defaults cannot strand an
        /// existing export: the importer derives with the parameters the file was written with.
        /// </summary>
        public const string KdfMemoryAttributeName = "KdfMemoryKb";

        /// <summary>
        /// Argon2 parallelism, recorded for the same reason as <see cref="KdfMemoryAttributeName"/>.
        /// </summary>
        public const string KdfParallelismAttributeName = "KdfParallelism";

        /// <summary>
        /// Absent attribute: the historical scheme, where every secret is derived from the file password
        /// (by default the well-known "mR3m"). Still read so existing and third-party files keep opening.
        /// </summary>
        public const string Legacy = "Legacy";
    }
}
