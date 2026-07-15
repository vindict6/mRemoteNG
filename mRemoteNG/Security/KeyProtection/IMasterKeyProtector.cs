namespace mRemoteNG.Security.KeyProtection
{
    /// <summary>
    /// Wraps and unwraps a connection file's random master key.
    /// </summary>
    /// <remarks>
    /// The master key encrypts the individual secrets in a connection file. Keeping it separate from
    /// the secrets is what allows the key derivation to run once per file instead of once per field,
    /// which is what made a strong KDF unaffordable in the password-per-field scheme.
    /// </remarks>
    public interface IMasterKeyProtector
    {
        /// <summary>
        /// Wraps a master key for storage alongside the connection file.
        /// </summary>
        byte[] Protect(byte[] masterKey);

        /// <summary>
        /// Recovers a master key previously wrapped by <see cref="Protect"/>.
        /// </summary>
        /// <exception cref="EncryptionException">The key cannot be unwrapped here.</exception>
        byte[] Unprotect(byte[] protectedKey);
    }
}
