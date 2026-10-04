package com.example.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Reads the credential-hash pepper from a JCEKS or PKCS12 keystore using the JDK's own
 * {@link KeyStore} API.
 *
 * <p>The pepper is the platform's answer to "where does a secret come from": a protected entry in a
 * password-protected keystore file, not a constant in source. Nothing here accepts a secret from a
 * client, and nothing here prints one: the loaded characters are copied straight into
 * {@link PasswordHasher}, and every failure path reports only a category.
 *
 * <p>Guards applied to the attacker-controllable inputs (keystore path, entry alias, both
 * passwords):
 * <ul>
 *   <li>the path must be an absolute path to an existing regular file, checked without following
 *       symlinks, and must not be readable or writable by group or other users;</li>
 *   <li>the file type is taken from the configured suffix and must be {@code .jceks} or
 *       {@code .p12}/{@code .pfx}; an arbitrary {@code file://}, jar or ZIP URL is never
 *       resolved;</li>
 *   <li>the alias must match {@code [A-Za-z0-9._-]{1,128}} and must exist in the store;</li>
 *   <li>the entry must be a {@link KeyStore.SecretKeyEntry} whose encoded key is at least
 *       {@link PasswordHasher#MIN_PEPPER_BYTES} bytes; a private-key or certificate entry is
 *       refused.</li>
 * </ul>
 *
 * <p>A wrong keystore password surfaces from the JDK as either a {@code GeneralSecurityException}
 * or an {@code IOException}, so both are handled; the JDK message can quote the keystore path, so
 * no exception message is propagated.
 */
final class KeystorePepperProvider {

    private static final int MAX_ALIAS_CHARS = 128;

    private KeystorePepperProvider() {
    }

    /**
     * Loads the pepper.
     *
     * @return the pepper characters, which the caller must wipe after handing them to
     *     {@link PasswordHasher}
     * @throws AuthException when the keystore or the entry cannot be used; the diagnostic carries no
     *     detail beyond the fixed {@link Diagnostic#STORE_UNAVAILABLE} text
     */
    static char[] loadPepper(Path keystoreFile, char[] keystorePassword, String alias) throws AuthException {
        if (keystoreFile == null || keystorePassword == null || keystorePassword.length == 0) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        if (!isUsableAlias(alias)) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        if (!Files.isRegularFile(keystoreFile, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(keystoreFile)) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        String type = keystoreType(keystoreFile);
        if (type == null) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        char[] passwordCopy = keystorePassword.clone();
        char[] pepper = null;
        try {
            KeyStore store = KeyStore.getInstance(type);
            try (InputStream in = Files.newInputStream(keystoreFile)) {
                store.load(in, passwordCopy);
            }
            // PasswordProtection clones the characters it is given, so the copy can be wiped as
            // soon as the object exists. The same password protects the entry: the two are read
            // from one configuration key and there is no second secret to keep.
            KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(passwordCopy);
            java.util.Arrays.fill(passwordCopy, (char) 0);
            if (!store.containsAlias(alias)) {
                throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
            }
            KeyStore.Entry entry = store.getEntry(alias, protection);
            // SecretKeyEntry is the only secret entry type the JDK offers, and the one keytool
            // produces for a symmetric secret. A PrivateKeyEntry or TrustedCertificateEntry is not a
            // MAC key and is refused rather than coerced into one.
            if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
            }
            byte[] encoded = ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded();
            if (encoded == null || encoded.length < PasswordHasher.MIN_PEPPER_BYTES) {
                if (encoded != null) {
                    java.util.Arrays.fill(encoded, (byte) 0);
                }
                throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
            }
            // ISO-8859-1 view of the key bytes, so an arbitrary 16+ byte key works. PasswordHasher
            // re-encodes with the same mapping, which is a bijection and cannot lose bytes.
            char[] asChars = new char[encoded.length];
            for (int i = 0; i < encoded.length; i++) {
                asChars[i] = (char) (encoded[i] & 0xff);
            }
            java.util.Arrays.fill(encoded, (byte) 0);
            pepper = asChars;
            return pepper;
        } catch (AuthException e) {
            throw e;
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        } finally {
            java.util.Arrays.fill(passwordCopy, (char) 0);
        }
    }

    static boolean isUsableAlias(String alias) {
        if (alias == null || alias.isEmpty() || alias.length() > MAX_ALIAS_CHARS) {
            return false;
        }
        for (int i = 0; i < alias.length(); i++) {
            char c = alias.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    /** Maps the file suffix onto a keystore type; anything unrecognised is refused. */
    static String keystoreType(Path file) {
        String name = file.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".jceks")) {
            return "JCEKS";
        }
        if (name.endsWith(".p12") || name.endsWith(".pfx")) {
            return "PKCS12";
        }
        if (name.endsWith(".jks")) {
            return "JKS";
        }
        return null;
    }
}
