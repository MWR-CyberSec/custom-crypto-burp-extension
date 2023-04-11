package mwr.customcrypto;


import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.utilities.Utilities;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;


/**
 * Some standard crypto operations for reuse. These take and return only unencoded byte arrays, for consistency
 * Feel free to make a PR and add your own algorithms
 */
public class CryptoOperations {

    private static final Logging log = CustomCrypto.log;
    static PersistedObject storage = CustomCrypto.storage;
    private final Utilities utils = CustomCrypto.utils;

    /**
     * Perform a rotation (e.g. ROT13)
     *
     * @param input String to be rotated (Byte arrays don't make sense for rotations)
     * @param n     Number of digits to rotate by
     * @return Rotated string
     */
    public static String rot(String input, int n) {
        StringBuilder output = new StringBuilder();
        //Ensure that the input is as expected
        //e.g. rot52 == rot26 == rot0 == rot-26 == rot-52
        n = n % 26;
        if (n < 0) {
            n += 26;
        }

        for (char i : input.toCharArray()) {
            if (i >= 'A' && i <= 'Z') {
                if (i + n <= 'Z') {
                    output.append((char) (i + n));
                } else {
                    output.append((char) (i + n - 26));
                }

            } else if (i >= 'a' && i <= 'z') {
                if (i + n <= 'z') {
                    output.append((char) (i + n));
                } else {
                    output.append((char) (i + n - 26));
                }
            } else {
                output.append(i);
            }
        }
        return output.toString();
    }

    protected static void logError(Exception e) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        e.printStackTrace(printWriter);
        log.logToError(stringWriter.toString());
    }

    /**
     * RSA operations (encrypt, decrypt, sign, verify)
     */
    static class RSA {
        /**
         * RSA encrypt using RSA/ECB/PKCS1Padding or RSA/None/PKCS1Padding
         *
         * @param input     The data to encrypt
         * @param publicKey The public key to encrypt with  (or null for <code>rsaPublicKey</code> from storage)
         * @return The encrypted data
         */
        public static ByteArray encryptWithPkcs1(ByteArray input, ByteArray publicKey) {
            try {
                // The "ECB" in "RSA/ECB/PKCS1Padding" isn't actually ECB, RSA isn't a block cipher.
                // BouncyCastle's implementation of this cipher is called "RSA/None/PKCS1Padding", which is more accurate.
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
                return ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                return null;
            }
        }

        /**
         * RSA decrypt using RSA/ECB/PKCS1Padding or RSA/None/PKCS1Padding
         *
         * @param input      The data to decrypt
         * @param privateKey The private key to decrypt with  (or null for <code>rsaPrivateKey</code> from storage)
         * @return The decrypted data
         */
        public static ByteArray decryptWithPkcs1(ByteArray input, ByteArray privateKey) {
            try {
                // The "ECB" in "RSA/ECB/PKCS1Padding" isn't actually ECB, RSA isn't a block cipher.
                // BouncyCastle's implementation of this cipher is called "RSA/None/PKCS1Padding", which is more accurate.
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
                return ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                return null;
            }
        }

        /**
         * Sign using RSAwithSHA256 (a.k.a RS256)
         *
         * @param input      The data to sign
         * @param privateKey The private key to sign with  (or null for <code>rsaPrivateKey</code> from storage)
         * @return The signature
         */
        public static ByteArray signWithSha256(ByteArray input, ByteArray privateKey) {
            try {
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(getPrivateKey(privateKey));
                signature.update(input.getBytes());
                return ByteArray.byteArray(signature.sign());
            } catch (Exception e) {
                logError(e);
                return null;
            }
        }

        /**
         * Create a signature using RSAwithSHA1 (don't call it RS1, that's a car (according to Google))
         *
         * @param input      The data to verify
         * @param privateKey The private key to sign with (or null for <code>rsaPrivateKey</code> from storage)
         * @return The signature
         */
        public static ByteArray signWithSha1(ByteArray input, ByteArray privateKey) {
            try {
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initSign(getPrivateKey(privateKey));
                signature.update(input.getBytes());
                return ByteArray.byteArray(signature.sign());
            } catch (Exception e) {
                logError(e);
                return null;
            }
        }

        /**
         * Get the private key as a <code>PrivateKey</code>
         *
         * @param key The private key as a byte array (or null for <code>rsaPrivateKey</code> from storage)
         * @return The private key as a <code>PrivateKey</code>
         */
        public static PrivateKey getPrivateKey(ByteArray key) {
            PrivateKey result;
            if (key == null)
                key = storage.getByteArray("rsaPrivateKey");
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getBytes());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                result = keyFactory.generatePrivate(keySpec);
            } catch (Exception e) {
                logError(e);
                result = null;
            }
            return result;
        }

        /**
         * Get the public key as a <code>PublicKey</code>
         *
         * @param key The public key as a byte array (or null for <code>rsaPublicKey</code> from storage)
         * @return The public key as a <code>PublicKey</code>
         */
        public static PublicKey getPublicKey(ByteArray key) {
            PublicKey result = null;
            if (key == null)
                key = storage.getByteArray("rsaPublicKey");
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getBytes());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                result = keyFactory.generatePublic(keySpec);
            } catch (Exception e) {
                logError(e);
                return null;
            }
            return result;
        }

        /**
         * Verify a signature using RSAwithSHA256 (a.k.a RS256)
         *
         * @param input     The data to verify
         * @param publicKey The public key to verify the signature with  (or null for <code>rsaPublicKey</code> from storage)
         * @param signature The signature to verify against
         * @return True if the signature is valid, False otherwise
         */
        public boolean verifyWithSha256(ByteArray input, ByteArray publicKey, ByteArray signature) {
            if (publicKey == null)
                publicKey = storage.getByteArray("rsaPrivateKey");
            try {
                Signature publicSignature = Signature.getInstance("SHA256withRSA");
                publicSignature.initVerify(getPublicKey(publicKey));
                publicSignature.update(input.getBytes());
                return publicSignature.verify(signature.getBytes());
            } catch (Exception e) {
                logError(e);
                return false;
            }
        }

        /**
         * Verify a signature using RSAwithSHA1
         *
         * @param input     The data to verify
         * @param publicKey The public key to verify the signature with (or null for <code>rsaPublicKey</code> from storage)
         * @param signature The signature to verify against
         * @return True if the signature is valid, False otherwise
         */
        public boolean verifyWithSha1(ByteArray input, ByteArray publicKey, ByteArray signature) {
            try {
                Signature publicSignature = Signature.getInstance("SHA1withRSA");
                publicSignature.initVerify(getPublicKey(publicKey));
                publicSignature.update(input.getBytes());
                return publicSignature.verify(signature.getBytes());
            } catch (Exception e) {
                logError(e);
                return false;
            }
        }
    }

    /**
     * AES operations (encrypt, decrypt)
     */
    public static class AES {
        /**
         * Encrypt an unencoded byte array with the AES/CBC/PKCS5 cipher
         *
         * @param input Byte array to be encrypted
         * @param key   AES secret key, or null to use stored key
         * @param iv    Initialisation Vector, or null for a random IV
         * @return encrypted bytes
         */
        public static ByteArray encryptWithCbcPkcs5(ByteArray input, ByteArray key, ByteArray iv) {
            if (iv == null) {
                // Get random IV
                iv = ByteArray.byteArrayOfLength(16);
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv.getBytes());
            }
            ByteArray result;

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                SecretKeySpec secretKeySpec = getSecretKey(key);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                result = ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                result = null;
            }
            return result;
        }

        /**
         * Decrypt an unencoded byte array with the AES/CBC/PKCS5 cipher
         *
         * @param input Byte array to be decrypted
         * @param key   AES secret key, or null to use stored key
         * @param iv    Initialisation Vector
         * @return decrypted bytes
         */
        public static ByteArray decryptWithCbcPkcs5(ByteArray input, ByteArray key, ByteArray iv) {
            ByteArray result;

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                SecretKey secretKey = getSecretKey(key);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

                result = ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                result = null;
            }
            return result;
        }

        /**
         * Encrypt an unencoded byte array with the AES/GCM/NoPadding cipher
         *
         * @param input Byte array to be encrypted
         * @param key   AES secret key, or null to use stored key
         * @param iv    Initialisation Vector, or null for a random IV
         * @param tLen  The tag length in bits, or null for the longest accepted length of 128 bits
         * @return encrypted bytes
         */
        public static ByteArray encryptWithGcm(ByteArray input, ByteArray key, ByteArray iv, Integer tLen) {
            if (iv == null) {
                // Get random IV
                // FIPS recommends an IV length of 12 for GCM, since it doesn't require extra computation
                iv = ByteArray.byteArrayOfLength(12);
                (new SecureRandom()).nextBytes(iv.getBytes());
            }
            if (tLen == null) {
                //Use default tLen
                tLen = 128;
            }
            ByteArray result;

            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                SecretKeySpec secretKeySpec = getSecretKey(key);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tLen, iv.getBytes());

                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

                result = ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                result = null;
            }
            return result;
        }

        /**
         * Decrypt an unencoded byte array with the AES/GCM/NoPadding cipher
         *
         * @param input Byte array to be decrypted
         * @param key   AES secret key, or null to use stored key
         * @param iv    Initialisation Vector
         * @param tLen  The tag length in bits, or null for the longest accepted length of 128 bits
         * @return decrypted bytes
         */
        public static ByteArray decryptWithGcm(ByteArray input, ByteArray key, ByteArray iv, Integer tLen) {
            if (tLen == null) {
                //Use default tLen
                tLen = 128;
            }
            ByteArray result;

            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                SecretKey secretKey = getSecretKey(key);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tLen, iv.getBytes());

                cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

                result = ByteArray.byteArray(cipher.doFinal(input.getBytes()));
            } catch (Exception e) {
                logError(e);
                result = null;
            }
            return result;
        }

        /**
         * Get the secret key as a <code>SecretKeySpec</code>
         *
         * @param key The secret key as a byte array (or null for <code>aesSecretkey</code> in storage)
         * @return The secret key as a <code>SecretKeySpec</code>
         */
        public static SecretKeySpec getSecretKey(ByteArray key) {
            if (key == null)
                key = storage.getByteArray("aesSecretKey");
            try {
                return new SecretKeySpec(key.getBytes(), "AES");
            } catch (Exception e) {
                logError(e);
                return null;
            }
        }
    }
}
