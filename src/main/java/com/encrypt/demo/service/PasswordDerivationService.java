package com.encrypt.demo.service;

import com.encrypt.demo.exception.DecryptException;
import com.encrypt.demo.exception.EncryptException;
import org.springframework.lang.NonNull;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * PasswordDerivationService for handlingPBKDF2 (Password-Based Key Derivation Function 2) and HmacSHA256 (Hash-based Message
 * Authentication Code using the SHA-256 hashing algorithm)
 */
public class PasswordDerivationService {

    private final String masterPassword;
    private final String salt;
    public static final int MASTER_PASSWORD_KEY_LENGTH = 36;
    public static final int MIN_SALT_LENGTH = 8;
    private static final byte[] IV = new byte[16];
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";

    public PasswordDerivationService(String masterPassword, String salt) {
        this.masterPassword = masterPassword;
        this.salt = salt;
        validateSaltAndMasterPassword(masterPassword, salt);
    }

    /**
     * Prepares an instance of SecretKeySpec
     *
     * @return new SecretKeySpec
     */
    @NonNull
    private SecretKeySpec generateSecretKeySpec() throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt.getBytes(), 512, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }

    /**
     * Prepares an instance of Cipher
     *
     * @param cipherMode enable encrypt or decrypt mode.
     * @return new Cipher
     */
    @NonNull
    private Cipher prepareCipher(int cipherMode) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance(PasswordDerivationService.CIPHER_TRANSFORMATION);
        cipher.init(cipherMode, generateSecretKeySpec(), ivSpec);
        return cipher;
    }

    /**
     * Encrypt string with Cipher and Base64 encoder
     *
     * @param strToEncrypt String which will be encrypted.
     * @return encrypted String
     */
    public String encrypt(@NonNull String strToEncrypt) {
        try {
            Cipher cipher = prepareCipher(Cipher.ENCRYPT_MODE);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new EncryptException(e.getMessage(), e);
        }
    }

    /**
     * Validate masterPassword & salt length
     *
     * @param masterPassword String value of masterPassword
     * @param salt      String value of salt
     */
    protected void validateSaltAndMasterPassword(@NonNull String masterPassword, @NonNull String salt) {
        if (masterPassword.length() < MASTER_PASSWORD_KEY_LENGTH) {
            throw new EncryptException("Secret length must be at least " + MASTER_PASSWORD_KEY_LENGTH);
        }
        if (salt.length() < MIN_SALT_LENGTH) {
            throw new EncryptException("Salt length must be at least " + MIN_SALT_LENGTH);
        }
    }

    /**
     * Decrypt string with Cipher and Base64 decoder
     *
     * @param strToDecrypt String which will be decrypted.
     * @return encrypted String
     */
    public String decrypt(@NonNull String strToDecrypt) {
        try {
            Cipher cipher = prepareCipher(Cipher.DECRYPT_MODE);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            throw new DecryptException(e.getMessage(), e);
        }
    }
}
