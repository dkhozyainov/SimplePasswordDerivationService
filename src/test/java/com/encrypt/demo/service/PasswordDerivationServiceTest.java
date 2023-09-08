package com.encrypt.demo.service;

import com.encrypt.demo.exception.DecryptException;
import com.encrypt.demo.exception.EncryptException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.encrypt.demo.service.PasswordDerivationService.MASTER_PASSWORD_KEY_LENGTH;
import static com.encrypt.demo.service.PasswordDerivationService.MIN_SALT_LENGTH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;


class PasswordDerivationServiceTest {

    private PasswordDerivationService service;

    @BeforeEach
    void init() {
        String masterPassword = "YourLongSecretKey!!!!!!!!!!!!!!!!!!!!";
        String salt = "yourLongSalt";

        service = new PasswordDerivationService(masterPassword, salt);
    }

    @Test
    public void shouldMakeEncryptAndDecrypt() {
        String originalText = "123";
        String encryptedText = service.encrypt(originalText);
        assertNotNull(encryptedText);
        String decryptedText = service.decrypt(encryptedText);
        assertNotNull(decryptedText);

        assertEquals(originalText, decryptedText);
    }

    @Test
    void shouldShowDecryptionException() {
        String nonEncrypted = "123";

        Exception exception = assertThrows(DecryptException.class, () -> service.decrypt(nonEncrypted));
        assertEquals("Input length must be multiple of 16 when decrypting with padded cipher",
                exception.getMessage());
    }

    @Test
    void shouldShowEncryptionExceptionWhenSecretKeyIsShort() {
        String masterPassword = "yourShortSecretKey";
        String salt = "salt!!!!";

        Exception exception = assertThrows(EncryptException.class, () ->
                new PasswordDerivationService(masterPassword, salt));
        assertEquals("Secret length must be at least " + MASTER_PASSWORD_KEY_LENGTH, exception.getMessage());
    }

    @Test
    void shouldShowEncryptionExceptionWhenSaltIsShort() {
        String masterPassword = "YourLongSecretKey!!!!!!!!!!!!!!!!!!!!";
        String salt = "salt";

        Exception exception = assertThrows(EncryptException.class, () ->
                new PasswordDerivationService(masterPassword, salt));
        assertEquals("Salt length must be at least " + MIN_SALT_LENGTH, exception.getMessage());
    }

}