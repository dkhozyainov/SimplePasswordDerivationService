package com.encrypt.demo.exception;

import org.springframework.lang.NonNull;

/**
 * DecryptionException is a custom exception class that extends RuntimeException.
 * It is used when decryption error occurs.
 */
public class DecryptException extends RuntimeException {
    public DecryptException(@NonNull String message, Throwable cause) {
        super(message, cause);
    }

    public DecryptException(@NonNull String message) {
        super(message);
    }
}
