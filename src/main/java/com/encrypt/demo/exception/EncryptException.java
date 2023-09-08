package com.encrypt.demo.exception;

import org.springframework.lang.NonNull;

/**
 * EncryptionException is a custom exception class that extends RuntimeException.
 * It is used when encryption error occurs.
 */
public class EncryptException extends RuntimeException {
    public EncryptException(@NonNull String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptException(@NonNull String message) {
        super(message);
    }
}
