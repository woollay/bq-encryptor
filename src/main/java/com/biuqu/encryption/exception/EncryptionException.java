package com.biuqu.encryption.exception;

/**
 * 加解密异常类(运行时异常)
 *
 * @author BiuQu
 * @date 2022/10/07 22:49
 **/
public class EncryptionException extends RuntimeException
{
    public EncryptionException(String message)
    {
        super(EXCEPTION_PREFIX + message);
    }

    public EncryptionException(String message, Throwable cause)
    {
        super(EXCEPTION_PREFIX + message, cause);
    }

    /**
     * 异常前缀
     */
    private static final String EXCEPTION_PREFIX = "EncryptionException with:";
}
