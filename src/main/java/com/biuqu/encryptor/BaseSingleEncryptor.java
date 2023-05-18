package com.biuqu.encryptor;

import com.biuqu.encryption.BaseSingleEncryption;
import lombok.Data;

import javax.crypto.SecretKey;

/**
 * 单秘钥的只能加解密的加密器(AES/SM4)
 *
 * @author BiuQu
 * @date 2023/5/3 01:33
 */
@Data
public abstract class BaseSingleEncryptor implements EncryptEncryptor<SecretKey>
{
    public BaseSingleEncryptor(BaseSingleEncryption encryption, byte[] key)
    {
        this.encryption = encryption;
        this.key = key;
    }

    @Override
    public SecretKey createKey(byte[] initKey)
    {
        return this.encryption.createKey(initKey);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] salt)
    {
        return this.encryption.encrypt(data, this.key, salt);
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] salt)
    {
        return this.encryption.decrypt(data, this.key, salt);
    }

    /**
     * 加密算法
     */
    private BaseSingleEncryption encryption;

    /**
     * 秘钥
     */
    private byte[] key;
}
