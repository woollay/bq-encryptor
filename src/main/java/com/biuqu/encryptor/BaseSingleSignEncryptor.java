package com.biuqu.encryptor;

import com.biuqu.encryption.BaseSingleSignature;
import lombok.Data;

import java.security.KeyPair;

/**
 * 单秘钥的加密和验签的加密器(RSA/SM2)
 * <p>
 * 1.single表示单加密算法；
 * 2.单加密算法场景下，只能解密和签名
 *
 * @author BiuQu
 * @date 2023/5/3 01:51
 */
@Data
public abstract class BaseSingleSignEncryptor implements SignEncryptor<KeyPair>
{
    public BaseSingleSignEncryptor(BaseSingleSignature encryption, byte[] pri, byte[] pub)
    {
        this.encryption = encryption;
        this.pri = pri;
        this.pub = pub;
    }

    @Override
    public KeyPair createKey(byte[] initKey)
    {
        return this.encryption.createKey(initKey);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] salt)
    {
        return this.encryption.encrypt(data, pub, salt);
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] salt)
    {
        return this.encryption.decrypt(data, pri, salt);
    }

    @Override
    public byte[] sign(byte[] data)
    {
        return this.encryption.sign(data, pri);
    }

    @Override
    public boolean verify(byte[] data, byte[] signature)
    {
        return this.encryption.verify(data, pub, signature);
    }

    /**
     * 带签名的加密算法
     */
    private BaseSingleSignature encryption;

    /**
     * 自持私钥
     */
    private byte[] pri;

    /**
     * 对端公钥
     */
    private byte[] pub;
}
