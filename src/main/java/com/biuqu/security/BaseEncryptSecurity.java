package com.biuqu.security;

import com.biuqu.encryptor.*;
import lombok.Getter;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * 抽象的本地加密安全类
 *
 * @author BiuQu
 * @date 2023/5/7 15:49
 */
@Getter
public abstract class BaseEncryptSecurity implements EncryptSecurity
{
    @Override
    public byte[] hash(byte[] data)
    {
        return this.getHashEncryptor().hash(data);
    }

    @Override
    public byte[] encrypt(byte[] data)
    {
        return this.getSingleEncryptor().encrypt(data, null);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] salt)
    {
        return this.getSingleEncryptor().encrypt(data, salt);
    }

    @Override
    public byte[] secureEncrypt(byte[] data)
    {
        return this.getSecureSingleEncryptor().encrypt(data, null);
    }

    @Override
    public byte[] signEncrypt(byte[] data)
    {
        return this.getSignEncryptor().encrypt(data, null);
    }

    @Override
    public byte[] pgpEncrypt(byte[] data)
    {
        return this.getPgpEncryptor().encrypt(data, null);
    }

    @Override
    public byte[] decrypt(byte[] data)
    {
        return this.getSingleEncryptor().decrypt(data, null);
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] salt)
    {
        return this.getSingleEncryptor().decrypt(data, salt);
    }

    @Override
    public byte[] secureDecrypt(byte[] data)
    {
        return this.getSecureSingleEncryptor().decrypt(data, null);
    }

    @Override
    public byte[] signDecrypt(byte[] data)
    {
        return this.getSignEncryptor().decrypt(data, null);
    }

    @Override
    public byte[] pgpDecrypt(byte[] data)
    {
        return this.getPgpEncryptor().decrypt(data, null);
    }

    @Override
    public byte[] sign(byte[] data)
    {
        return this.getSignEncryptor().sign(data);
    }

    @Override
    public byte[] secureSign(byte[] data)
    {
        return this.getSecureSignEncryptor().sign(data);
    }

    @Override
    public boolean verify(byte[] data, byte[] signature)
    {
        return this.getSignEncryptor().verify(data, signature);
    }

    @Override
    public boolean secureVerify(byte[] data)
    {
        return this.getSecureSignEncryptor().verify(data, null);
    }

    /**
     * 对称加密器
     */
    private BaseSingleEncryptor singleEncryptor;

    /**
     * 增强的对称加密器
     */
    private BaseSingleEncryptor secureSingleEncryptor;

    /**
     * 非对称加密算法加密器(加密机因为秘钥不会外发，同时由于非对称加密算法运算效率较低，一般不直接商用)
     */
    private BaseSingleSignEncryptor signEncryptor;

    /**
     * Hash算法加密器
     */
    private BaseHashEncryptor hashEncryptor;

    /**
     * 组合加密器
     */
    private BaseMultiSignEncryptor secureSignEncryptor;

    /**
     * pgp加密器(国际比较通用的加密算法,和上面的组合算法类似)
     */
    private BaseMultiEncryptor<PGPSecretKey> pgpEncryptor;
}
