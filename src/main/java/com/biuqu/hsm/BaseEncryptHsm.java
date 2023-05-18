package com.biuqu.hsm;

import com.biuqu.encryptor.BaseHashEncryptor;
import com.biuqu.encryptor.BaseSingleEncryptor;
import com.biuqu.encryptor.BaseSingleSignEncryptor;
import lombok.Getter;

/**
 * 加密机抽象类(加密机内部)
 *
 * @author BiuQu
 * @date 2023/5/7 13:58
 */
@Getter
public abstract class BaseEncryptHsm implements EncryptHsm
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
    public byte[] decrypt(byte[] data)
    {
        return this.getSingleEncryptor().decrypt(data, null);
    }

    @Override
    public byte[] sign(byte[] data)
    {
        return this.getIntegrityEncryptor().sign(data);
    }

    @Override
    public boolean verify(byte[] data, byte[] signature)
    {
        return this.getIntegrityEncryptor().verify(data, signature);
    }

    /**
     * 对称加密算法加密器
     */
    private BaseSingleEncryptor singleEncryptor;

    /**
     * 非对称加密算法加密器(加密机因为秘钥不会外发，同时由于非对称加密算法运算效率较低，一般不直接商用)
     */
    private BaseSingleSignEncryptor signEncryptor;

    /**
     * Hash算法加密器
     */
    private BaseHashEncryptor hashEncryptor;

    /**
     * 完整性的组合加解密加密器
     */
    private BaseSingleSignEncryptor integrityEncryptor;
}
