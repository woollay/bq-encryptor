package com.biuqu.encryptor;

import com.biuqu.encryption.BaseMultiSignature;
import lombok.Data;

import java.security.KeyPair;

/**
 * 抽象的多秘钥的加密器
 * <p>
 * 1.既能加密又能签名(GM/US复合加密算法)
 * 2.注意加密器通常只能有1组秘钥(自持私钥和对端公钥,或者对端私钥和自持公钥)，因为任一方不可能拥有对端的私钥
 *
 * @author BiuQu
 * @date 2023/5/3 00:49
 */
@Data
public abstract class BaseMultiSignEncryptor implements SignEncryptor<KeyPair>
{
    public BaseMultiSignEncryptor(BaseMultiSignature encryption, byte[] pri, byte[] pub)
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
        return this.encryption.encrypt(data, pri, pub);
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] salt)
    {
        return this.encryption.decrypt(data, pub, pri);
    }

    @Override
    public byte[] sign(byte[] data)
    {
        return this.encryption.sign(data, pri, pub);
    }

    @Override
    public boolean verify(byte[] data, byte[] signature)
    {
        return this.encryption.verify(data, pub, pri);
    }

    /**
     * 加密算法
     */
    private BaseMultiSignature encryption;

    /**
     * 自持的私钥
     */
    private byte[] pri;

    /**
     * 对端的公钥
     */
    private byte[] pub;
}
