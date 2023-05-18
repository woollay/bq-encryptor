package com.biuqu.encryptor;

import com.biuqu.encryption.BaseMultiEncryption;
import lombok.Data;

/**
 * 抽象的多秘钥的加密器
 * <p>
 * 1.只加密不签名，当前只有PGP(PGP实际上在加密里面已经签名了)
 * 2.注意加密器通常只能有1组秘钥(自持私钥和对端公钥,或者对端私钥和自持公钥)，因为任一方不可能拥有对端的私钥
 *
 * @author BiuQu
 * @date 2023/5/3 00:49
 */
@Data
public abstract class BaseMultiEncryptor<T> implements EncryptEncryptor<T>
{
    public BaseMultiEncryptor(BaseMultiEncryption<T> encryption, byte[] pri, byte[] pub)
    {
        this.encryption = encryption;
        this.pri = pri;
        this.pub = pub;
    }

    @Override
    public T createKey(byte[] initKey)
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

    /**
     * 加密算法
     */
    private BaseMultiEncryption<T> encryption;

    /**
     * 自持的私钥
     */
    private byte[] pri;

    /**
     * 对端的公钥
     */
    private byte[] pub;
}
