package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.exception.EncryptionException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * 3DES加密算法
 * <p>
 * 不安全的对称加密算法。秘钥长度为24字节，低于24字节会报错，高于24字节会自动截断
 *
 * @author BiuQu
 * @date 2023/5/1 22:56
 */
public class Des3Encryption extends BaseSingleEncryption
{
    /**
     * 构造方法
     */
    public Des3Encryption()
    {
        super(ALGORITHM, PADDING_MODE, 0);
        this.setAlgorithmAlias(ALGORITHM_ALIAS);
    }

    @Override
    public SecretKey createKey(byte[] initKey)
    {
        return this.toKey(initKey);
    }

    @Override
    public SecretKey toKey(byte[] key)
    {
        try
        {
            DESedeKeySpec keySpec = new DESedeKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(keySpec);
        }
        catch (Exception e)
        {
            throw new EncryptionException("create 3des key error.", e);
        }
    }

    @Override
    public String getPaddingMode()
    {
        String padding = super.getPaddingMode();
        if (null == padding)
        {
            padding = PADDING_MODE;
        }
        return padding;
    }

    /**
     * 算法类型
     */
    private static final String ALGORITHM = "DESede";

    /**
     * 算法类型
     */
    private static final String ALGORITHM_ALIAS = "3DES";

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "DESede/CBC/PKCS5Padding";
}
