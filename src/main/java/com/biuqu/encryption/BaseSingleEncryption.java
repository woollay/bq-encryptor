package com.biuqu.encryption;

import com.biuqu.encryption.constants.EncryptionConst;
import com.biuqu.encryption.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * 基础加密的单秘钥加密算法
 * <p>
 * 抽象实现了AES/SM4的加解密逻辑
 *
 * @author BiuQu
 * @date 2023/4/30 09:56
 */
public abstract class BaseSingleEncryption extends BaseEncryption implements SingleEncryption<SecretKey>
{
    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     *
     * @param algorithm   加密算法
     * @param paddingMode 填充模式
     * @param encryptLen  加密长度
     */
    public BaseSingleEncryption(String algorithm, String paddingMode, int encryptLen)
    {
        this.setAlgorithm(algorithm);
        this.setPaddingMode(paddingMode);
        this.setEncryptLen(encryptLen);
        this.setRandomMode(RANDOM_MODE);
    }

    @Override
    public SecretKey createKey(byte[] initKey)
    {
        try
        {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(this.getAlgorithm(), this.getProvider());
            SecureRandom random = this.createRandom(initKey);

            if (0 != this.getEncryptLen())
            {
                //对应国际加密算法
                keyGenerator.init(this.getEncryptLen(), random);
            }
            else
            {
                //对应国密
                keyGenerator.init(random);
            }
            return keyGenerator.generateKey();
        }
        catch (Exception e)
        {
            throw new EncryptionException("create single key error.", e);
        }
    }

    /**
     * 获取对称秘钥对象
     *
     * @param key 对称秘钥二进制
     * @return 对称秘钥对象
     */
    public SecretKey toKey(byte[] key)
    {
        return new SecretKeySpec(key, this.getPaddingMode());
    }

    /**
     * 加密
     *
     * @param data 明文
     * @param key  秘钥
     * @param salt 盐值
     * @return 密文
     */
    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] salt)
    {
        return this.doCipher(data, key, salt, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data 密文
     * @param key  秘钥
     * @param salt 盐值
     * @return 明文
     */
    @Override
    public byte[] decrypt(byte[] data, byte[] key, byte[] salt)
    {
        return this.doCipher(data, key, salt, Cipher.DECRYPT_MODE);
    }

    /**
     * 加解密
     *
     * @param data       报文
     * @param key        秘钥
     * @param salt       盐值(偏移向量)
     * @param cipherMode 加密/解密(1和2分别表示加密和解密，参见{@link  javax.crypto.Cipher#DECRYPT_MODE})
     * @return 加解密后的报文
     */
    public byte[] doCipher(byte[] data, byte[] key, byte[] salt, int cipherMode)
    {
        try
        {
            Key keyObj = toKey(key);
            Cipher cipher = Cipher.getInstance(this.getPaddingMode(), this.getProvider());
            if (null == salt)
            {
                salt = new byte[EncryptionConst.DEFAULT_SALT_LEN];
            }
            IvParameterSpec vector = new IvParameterSpec(salt, 0, cipher.getBlockSize());
            if (!this.getPaddingMode().contains(ECB_MODE))
            {
                cipher.init(cipherMode, keyObj, vector);
            }
            else
            {
                cipher.init(cipherMode, keyObj);
            }
            return cipher.doFinal(data);
        }
        catch (Exception e)
        {
            throw new EncryptionException("do single key encrypt/decrypt error.", e);
        }
    }

    /**
     * ECB工作模式
     */
    private static final String ECB_MODE = "/ECB/";
}
