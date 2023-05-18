package com.biuqu.encryption;

import com.biuqu.encryption.constants.EncryptionConst;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * 增强的单秘钥加密算法
 * <p>
 * 通用于SM4和AES
 *
 * @author BiuQu
 * @date 2023/4/30 14:52
 */
public abstract class BaseSecureSingleEncryption extends BaseSingleEncryption
{
    /**
     * 构造方法
     *
     * @param algorithm   加密算法
     * @param paddingMode 填充模式
     * @param enLen       加密长度
     */
    public BaseSecureSingleEncryption(String algorithm, String paddingMode, int enLen)
    {
        super(algorithm, paddingMode, enLen);
        this.setSaltLen(EncryptionConst.DEFAULT_SALT_LEN);
    }

    /**
     * 自动填充盐值的对称秘钥加密计算
     *
     * @param data 明文
     * @param key  秘钥
     * @param salt 盐值(安全加密中不使用)
     * @return 随机盐值拼接加密后的报文
     */
    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] salt)
    {
        byte[] saltBytes = this.genSalt();
        byte[] enData = this.doCipher(data, key, saltBytes, Cipher.ENCRYPT_MODE);
        byte[] newData = new byte[saltBytes.length + enData.length];
        System.arraycopy(saltBytes, 0, newData, 0, saltBytes.length);
        System.arraycopy(enData, 0, newData, saltBytes.length, enData.length);
        return newData;
    }

    /**
     * 解密带盐值的对称加密数据
     *
     * @param data 盐值拼接密文的数据
     * @param key  秘钥
     * @param salt 盐值(安全加密中不使用)
     * @return 明文
     */
    @Override
    public byte[] decrypt(byte[] data, byte[] key, byte[] salt)
    {
        byte[] saltBytes = new byte[this.saltLen];
        byte[] enData = new byte[data.length - saltBytes.length];
        System.arraycopy(data, 0, saltBytes, 0, saltBytes.length);
        System.arraycopy(data, saltBytes.length, enData, 0, enData.length);
        return this.doCipher(enData, key, saltBytes, Cipher.DECRYPT_MODE);
    }

    public void setSaltLen(int saltLen)
    {
        this.saltLen = saltLen;
    }

    /**
     * 生产随机盐值
     *
     * @return 随机盐值
     */
    private byte[] genSalt()
    {
        byte[] vector = new byte[this.saltLen];
        SecureRandom random = this.createRandom(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        random.nextBytes(vector);
        return vector;
    }

    /**
     * 盐值长度
     */
    private int saltLen;
}
