package com.biuqu.encryption;

/**
 * 单秘钥加密算法
 * <p>
 * 抽象了AES/SM4的加解密逻辑
 *
 * @author BiuQu
 * @date 2023/4/30 09:24
 */
public interface SingleEncryption<T> extends Encryption<T>
{
    /**
     * 二进制加密
     * 支持分段加密
     *
     * @param data 明文
     * @param key  秘钥
     * @param salt 盐值
     * @return 密文
     */
    byte[] encrypt(byte[] data, byte[] key, byte[] salt);

    /**
     * 二进制解密
     * 支持分段解密
     *
     * @param data 密文
     * @param key  秘钥
     * @param salt 盐值
     * @return 明文
     */
    byte[] decrypt(byte[] data, byte[] key, byte[] salt);
}
