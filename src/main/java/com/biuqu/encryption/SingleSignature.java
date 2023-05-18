package com.biuqu.encryption;

/**
 * 单秘钥签名算法(签名算法都有加密算法)
 * <p>
 * 抽象了SM2/RSA非对称加密算法的接口
 *
 * @author BiuQu
 * @date 2023/4/30 09:35
 */
public interface SingleSignature<T> extends SingleEncryption<T>
{
    /**
     * 签名
     *
     * @param data 原始数据
     * @param key  秘钥
     * @return 签名二进制
     */
    byte[] sign(byte[] data, byte[] key);

    /**
     * 验证签名
     *
     * @param data 原始数据
     * @param sign 签名二进制
     * @param key  秘钥
     * @return true表示成功
     */
    boolean verify(byte[] data, byte[] key, byte[] sign);
}
