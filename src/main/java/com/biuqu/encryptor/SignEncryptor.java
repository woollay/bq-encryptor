package com.biuqu.encryptor;

/**
 * 支持加解密和签名验签的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 00:20
 */
public interface SignEncryptor<T> extends EncryptEncryptor<T>
{
    /**
     * 签名
     *
     * @param data 原始数据
     * @return 签名二进制
     */
    byte[] sign(byte[] data);

    /**
     * 验证签名
     *
     * @param data      数据
     * @param signature 签名值
     * @return true表示成功
     */
    boolean verify(byte[] data, byte[] signature);
}
