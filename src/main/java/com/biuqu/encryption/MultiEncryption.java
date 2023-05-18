package com.biuqu.encryption;

/**
 * 多秘钥加密算法
 * <p>
 * 通常为组合加密算法
 *
 * @author BiuQu
 * @date 2023/4/30 09:27
 */
public interface MultiEncryption<T> extends Encryption<T>
{
    /**
     * 双密钥对加密
     *
     * @param data 明文
     * @param pri  己方的私钥(用于签名)
     * @param pub  对端的公钥(用于加密)
     * @return 密文
     */
    byte[] encrypt(byte[] data, byte[] pri, byte[] pub);

    /**
     * 双密钥解密
     * <p>
     * 注意：此方法和{@link MultiEncryption#encrypt(byte[], byte[], byte[])}的第2个参数为一对秘钥，第3个参数为另一组密钥对
     *
     * @param data 密文
     * @param pub  对端的公钥(用于验签)
     * @param pri  己方的私钥(用于解密)
     * @return 明文
     */
    byte[] decrypt(byte[] data, byte[] pub, byte[] pri);
}
