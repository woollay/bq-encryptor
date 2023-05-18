package com.biuqu.security;

/**
 * 加密安全类
 *
 * @author BiuQu
 * @date 2023/5/7 15:12
 */
public interface EncryptSecurity
{
    /**
     * 本地不可逆加密或者hash
     *
     * @param data 原始数据
     * @return 摘要数据
     */
    byte[] hash(byte[] data);

    /**
     * 本地可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    byte[] encrypt(byte[] data);

    /**
     * 本地可逆加密
     *
     * @param data 原始报文
     * @param salt 盐值
     * @return 加密后的报文
     */
    byte[] encrypt(byte[] data, byte[] salt);

    /**
     * 增强的本地可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    byte[] secureEncrypt(byte[] data);

    /**
     * 非对称的本地加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    byte[] signEncrypt(byte[] data);

    /**
     * 非对称的本地加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    byte[] pgpEncrypt(byte[] data);

    /**
     * 本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    byte[] decrypt(byte[] data);

    /**
     * 本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @param salt 盐值
     * @return 解密后的报文
     */
    byte[] decrypt(byte[] data, byte[] salt);

    /**
     * 增强的本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    byte[] secureDecrypt(byte[] data);

    /**
     * 非对称本地解密
     *
     * @param data 原始数据
     * @return 解密后的数据
     */
    byte[] signDecrypt(byte[] data);

    /**
     * 非对称本地解密
     *
     * @param data 原始数据
     * @return 解密后的数据
     */
    byte[] pgpDecrypt(byte[] data);

    /**
     * 本地签名
     *
     * @param data 原始数据
     * @return 签名值
     */
    byte[] sign(byte[] data);

    /**
     * 本地签名(使用复合加密算法)
     *
     * @param data 原始数据
     * @return 签名值
     */
    byte[] secureSign(byte[] data);

    /**
     * 本地验证签名
     *
     * @param data      原始数据
     * @param signature 签名值
     * @return true表示签名验证通过
     */
    boolean verify(byte[] data, byte[] signature);

    /**
     * 本地验证签名(使用复合加密算法)
     *
     * @param data 原始数据(带签名)
     * @return true表示签名验证通过
     */
    boolean secureVerify(byte[] data);
}
