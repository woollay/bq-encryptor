package com.biuqu.hsm;

/**
 * 加密机对应的加密器接口
 *
 * @author BiuQu
 * @date 2023/5/7 13:50
 */
public interface EncryptHsm
{
    /**
     * 加密机中不可逆加密
     *
     * @param data 原始数据
     * @return 摘要数据
     */
    byte[] hash(byte[] data);

    /**
     * 加密机中可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    byte[] encrypt(byte[] data);

    /**
     * 加密机中解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    byte[] decrypt(byte[] data);

    /**
     * 加密机中的签名
     *
     * @param data 原始数据
     * @return 签名值
     */
    byte[] sign(byte[] data);

    /**
     * 验证签名
     *
     * @param data      原始数据
     * @param signature 签名
     * @return true表示签名验证通过
     */
    boolean verify(byte[] data, byte[] signature);
}
