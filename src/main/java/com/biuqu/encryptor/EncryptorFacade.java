package com.biuqu.encryptor;

/**
 * 加密器门面接口
 *
 * @author BiuQu
 * @date 2023/5/9 14:27
 */
public interface EncryptorFacade
{
    /**
     * 加密机中不可逆加密
     *
     * @param data 原始数据
     * @return 摘要数据
     */
    String hash(String data);

    /**
     * 加密机中可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    String encrypt(String data);

    /**
     * 加密机中解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    String decrypt(String data);

    /**
     * 加密机中的签名
     *
     * @param data 原始数据
     * @return 签名值
     */
    String sign(String data);

    /**
     * 验证签名
     *
     * @param data      原始数据(带签名值)
     * @param signature 签名值
     * @return true表示签名验证通过
     */
    boolean verify(String data, String signature);
}
