package com.biuqu.security;

/**
 * 客户加密器接口
 * <p>
 * 封装了本地秘钥的加密器服务门面(因为客户调用的加密器秘钥不同,所以需要区分不同的加密器实例）
 *
 * @author BiuQu
 * @date 2023/5/11 10:42
 */
public interface ClientSecurity
{
    /**
     * 加密
     *
     * @param algName 加密器名称
     * @param data    原始数据
     * @return 密文
     */
    String encrypt(String algName, String data);

    /**
     * 解密
     *
     * @param algName 加密器名称
     * @param data    加密数据
     * @return 明文
     */
    String decrypt(String algName, String data);
}
