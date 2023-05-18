package com.biuqu.encryptor;

/**
 * 只能加解密的加密器
 * <p>
 * 设计说明：
 * 1.xxxEncryption(加密算法)表示加密算法类型，不存储任何算法需要的秘钥等相关数据;
 * 2.xxxEncryptor(加密器)表示加密服务，包含了xxxEncryption加密算法对象，还存储了算法对象必须的秘钥和秘钥参数，如：获取秘钥的密码等；
 * 3.xxxEncryptor(加密器)从使用层面出发，不区分是Hash算法还是加密算法，统统以Encryptor结尾，与加密算法严格区分Hash和加密不同；
 *
 * @param <T> 秘钥对象类型
 * @author BiuQu
 * @date 2023/5/3 00:14
 */
public interface EncryptEncryptor<T> extends Encryptor
{
    /**
     * 创建Key对象
     *
     * @param initKey 初始key
     * @return 秘钥对象
     */
    T createKey(byte[] initKey);

    /**
     * 加密数据
     *
     * @param data 原始报文
     * @param salt 盐值
     * @return 密文
     */
    byte[] encrypt(byte[] data, byte[] salt);

    /**
     * 解密数据
     *
     * @param data 密文
     * @param salt 盐值
     * @return 明文
     */
    byte[] decrypt(byte[] data, byte[] salt);
}
