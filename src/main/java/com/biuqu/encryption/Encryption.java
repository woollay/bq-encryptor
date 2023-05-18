package com.biuqu.encryption;

/**
 * 最基础的加密接口
 *
 * @author BiuQu
 * @date 2023/4/30 09:51
 */
public interface Encryption<T>
{
    /**
     * 创建Key对象
     *
     * @param initKey 初始key
     * @return 秘钥对象
     */
    T createKey(byte[] initKey);
}
