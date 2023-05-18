package com.biuqu.encryptor;

/**
 * 不带秘钥的摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:07
 */
public interface HashEncryptor extends Encryptor
{
    /**
     * 摘要方法
     *
     * @param data 原始数据
     * @return 摘要值
     */
    byte[] hash(byte[] data);
}
