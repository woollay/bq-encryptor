package com.biuqu.encryption;

/**
 * 使用key的hash算法
 *
 * @author BiuQu
 * @date 2023/4/30 09:00
 */
public interface KeyHash
{
    /**
     * 摘要算法
     *
     * @param data 明文
     * @param key  hash的key
     * @return 摘要值
     */
    byte[] digest(byte[] data, byte[] key);
}
