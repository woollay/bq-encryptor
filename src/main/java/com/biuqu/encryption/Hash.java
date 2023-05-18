package com.biuqu.encryption;

/**
 * Hash接口
 *
 * @author BiuQu
 * @date 2023/4/30 08:58
 */
public interface Hash
{
    /**
     * 摘要算法
     *
     * @param data 明文
     * @return 摘要值
     */
    byte[] digest(byte[] data);
}
