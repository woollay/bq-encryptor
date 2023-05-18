package com.biuqu.encryptor;

import com.biuqu.encryption.Hash;
import lombok.Data;

/**
 * 抽象的Hash加密器
 *
 * @author BiuQu
 * @date 2023/5/3 00:27
 */
@Data
public abstract class BaseHashEncryptor implements HashEncryptor
{
    @Override
    public byte[] hash(byte[] data)
    {
        return this.getHash().digest(data);
    }

    /**
     * hash算法
     */
    private Hash hash;
}
