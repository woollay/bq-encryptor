package com.biuqu.encryptor;

import com.biuqu.encryption.KeyHash;
import lombok.Data;

/**
 * 抽象的Hmac摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:32
 */
@Data
public abstract class BaseHmacEncryptor implements HmacEncryptor
{
    public BaseHmacEncryptor(KeyHash keyHash, byte[] key)
    {
        this.keyHash = keyHash;
        this.key = key;
    }

    @Override
    public byte[] hash(byte[] data)
    {
        return this.getKeyHash().digest(data, this.getKey());
    }

    /**
     * 抽象的带秘钥的hash算法对象
     */
    private KeyHash keyHash;

    /**
     * 密码
     */
    private byte[] key;
}
