package com.biuqu.encryptor.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseHmacEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * 默认的Hmac摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:37
 */
public class ShaHmacEncryptor extends BaseHmacEncryptor
{
    public ShaHmacEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.HmacSHA.createAlgorithm(), Hex.decode(key.getPub()));
        if (!StringUtils.isEmpty(key.getHashAlg()))
        {
            //更新SHA Hash算法的类型
            ((BaseHash)this.getKeyHash()).setAlgorithm(key.getHashAlg());
        }
    }
}
