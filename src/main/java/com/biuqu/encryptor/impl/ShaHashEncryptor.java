package com.biuqu.encryptor.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseHashEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.apache.commons.lang3.StringUtils;

/**
 * 默认的Hash摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:29
 */
public class ShaHashEncryptor extends BaseHashEncryptor
{
    public ShaHashEncryptor(EncryptorKey key)
    {
        this.setHash(EncryptionFactory.SHAHash.createAlgorithm());
        if (null != key && !StringUtils.isEmpty(key.getHashAlg()))
        {
            //更新SHA Hash算法的类型
            ((BaseHash)this.getHash()).setAlgorithm(key.getHashAlg());
        }
    }
}
