package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseMultiSignEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;

/**
 * 国密复合算法加密器(适用于安全较高的接口交互场景，且自持秘钥)
 *
 * @author BiuQu
 * @date 2023/5/3 01:26
 */
public class GmEncryptor extends BaseMultiSignEncryptor
{
    public GmEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.GM.createAlgorithm(), null, null);
    }
}
