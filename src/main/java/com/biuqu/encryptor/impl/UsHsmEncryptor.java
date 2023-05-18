package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleSignEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;

/**
 * 国际加密机模拟的加密器
 * <p>
 * 该加密器和加密机的区别是加密机的秘钥是加密机物理环境内置的，不会外发，所有加密的秘钥都是通过秘钥ID代替，其它使用完全一致；
 *
 * @author BiuQu
 * @date 2023/5/3 23:18
 */
public class UsHsmEncryptor extends BaseSingleSignEncryptor
{
    public UsHsmEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.UsIntegrityHsm.createAlgorithm(), null, null);
    }
}
