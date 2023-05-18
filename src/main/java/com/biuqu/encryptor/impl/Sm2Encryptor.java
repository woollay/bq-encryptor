package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleSignEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.util.encoders.Hex;

/**
 * 只使用单个非对称的国密SM2加密算法的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 02:23
 */
public class Sm2Encryptor extends BaseSingleSignEncryptor
{
    public Sm2Encryptor(EncryptorKey key)
    {
        super(EncryptionFactory.SM2.createAlgorithm(), Hex.decode(key.getPri()), Hex.decode(key.getPub()));
    }
}
