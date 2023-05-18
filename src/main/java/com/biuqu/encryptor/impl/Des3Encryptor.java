package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.util.encoders.Hex;

/**
 * 国际对称加密算法的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 01:38
 */
public class Des3Encryptor extends BaseSingleEncryptor
{
    public Des3Encryptor(EncryptorKey key)
    {
        super(EncryptionFactory.DES3.createAlgorithm(), Hex.decode(key.getPri()));
    }
}
