package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.util.encoders.Hex;

/**
 * 国密中的对称加密算法的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 01:38
 */
public class Sm4Encryptor extends BaseSingleEncryptor
{
    public Sm4Encryptor(EncryptorKey key)
    {
        super(EncryptionFactory.SM4.createAlgorithm(), Hex.decode(key.getPri()));
    }
}
