package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseHmacEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.util.encoders.Hex;

/**
 * 默认的Hmac摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:37
 */
public class Sm3HmacEncryptor extends BaseHmacEncryptor
{
    public Sm3HmacEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.SM3Hmac.createAlgorithm(), Hex.decode(key.getPri()));
    }
}
