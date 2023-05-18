package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseHashEncryptor;

/**
 * 默认国密的Hash摘要器
 *
 * @author BiuQu
 * @date 2023/5/3 00:29
 */
public class Sm3HashEncryptor extends BaseHashEncryptor
{
    public Sm3HashEncryptor()
    {
        this.setHash(EncryptionFactory.SM3.createAlgorithm());
    }
}
