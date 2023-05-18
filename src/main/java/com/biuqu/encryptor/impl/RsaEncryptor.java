package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleSignEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * 只使用单个非对称的国密RSA加密算法的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 02:23
 */
public class RsaEncryptor extends BaseSingleSignEncryptor
{
    public RsaEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.RSA.createAlgorithm(), Hex.decode(key.getPri()), Hex.decode(key.getPub()));

        //支持扩展算法
        int encLen = key.getEncryptLen();
        if (encLen > 0)
        {
            this.getEncryption().setEncryptLen(encLen);
        }

        String padding = key.getPadding();
        if (!StringUtils.isEmpty(padding))
        {
            this.getEncryption().setPaddingMode(padding);
        }

        String signAlg = key.getSignAlg();
        if (!StringUtils.isEmpty(signAlg))
        {
            this.getEncryption().setSignatureAlg(signAlg);
        }
    }
}
