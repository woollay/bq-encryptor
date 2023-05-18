package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseMultiSignEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.apache.commons.lang3.StringUtils;

/**
 * 国际复合算法加密器
 *
 * @author BiuQu
 * @date 2023/5/3 01:27
 */
public class UsEncryptor extends BaseMultiSignEncryptor
{
    public UsEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.US.createAlgorithm(), null, null);

        //支持扩展算法
        int encLen = key.getEncryptLen();
        if (encLen > 0)
        {
            this.getEncryption().setEncryptLen(encLen);
            this.getEncryption().getSignEncryption().setEncryptLen(encLen);
        }

        String padding = key.getPadding();
        if (!StringUtils.isEmpty(padding))
        {
            this.getEncryption().setPaddingMode(padding);
            this.getEncryption().getSignEncryption().setPaddingMode(padding);
        }

        String signAlg = key.getSignAlg();
        if (!StringUtils.isEmpty(signAlg))
        {
            this.getEncryption().getSignEncryption().setSignatureAlg(signAlg);
        }
    }
}
