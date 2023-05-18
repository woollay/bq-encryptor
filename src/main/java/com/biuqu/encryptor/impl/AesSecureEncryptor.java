package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.BaseSingleEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * 增强的国际对称加密算法的加密器
 *
 * @author BiuQu
 * @date 2023/5/3 01:38
 */
public class AesSecureEncryptor extends BaseSingleEncryptor
{
    public AesSecureEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.SecureAES.createAlgorithm(), Hex.decode(key.getPri()));

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
    }
}
