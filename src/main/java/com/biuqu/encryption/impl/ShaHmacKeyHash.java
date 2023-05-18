package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.KeyHash;
import com.biuqu.encryption.exception.EncryptionException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA xxx HASH算法(默认为HmacSHA256)
 *
 * @author BiuQu
 * @date 2023/4/30 16:41
 */
public class ShaHmacKeyHash extends BaseHash implements KeyHash
{
    public ShaHmacKeyHash()
    {
        this.setAlgorithm(ALGORITHM);
    }

    @Override
    public byte[] digest(byte[] data, byte[] key)
    {
        try
        {
            Mac mac = Mac.getInstance(this.getAlgorithm(), this.getProvider());
            SecretKeySpec keySpec = new SecretKeySpec(key, this.getAlgorithm());
            mac.init(keySpec);
            return mac.doFinal(data);
        }
        catch (Exception e)
        {
            throw new EncryptionException("invalid hash by:" + this.getAlgorithm() + ",exception:" + e.getMessage());
        }
    }

    /**
     * 国密标准的HmacSHA256 HASH算法简称
     */
    private static final String ALGORITHM = "HmacSHA256";
}
