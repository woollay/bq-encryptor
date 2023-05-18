package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.KeyHash;
import com.biuqu.encryption.exception.EncryptionException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * SM3多形态hash算法
 *
 * @author BiuQu
 * @date 2023/4/30 16:51
 */
public class Sm3HmacKeyHash extends BaseHash implements KeyHash
{
    public Sm3HmacKeyHash()
    {
        this.setAlgorithm(ALGORITHM);
    }

    @Override
    public byte[] digest(byte[] data, byte[] key)
    {
        try
        {
            SM3Digest sm3 = new SM3Digest();
            HMac mac = new HMac(sm3);
            mac.init(new KeyParameter(key));
            mac.update(data, 0, data.length);
            byte[] hash = new byte[mac.getMacSize()];
            mac.doFinal(hash, 0);
            return hash;
        }
        catch (Exception e)
        {
            throw new EncryptionException("invalid hash by:" + this.getAlgorithm() + ",exception:" + e.getMessage());
        }
    }

    /**
     * SM3摘要算法
     */
    private static final String ALGORITHM = "HmacSM3";
}
