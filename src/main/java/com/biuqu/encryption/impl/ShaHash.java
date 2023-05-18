package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.Hash;

/**
 * SHA-xxx Hash算法(默认为SHA-512)
 *
 * @author BiuQu
 * @date 2023/4/30 16:32
 */
public class ShaHash extends BaseHash implements Hash
{
    public ShaHash()
    {
        this.setAlgorithm(ALGORITHM);
    }

    @Override
    public byte[] digest(byte[] data)
    {
        return this.calc(data);
    }

    /**
     * 国密标准的SHA512 HASH算法简称
     */
    private static final String ALGORITHM = "SHA-512";
}
