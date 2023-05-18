package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.Hash;

/**
 * SM3多形态hash算法
 *
 * @author BiuQu
 * @date 2023/4/30 16:51
 */
public class Sm3Hash extends BaseHash implements Hash
{
    public Sm3Hash()
    {
        this.setAlgorithm(ALGORITHM);
    }

    @Override
    public byte[] digest(byte[] data)
    {
        return this.calc(data);
    }

    /**
     * SM3摘要算法
     */
    private static final String ALGORITHM = "SM3";
}
