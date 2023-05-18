package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSecureSingleEncryption;

/**
 * 增强的sm4加密算法
 *
 * @author BiuQu
 * @date 2023/4/30 15:49
 */
public class Sm4SecureEncryption extends BaseSecureSingleEncryption
{
    /**
     * 构造方法
     */
    public Sm4SecureEncryption()
    {
        super(ALGORITHM, PADDING_MODE, 0);
        this.setAlgorithmAlias(ALGORITHM_ALIAS);
    }

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "SM4/CTR/NoPadding";

    /**
     * 国密标准的对称加密算法简称
     */
    private static final String ALGORITHM = "SM4";

    /**
     * 国密标准的对称加密算法简称别名
     */
    private static final String ALGORITHM_ALIAS = "SecureSM4";
}
