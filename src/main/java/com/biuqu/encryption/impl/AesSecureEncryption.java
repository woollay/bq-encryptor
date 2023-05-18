package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSecureSingleEncryption;

/**
 * 增强的AES加密算法
 *
 * @author BiuQu
 * @date 2023/4/30 15:52
 */
public class AesSecureEncryption extends BaseSecureSingleEncryption
{
    /**
     * 构造方法
     */
    public AesSecureEncryption()
    {
        super(ALGORITHM, PADDING_MODE, EN_LEN);
        this.setAlgorithmAlias(ALGORITHM_ALIAS);
    }

    /**
     * 默认的加密算法长度
     */
    private static final int EN_LEN = 256;

    /**
     * 算法类型
     */
    private static final String ALGORITHM = "AES";

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "AES/CBC/PKCS5Padding";

    /**
     * 标准的对称加密算法简称别名
     */
    private static final String ALGORITHM_ALIAS = "SecureAES";
}
