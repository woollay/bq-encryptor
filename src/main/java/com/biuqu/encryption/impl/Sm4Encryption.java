package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;

/**
 * 国密对称加密算法
 * <p>
 * 国密sm4秘钥长度只有128位，每次加解密必须填充盐值
 *
 * @author BiuQu
 * @date 2023/01/02 16:18
 **/
public class Sm4Encryption extends BaseSingleEncryption
{
    /**
     * 构造方法
     */
    public Sm4Encryption()
    {
        super(ALGORITHM, PADDING_MODE, 0);
    }

    @Override
    public String getPaddingMode()
    {
        String padding = super.getPaddingMode();
        if (null == padding)
        {
            padding = PADDING_MODE;
        }
        return padding;
    }

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "SM4/CBC/PKCS5Padding";

    /**
     * 国密标准的对称加密算法简称
     */
    private static final String ALGORITHM = "SM4";
}
