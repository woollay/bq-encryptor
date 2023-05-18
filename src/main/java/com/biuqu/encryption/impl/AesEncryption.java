package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;

/**
 * AES加密算法
 * <p>
 * 1.AES加密算法秘钥长度有128/192/256，参考:https://zh.wikipedia.org/wiki/%E9%AB%98%E7%BA%A7%E5%8A%A0%E5%AF%86%E6%A0%87%E5%87%86
 * 2.当前只有AES256是安全的
 * <p>
 * 加密算法的PADDING_MODE(加密算法模式)由3部分构成：(如：AES/ECB/PKCS5Padding)
 * 1.第一部分为加密算法名称，如:AES/RSA；
 * 2.第二部分为工作模式，如:ECB/CBC/CFB/OFB/CTR/PCBC；
 * 3.第三部分为填充模式，如:NoPadding/PKCS5Padding/PKCS7Padding/ISO10126Padding/ISO7816-4Padding/ZeroBytePadding/X923Padding/PKCS1Padding/TBCPadding(Trailing-Bit-Compliment）
 *
 * @author BiuQu
 * @date 2022/10/05 23:44
 **/
public class AesEncryption extends BaseSingleEncryption
{
    /**
     * 构造方法
     */
    public AesEncryption()
    {
        super(ALGORITHM, PADDING_MODE, EN_LEN);
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
}
