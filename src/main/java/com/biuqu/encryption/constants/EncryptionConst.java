package com.biuqu.encryption.constants;

/**
 * 加密常量类
 *
 * @author BiuQu
 * @date 2022/10/07 23:26
 **/
public final class EncryptionConst
{
    /**
     * 连接的点
     */
    public static final String POINT = ".";
    
    /**
     * 1字节包含的字符数
     */
    public static final int BYTE_TO_BIT = 8;

    /**
     * 16进制常量
     */
    public static final int HEX_UNIT = 16;

    /**
     * 默认盐值的长度
     */
    public static final int DEFAULT_SALT_LEN = 16;

    /**
     * 私有化构造方法
     */
    private EncryptionConst()
    {
    }
}
