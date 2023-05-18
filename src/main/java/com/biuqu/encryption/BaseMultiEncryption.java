package com.biuqu.encryption;

/**
 * 多秘钥加密算法抽象
 *
 * @author BiuQu
 * @date 2023/4/30 21:54
 */
public abstract class BaseMultiEncryption<T> extends BaseEncryption implements MultiEncryption<T>
{
    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     *
     * @param algorithm   加密算法
     * @param paddingMode 填充模式
     * @param encryptLen  加密长度
     */
    public BaseMultiEncryption(String algorithm, String paddingMode, int encryptLen)
    {
        this.setAlgorithm(algorithm);
        this.setPaddingMode(paddingMode);
        this.setEncryptLen(encryptLen);
        this.setRandomMode(RANDOM_MODE);
    }
}
