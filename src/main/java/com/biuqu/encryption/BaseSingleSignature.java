package com.biuqu.encryption;

import lombok.Data;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 单秘钥签名算法(带加密)
 * <p>
 * 抽象了SM2/RSA非对称加密算法的实现
 *
 * @author BiuQu
 * @date 2023/4/30 14:06
 */
@Data
public abstract class BaseSingleSignature extends BaseEncryption implements SingleSignature<KeyPair>
{
    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     *
     * @param algorithm   加密算法
     * @param paddingMode 填充模式
     * @param encryptLen  加密长度
     */
    public BaseSingleSignature(String algorithm, String signatureAlg, String paddingMode, int encryptLen)
    {
        this.setAlgorithm(algorithm);
        this.setPaddingMode(paddingMode);
        this.setEncryptLen(encryptLen);
        this.setSignatureAlg(signatureAlg);
        this.setRandomMode(RANDOM_MODE);
    }

    /**
     * 抽象加解密
     *
     * @param data       明文/密文
     * @param key        非对称秘钥
     * @param cipherMode 加密/解密(1和2分别表示加密和解密，参见{@link  javax.crypto.Cipher#DECRYPT_MODE})
     * @return 加解密处理后的结果
     */
    public abstract byte[] doCipher(byte[] data, byte[] key, int cipherMode);

    /**
     * 获取公钥对象
     *
     * @param pubKey 公钥二进制
     * @return 公钥对象
     */
    public abstract PublicKey toPubKey(byte[] pubKey);

    /**
     * 获取私钥对象
     *
     * @param priKey 私钥二进制
     * @return 私钥对象
     */
    public abstract PrivateKey toPriKey(byte[] priKey);

    /**
     * 签名算法
     */
    private String signatureAlg;

    @Override
    public String toString()
    {
        return super.toString() + "signatureAlg:" + signatureAlg + ".";
    }
}
