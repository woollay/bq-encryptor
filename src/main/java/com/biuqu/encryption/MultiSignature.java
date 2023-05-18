package com.biuqu.encryption;

/**
 * 多秘钥签名算法
 * <p>
 * 通常为组合加密算法
 *
 * @author BiuQu
 * @date 2023/4/30 09:41
 */
public interface MultiSignature<T> extends MultiEncryption<T>
{
    /**
     * 复合算法签名：
     * 1.使用hash算法对原始数据做摘要；
     * 2.使用非对称私钥对摘要值进行签名；
     * 3.使用对端非对称公钥加密原始数据；
     * 4.拼接原始数据加密后的Hex字符串+"."+签名值Hex字符串
     *
     * @param data 原始数据
     * @param pri  私钥
     * @param pub  对端公钥
     * @return 签名二进制
     */
    byte[] sign(byte[] data, byte[] pri, byte[] pub);

    /**
     * 复合算法验证签名:
     * 1.分解出签名数据和加密的报文
     * 2.使用自持私钥解密加密后的报文；
     * 3.对解密后的报文做Hash摘要；
     * 4.对摘要和对端公钥进行签名验证；
     *
     * @param data 加密和签名后的数据(包含了签名值和SM2公钥加密的密文)
     * @param pub  公钥(和签名接口的私钥配对)
     * @param pri  对端私钥(和签名接口的公钥配对)
     * @return true表示成功
     */
    boolean verify(byte[] data, byte[] pub, byte[] pri);
}
