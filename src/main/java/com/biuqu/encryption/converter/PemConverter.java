package com.biuqu.encryption.converter;

import java.io.InputStream;

/**
 * Pem证书转换器
 *
 * @author BiuQu
 * @date 2022/11/11 21:28
 **/
public interface PemConverter
{
    /**
     * 把文件流转换成公钥二进制(PKCS#1格式，兼容OpenSSL)
     *
     * @param in 输入流
     * @return 二进制公钥
     */
    byte[] toPubKey(InputStream in);

    /**
     * 把文件流转换成公钥二进制(PKCS#1格式，兼容OpenSSL)
     *
     * @param in  输入流
     * @param pwd 私钥密码
     * @return 二进制公钥
     */
    byte[] toPriKey(InputStream in, byte[] pwd);

    /**
     * 把秘钥二进制转换成文件(PKCS#1格式，兼容OpenSSL)
     *
     * @param key  秘钥二进制
     * @param path 文件路径
     */
    void toPem(byte[] key, String path);
}
