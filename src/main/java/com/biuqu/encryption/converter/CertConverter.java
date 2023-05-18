package com.biuqu.encryption.converter;

import com.biuqu.encryption.model.Cert;

import java.io.InputStream;
import java.security.cert.X509Certificate;

/**
 * 证书转换器接口
 *
 * @author BiuQu
 * @date 2023/01/02 10:26
 **/
public interface CertConverter
{
    /**
     * 基于密钥对生成证书对象
     *
     * @param certBuilder 证书构建器
     * @return 证书对象
     */
    X509Certificate genCertificate(X509CertificateBuilder certBuilder);

    /**
     * 转换成证书对象
     *
     * @param data 证书内容
     * @return 证书对象
     */
    Cert toCert(String data);

    /**
     * 转换成证书对象
     *
     * @param in 证书输入流
     * @return 证书对象
     */
    Cert toCert(InputStream in);

    /**
     * 转换成标准的JDK证书对象
     *
     * @param in 证书输入流
     * @return JDK证书对象
     */
    X509Certificate toCertificate(InputStream in);

    /**
     * 生成公钥文件
     *
     * @param certificate 公钥证书对象
     * @param path        写入文件路径
     */
    void toCertificate(X509Certificate certificate, String path);
}
