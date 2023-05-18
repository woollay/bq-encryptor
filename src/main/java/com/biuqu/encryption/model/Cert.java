package com.biuqu.encryption.model;

import lombok.Data;

/**
 * 公钥证书对象
 *
 * @author BiuQu
 * @date 2023/01/02 10:19
 **/
@Data
public class Cert
{
    /**
     * 证书版本号
     */
    private String version;

    /**
     * 证书序列号
     */
    private String serialNumber;

    /**
     * 证书算法
     */
    private String algorithm;

    /**
     * 使用者
     */
    private String subject;

    /**
     * 证书签名
     */
    private String signature;

    /**
     * 证书颁发者
     */
    private String issuer;

    /**
     * 证书有效期的起始时间
     */
    private long beginTime;

    /**
     * 证书有效期的截止时间
     */
    private long endTime;

    /**
     * 公钥二进制
     */
    private byte[] key;
}
