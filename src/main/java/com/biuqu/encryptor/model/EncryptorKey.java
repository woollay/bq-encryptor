package com.biuqu.encryptor.model;

import com.biuqu.encryption.factory.EncryptionFactory;
import lombok.Data;

/**
 * 加密器Key模型
 *
 * @author BiuQu
 * @date 2023/5/3 11:06
 */
@Data
public class EncryptorKey
{
    /**
     * 加密器的名称
     */
    private String name;

    /**
     * 加密算法名称(以{@link EncryptionFactory#getType()}定义为准)
     */
    private String algorithm;

    /**
     * 算法对应的私钥(SecretKey/KeyPair/PGPSecretKey/Hmac主密钥)
     */
    private String pri;

    /**
     * 算法对应的公钥(KeyPair/PGPSecretKey对外的密钥)
     */
    private String pub;

    /**
     * 对称秘钥(专门使用在加密机场景下)
     */
    private String secret;

    /**
     * pgp的用户标识
     */
    private String kid;

    /**
     * pgp的私钥密码
     */
    private String pwd;

    /**
     * pgp的秘钥过期时间
     */
    private long expire;

    /**
     * 加密长度(秘钥长度)
     */
    private int encryptLen;

    /**
     * 加密填充模式
     */
    private String padding;

    /**
     * hash算法
     */
    private String hashAlg;

    /**
     * 签名算法
     */
    private String signAlg;
}
