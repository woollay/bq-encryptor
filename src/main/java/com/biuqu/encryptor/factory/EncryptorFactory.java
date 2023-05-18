package com.biuqu.encryptor.factory;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryptor.*;
import com.biuqu.encryptor.impl.*;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.crypto.SecretKey;
import java.security.KeyPair;

/**
 * 加密器工厂
 *
 * @author BiuQu
 * @date 2023/5/3 11:57
 */
public enum EncryptorFactory
{
    /**
     * 3DES对称加密器
     */
    DES3(EncryptionFactory.DES3.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Des3Encryptor(encryptorKey);
            }
        },

    /**
     * AES对称加密器
     */
    AES(EncryptionFactory.AES.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new AesEncryptor(encryptorKey);
            }
        },

    /**
     * 增强的AES对称加密器
     */
    SecureAES(EncryptionFactory.SecureAES.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new AesSecureEncryptor(encryptorKey);
            }
        },

    /**
     * 增强的AES对称加密器(专用于加密机)
     */
    AESHsm(EncryptionFactory.AESHsm.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new AesSecureEncryptor(encryptorKey);
            }
        },

    /**
     * SM4对称加密器
     */
    SM4(EncryptionFactory.SM4.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm4Encryptor(encryptorKey);
            }
        },

    /**
     * 增强的SM4对称加密器
     */
    SecureSM4(EncryptionFactory.SecureSM4.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm4SecureEncryptor(encryptorKey);
            }
        },

    /**
     * 增强的SM4对称加密器(专用于加密机)
     */
    SM4Hsm(EncryptionFactory.SM4Hsm.getType())
        {
            @Override
            public EncryptEncryptor<SecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm4SecureEncryptor(encryptorKey);
            }
        },

    /**
     * RSA非对称加密器
     */
    RSA(EncryptionFactory.RSA.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new RsaEncryptor(encryptorKey);
            }
        },

    /**
     * RSA非对称加密器(专用于加密机)
     */
    RSAHsm(EncryptionFactory.RSAHsm.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new RsaEncryptor(encryptorKey);
            }
        },

    /**
     * SM2非对称加密器
     */
    SM2(EncryptionFactory.SM2.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm2Encryptor(encryptorKey);
            }
        },

    /**
     * SM2非对称加密器(专用于加密机)
     */
    SM2Hsm(EncryptionFactory.SM2Hsm.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm2Encryptor(encryptorKey);
            }
        },

    /**
     * PGP非对称加密器(内部是复合算法)
     */
    PGP(EncryptionFactory.PGP.getType())
        {
            @Override
            public EncryptEncryptor<PGPSecretKey> createEncryptor(EncryptorKey encryptorKey)
            {
                return new PgpEncryptor(encryptorKey);
            }
        },
    /**
     * 国际非对称加密器(封装的复合算法)
     */
    US(EncryptionFactory.US.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new UsEncryptor(encryptorKey);
            }
        },

    /**
     * GM非对称加密器(封装的复合算法)
     */
    GM(EncryptionFactory.GM.getType())
        {
            @Override
            public SignEncryptor<KeyPair> createEncryptor(EncryptorKey encryptorKey)
            {
                return new GmEncryptor(encryptorKey);
            }
        },

    /**
     * 国际非对称加密器(封装的复合算法，模拟的加密机)
     */
    UsIntegrityHsm(EncryptionFactory.UsIntegrityHsm.getType())
        {
            @Override
            public BaseSingleSignEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new UsHsmEncryptor(encryptorKey);
            }
        },

    /**
     * GM非对称加密器(封装的复合算法，模拟的加密机)
     */
    GmIntegrityHsm(EncryptionFactory.GmIntegrityHsm.getType())
        {
            @Override
            public BaseSingleSignEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new GmHsmEncryptor(encryptorKey);
            }
        },

    /**
     * SHA Hash加密器(默认为SHA512)
     * <p>
     * 通过encryptorKey的hashAlg参数可构造出SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SHA3-224/SHA3-256/SHA3-384/SHA3-512/MD5
     */
    SHA(EncryptionFactory.SHAHash.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new ShaHashEncryptor(encryptorKey);
            }
        },

    /**
     * SHA Hash加密器(专用于加密机)
     * <p>
     */
    SHAHsm(EncryptionFactory.SHAHsm.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new ShaHashEncryptor(encryptorKey);
            }
        },

    /**
     * 常用的sha1
     */
    SHA1(EncryptionFactory.SHA1.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                EncryptorKey key = new EncryptorKey();
                key.setHashAlg(EncryptionFactory.SHA1.getType());
                return new ShaHashEncryptor(key);
            }
        },

    /**
     * 常用的md5(用在加解密中的hash是不安全的)
     */
    MD5(EncryptionFactory.MD5.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                EncryptorKey key = new EncryptorKey();
                key.setHashAlg(EncryptionFactory.MD5.getType());
                return new ShaHashEncryptor(key);
            }
        },

    /**
     * 常用的SHA256
     */
    SHA256(EncryptionFactory.SHA256.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                EncryptorKey key = new EncryptorKey();
                key.setHashAlg(EncryptionFactory.SHA256.getType());
                return new ShaHashEncryptor(key);
            }
        },

    /**
     * 常用的SM3
     */
    SM3(EncryptionFactory.SM3.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm3HashEncryptor();
            }
        },

    /**
     * 常用的SM3(专用于加密机)
     */
    SM3Hsm(EncryptionFactory.SM3Hsm.getType())
        {
            @Override
            protected HashEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm3HashEncryptor();
            }
        },

    /**
     * 常用的SM3 Hmac算法
     */
    SM3Hmac(EncryptionFactory.SM3Hmac.getType())
        {
            @Override
            protected HmacEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new Sm3HmacEncryptor(encryptorKey);
            }
        },

    /**
     * HmacSHA(默认为HmacSHA256)
     */
    HmacSHA(EncryptionFactory.HmacSHA.getType())
        {
            @Override
            protected HmacEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                return new ShaHmacEncryptor(encryptorKey);
            }
        },

    /**
     * 常用的HmacSHA512
     */
    HmacSHA512(EncryptionFactory.HmacSHA512.getType())
        {
            @Override
            protected HmacEncryptor createEncryptor(EncryptorKey encryptorKey)
            {
                encryptorKey.setHashAlg(EncryptionFactory.HmacSHA512.getType());
                return new ShaHmacEncryptor(encryptorKey);
            }
        };

    /**
     * 创建加密器
     *
     * @param algorithm    加密算法名称(可能是别名)
     * @param encryptorKey 秘钥配置参数对象
     * @param <T>          加密器类型
     * @return 新的加密器
     */
    public static <T> T newEncryptor(String algorithm, EncryptorKey encryptorKey)
    {
        for (EncryptorFactory factory : values())
        {
            if (factory.algorithm.equalsIgnoreCase(algorithm))
            {
                return factory.createEncryptor(encryptorKey);
            }
        }
        return null;
    }

    /**
     * 获取加密器名称
     *
     * @return 加密器名称
     */
    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * 创建新的加密器
     *
     * @param encryptorKey 加密器配置
     * @param <T>          加密器类型
     * @return 加密器对象
     */
    protected abstract <T> T createEncryptor(EncryptorKey encryptorKey);

    EncryptorFactory(String algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * 加密器算法名(和加密算法的算法名相同)
     */
    private final String algorithm;
}
