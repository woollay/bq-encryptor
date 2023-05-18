package com.biuqu.encryption.factory;

import com.biuqu.encryption.BaseEncryption;
import com.biuqu.encryption.BaseHash;
import com.biuqu.encryption.impl.*;
import org.apache.commons.lang3.StringUtils;

/**
 * 加密算法工厂
 * <p>
 * 1.列举了常用的加解密和Hash算法，并在单元测试类中给出了扩展实现；
 * 2.不分加密算法有不同的加密长度，还有不同的填充模式，也在本类的单元测试中实现了；
 *
 * @author BiuQu
 * @date 2023/4/27 08:19
 */
public enum EncryptionFactory
{
    /**
     * 国密非对称加密(对标RSA)
     */
    SM2("SM2", true, true, true)
        {
            @Override
            public Sm2Encryption createAlgorithm()
            {
                return new Sm2Encryption();
            }
        },

    /**
     * 国密非对称加密(专用于加密机)
     */
    SM2Hsm("SM2Hsm", true, true, true)
        {
            @Override
            public Sm2Encryption createAlgorithm()
            {
                return new Sm2Encryption();
            }
        },

    /**
     * 国密摘要算法
     */
    SM3("SM3", false, false, true)
        {
            @Override
            public Sm3Hash createAlgorithm()
            {
                return new Sm3Hash();
            }
        },

    /**
     * 国密摘要算法(专用于加密机)
     */
    SM3Hsm("SM3Hsm", false, false, true)
        {
            @Override
            public Sm3Hash createAlgorithm()
            {
                return new Sm3Hash();
            }
        },

    /**
     * 国密带秘钥的摘要算法
     */
    SM3Hmac("HmacSM3", false, false, true)
        {
            @Override
            public Sm3HmacKeyHash createAlgorithm()
            {
                return new Sm3HmacKeyHash();
            }
        },

    /**
     * 国密对称加密算法(对标AES)
     */
    SM4("SM4", true, false, true)
        {
            @Override
            public Sm4Encryption createAlgorithm()
            {
                return new Sm4Encryption();
            }
        },

    /**
     * 国密对称加密算法(专用于加密机)
     */
    SM4Hsm("SM4Hsm", true, false, true)
        {
            @Override
            public Sm4SecureEncryption createAlgorithm()
            {
                return new Sm4SecureEncryption();
            }
        },

    /**
     * 国密对称加密算法(对标AES)
     * <p>
     * 加密数据默认带16字节的盐值
     */
    SecureSM4("SecureSM4", true, false, true)
        {
            @Override
            public Sm4SecureEncryption createAlgorithm()
            {
                return new Sm4SecureEncryption();
            }
        },

    /**
     * 国际对称加密算法3DES
     * <p>
     */
    DES3("3DES", true, false, false)
        {
            @Override
            public Des3Encryption createAlgorithm()
            {
                return new Des3Encryption();
            }
        },

    /**
     * 国际对称加密算法
     * <p>
     * 1.默认为AES256;
     * 2.加密算法支持:AES256(安全)/AES192(不安全)/AES128(不安全);
     * 3.构造AES192/AES128的方法参见本类的单元测试类;
     */
    AES("AES", true, false, false)
        {
            @Override
            public AesEncryption createAlgorithm()
            {
                return new AesEncryption();
            }
        },

    /**
     * 国际对称加密算法
     * <p>
     * 加密数据默认带16字节的盐值
     */
    SecureAES("SecureAES", true, false, false)
        {
            @Override
            public AesSecureEncryption createAlgorithm()
            {
                return new AesSecureEncryption();
            }
        },

    /**
     * 国际对称加密算法(专用于加密机)
     * <p>
     * 加密数据默认带16字节的盐值
     */
    AESHsm("AESHsm", true, false, false)
        {
            @Override
            public AesSecureEncryption createAlgorithm()
            {
                return new AesSecureEncryption();
            }
        },

    /**
     * 国际非对称加密算法
     * <p>
     * 加密算法支持:RSA2048(安全)/RSA1024(不安全)
     * 签名算法支持：SHA512WITHRSA/SHA256WITHRSA
     */
    RSA("RSA", true, true, false)
        {
            @Override
            public RsaEncryption createAlgorithm()
            {
                return new RsaEncryption();
            }
        },

    /**
     * 国际非对称加密算法(专用于加密机)
     * <p>
     * 加密算法支持:RSA2048(安全)/RSA1024(不安全)
     * 签名算法支持：SHA512WITHRSA/SHA256WITHRSA
     */
    RSAHsm("RSAHsm", true, true, false)
        {
            @Override
            public RsaEncryption createAlgorithm()
            {
                return new RsaEncryption();
            }
        },

    /**
     * 国际上的消息加密、文件加密算法(签名在加密里面，不需要单独签名)
     */
    PGP("PGP", true, false, false)
        {
            @Override
            public PgpEncryption createAlgorithm()
            {
                //此构造方法还必须得赋值pwd和kid才能和对端对接
                return new PgpEncryption();
            }
        },

    /**
     * 国密组合加密+签名算法，类似PGP
     */
    GM("GM", true, true, true)
        {
            @Override
            public GmEncryption createAlgorithm()
            {
                return new GmEncryption();
            }
        },

    /**
     * 国密组合加密+签名的模拟加密器算法，类似PGP
     */
    GmIntegrityHsm("GmIntegrityHsm", true, false, true)
        {
            @Override
            public GmHsmEncryption createAlgorithm()
            {
                return new GmHsmEncryption();
            }
        },

    /**
     * 国际组合加密+签名的模拟加密器算法，类似PGP
     */
    UsIntegrityHsm("UsIntegrityHsm", true, false, true)
        {
            @Override
            public UsHsmEncryption createAlgorithm()
            {
                return new UsHsmEncryption();
            }
        },

    /**
     * 国际组合加密+签名算法，类似PGP
     */
    US("US", true, true, false)
        {
            @Override
            public UsEncryption createAlgorithm()
            {
                return new UsEncryption();
            }
        },

    /**
     * 国际摘要算法
     * <p>
     * 1.默认使用SHA-512，注意:`摘要`/`哈希`/`Hash`均表示同一个意思;
     * 2.算法支持但不限于：SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SHA3-224/SHA3-256/SHA3-384/SHA3-512/MD5
     * 3.下面已经枚举了几个常用的Hash算法，上面列举的不常用Hash算法实现可参见本类的单元测试类
     */
    SHAHash("SHA-512", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                return new ShaHash();
            }
        },

    /**
     * 常用的SHA512国际摘要算法(专用于加密机)
     */
    SHAHsm("SHAHsm", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                return new ShaHash();
            }
        },

    /**
     * 常用的SHA512国际摘要算法
     */
    SHA512("SHA-512", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                return new ShaHash();
            }
        },

    /**
     * 常用的SHA256国际摘要算法
     */
    SHA256("SHA-256", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                ShaHash hash = new ShaHash();
                hash.setAlgorithm(this.getType());
                return hash;
            }
        },

    /**
     * 常用的SHA1国际摘要算法
     */
    SHA1("SHA-1", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                ShaHash hash = new ShaHash();
                hash.setAlgorithm(this.getType());
                return hash;
            }
        },

    /**
     * 常用的MD5摘要算法(不安全)
     */
    MD5("MD5", false, false, false)
        {
            @Override
            public ShaHash createAlgorithm()
            {
                ShaHash hash = new ShaHash();
                hash.setAlgorithm(this.getType());
                return hash;
            }
        },

    /**
     * 国际带秘钥的摘要算法
     * <p>
     * 1.默认使用HmacSHA256,`Hmac`表示为上述的SHA算法带上Mac秘钥;
     * 2.算法支持但不限于：HmacSHA1/HmacSHA224/HmacSHA256/HmacSHA384/HmacSHA512/HmacMD5
     * 3.下面已经枚举了几个常用的Hash算法，上面列举的不常用Hash算法实现可参见本类的单元测试类
     */
    HmacSHA("HmacSHA256", false, false, false)
        {
            @Override
            public ShaHmacKeyHash createAlgorithm()
            {
                return new ShaHmacKeyHash();
            }
        },

    /**
     * 常用的HmacSHA256摘要算法
     */
    HmacSHA256("HmacSHA256", false, false, false)
        {
            @Override
            public ShaHmacKeyHash createAlgorithm()
            {
                return new ShaHmacKeyHash();
            }
        },

    /**
     * 常用的HmacSHA512摘要算法
     */
    HmacSHA512("HmacSHA512", false, false, false)
        {
            @Override
            public ShaHmacKeyHash createAlgorithm()
            {
                ShaHmacKeyHash keyHash = new ShaHmacKeyHash();
                keyHash.setAlgorithm(this.getType());
                return keyHash;
            }
        };

    /**
     * 获取算法类型
     *
     * @param type 算法类型名
     * @return 算法类型对象
     */
    public static EncryptionFactory get(String type)
    {
        if (StringUtils.isEmpty(type))
        {
            return null;
        }
        for (EncryptionFactory encType : values())
        {
            if (encType.type.equalsIgnoreCase(type))
            {
                return encType;
            }
        }
        return null;
    }

    /**
     * 获取算法类型枚举对象
     *
     * @param encryption 算法对象
     * @return 算法枚举类型对象
     */
    public static EncryptionFactory get(BaseEncryption encryption)
    {
        String algorithm = encryption.getAlgorithmAlias();
        if (null == algorithm)
        {
            algorithm = encryption.getAlgorithm();
        }
        return get(algorithm);
    }

    /**
     * 获取算法类型枚举对象
     *
     * @param hash hash算法对象
     * @return 算法枚举类型对象
     */
    public static EncryptionFactory get(BaseHash hash)
    {
        return get(hash.getAlgorithm());
    }

    /**
     * 是否可以签名
     *
     * @return true表示可以
     */
    public boolean canSign()
    {
        return this.enabledSign;
    }

    /**
     * 是否可以加密
     *
     * @return true表示可以
     */
    public boolean canEncrypt()
    {
        return this.enabledEncrypt;
    }

    /**
     * 是否为国密加密算法
     *
     * @return true表示是国密算法
     */
    public boolean isGm()
    {
        return gm;
    }

    /**
     * 获取算法类型
     *
     * @return 算法类型
     */
    public String getType()
    {
        return this.type;
    }

    /**
     * 创建算法对象
     * <p>
     * 包含hash和加密算法
     *
     * @param <T> 指定的算法对象类型
     * @return 算法对象
     */
    public abstract <T> T createAlgorithm();

    EncryptionFactory(String type, boolean enabledEncrypt, boolean enabledSign, boolean gm)
    {
        this.type = type;
        this.enabledEncrypt = enabledEncrypt;
        this.enabledSign = enabledSign;
        this.gm = gm;
    }

    /**
     * 算法类型
     */
    private final String type;

    /**
     * 是否支持加密
     */
    private final boolean enabledEncrypt;

    /**
     * 是否支持签名
     */
    private final boolean enabledSign;

    /**
     * 是否是国密算法
     */
    private final boolean gm;
}
