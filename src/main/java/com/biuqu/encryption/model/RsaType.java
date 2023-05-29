package com.biuqu.encryption.model;

import com.biuqu.encryption.constants.EncryptionConst;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 支持的RSA类型
 *
 * @author BiuQu
 * @date 2022/10/06 01:06
 **/
public enum RsaType
{
    /**
     * RSA 1024位
     */
    RSA_1024(1024),

    /**
     * RSA 2048位
     */
    RSA_2048(2048),

    /**
     * RSA 3072位
     */
    RSA_3072(3072),

    /**
     * RSA 4096位
     */
    RSA_4096(4096);

    /**
     * 根据加密算法长度获取RSA类型
     *
     * @param keyLen 加密算法长度(1024/2048)
     * @return RSA类型(RSA1024 / RSA2048)
     */
    public static RsaType getTye(int keyLen)
    {
        for (RsaType rsaType : values())
        {
            if (keyLen == rsaType.getLen())
            {
                return rsaType;
            }
        }
        return null;
    }

    /**
     * 根据秘钥获取RSA类型
     * <p>
     * 参考{@link RsaType#isPriKey(byte[])}的判定规则
     *
     * @param key 公钥/私钥
     * @return RSA类型
     */
    public static RsaType getType(byte[] key)
    {
        if (null != key && key.length > 0)
        {
            int keyLen = key.length;
            for (RsaType rsaType : values())
            {
                if (keyLen >= rsaType.getLen())
                {
                    continue;
                }
                else
                {
                    return rsaType;
                }
            }
        }
        return null;
    }

    /**
     * 是否是私钥
     * <p>
     * 经统计，规则如下：
     * 1.私钥长度介于加密算法长度的(1/2-1)
     * 2.公钥介于加密算法长度的(1/8-1/2)
     *
     * @param key 秘钥二进制
     * @return true表示私钥
     */
    public boolean isPriKey(byte[] key)
    {
        if (null != key && key.length > 0)
        {
            int keyLen = key.length;
            int maxKeyLen = this.getLen();
            int minKeyLen = maxKeyLen / PRI_RATIO;
            return (keyLen < maxKeyLen && keyLen > minKeyLen);
        }
        return false;
    }

    /**
     * 获取密文块长度(单次解密时能够支持的最大byte长度)
     * <p>
     * 加密算法长度通常表示是多少bit,所以密文块实际长度byte需要除以8
     *
     * @return 密文块长度
     */
    public int getEncryptLen()
    {
        return this.getLen() / EncryptionConst.BYTE_TO_BIT;
    }

    /**
     * 获取明文块长度(单次加密时能够支持的最大byte长度)
     * <p>
     * 以PKCS1填充算法为例：
     * 因为明文块最大为${AlgLen}/8，但是又需要有11byte的填充符，所以每次实际只能针对${AlgLen}/8-11的字符长度加密
     *
     * @param algorithm 非对称加密算法(带填充模式)
     * @return 明文块长度
     */
    public int getDecryptLen(String algorithm)
    {
        //默认是NoPadding
        int paddingLen = 0;
        if (!StringUtils.isEmpty(algorithm))
        {
            for (String padding : PADDING_MAP.keySet())
            {
                if (algorithm.toUpperCase(Locale.ROOT).endsWith(padding.toUpperCase(Locale.ROOT)))
                {
                    paddingLen = PADDING_MAP.get(padding);
                    break;
                }
            }
        }
        return this.getEncryptLen() - paddingLen;
    }

    /**
     * 获取加密算法的长度
     *
     * @return 加密算法的长度
     */
    public int getLen()
    {
        return this.len;
    }

    /**
     * 构造方法
     *
     * @param len 算法长度
     */
    RsaType(int len)
    {
        this.len = len;
    }

    /**
     * RSA加密算法的长度
     */
    private int len;

    /**
     * RSA的OAEP填充算法的填充标记占位为42byte
     */
    private static final int OAEP_PADDING_LEN = 42;

    /**
     * RSA默认的PKCS1填充算法的填充标记占位为11byte
     */
    private static final int PKCS1_PADDING_LEN = 11;

    /**
     * 私钥长度占加密算法长度的50%以上
     */
    private static final int PRI_RATIO = 2;

    /**
     * 填充算法对应的长度关系
     */
    private static final Map<String, Integer> PADDING_MAP = new HashMap<>();

    static
    {
        PADDING_MAP.put("/NoPadding", 0);
        PADDING_MAP.put("/OAEPPadding", OAEP_PADDING_LEN);
        PADDING_MAP.put("/PKCS1Padding", PKCS1_PADDING_LEN);
    }
}
