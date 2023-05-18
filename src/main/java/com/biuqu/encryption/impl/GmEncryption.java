package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseMultiSignature;

/**
 * 综合SM2/SM4/SM3的国密安全算法
 * <p>
 * 算法策略：
 * 1.生成SM2的密钥对2对，调用方和服务方各持有其私钥，彼此交换公钥；
 * 2.调用方同时生成sm4的对称秘钥；
 * 3.调用方调用服务方的服务时，使用sm3对发送报文做摘要，并使用自持sm2私钥对摘要签名，使用sm4对报文加密，并使用服务方的公钥对sm4秘钥加密；
 * 4.服务方收到调用方的数据后，使用自持sm2私钥解密出sm4秘钥，使用sm4对称秘钥解密报文密文，再使用sm3对报文做摘要，最后再使用调用方的sm2公钥验签摘要；
 *
 * @author BiuQu
 * @date 2023/4/29 18:30
 */
public class GmEncryption extends BaseMultiSignature
{
    /**
     * 构造方法
     */
    public GmEncryption()
    {
        super(ALGORITHM, String.valueOf(DEFAULT_MODE), 0);

        //以sm2加密算法的配置为主
        this.setSignEncryption(new Sm2Encryption());
        this.getSignEncryption().setPaddingMode(this.getPaddingMode());
        this.getSignEncryption().setEncryptLen(this.getEncryptLen());
        this.getSignEncryption().setRandomMode(this.getRandomMode());

        //2.配置sm4加解密算法(如果不想每次都生成sm4的秘钥，可以在此处生成1个key，再覆写父类getKey方法即可)
        this.setEncEncryption(new Sm4SecureEncryption());
        this.getEncEncryption().setRandomMode(this.getRandomMode());

        //3.配置SM3 HASH算法
        this.setHash(new Sm3Hash());
    }

    /**
     * 自定义的国密算法简称
     */
    private static final String ALGORITHM = "GM";

    /**
     * 默认加密模式为C1C2C3
     */
    private static final int DEFAULT_MODE = 0;
}
