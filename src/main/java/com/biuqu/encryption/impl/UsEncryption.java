package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseMultiSignature;
import com.biuqu.encryption.model.RsaType;

/**
 * 使用了RSA/AES/SHA-512综合加密及签名算法
 * <p>
 * 算法策略：
 * 1.生成RSA的密钥对2对，调用方和服务方各持有其私钥，彼此交换公钥；
 * 2.调用方同时生成AES的对称秘钥；
 * 3.调用方调用服务方的服务时，使用SHA-512对发送报文做摘要，并使用自持RSA私钥对摘要签名，使用AES对报文加密，并使用服务方的公钥对AES秘钥加密；
 * 4.服务方收到调用方的数据后，使用自持RSA私钥解密出AES秘钥，使用AES对称秘钥解密报文密文，再使用SHA-512对报文做摘要，最后再使用调用方的RSA公钥验签摘要；
 *
 * @author BiuQu
 * @date 2023/4/30 23:19
 */
public class UsEncryption extends BaseMultiSignature
{
    /**
     * 构造方法
     */
    public UsEncryption()
    {
        super(ALGORITHM, PADDING_MODE, RsaType.RSA_2048.getLen());

        //以RSA加密算法的配置为主
        this.setSignEncryption(new RsaEncryption());
        this.getSignEncryption().setPaddingMode(this.getPaddingMode());
        this.getSignEncryption().setEncryptLen(this.getEncryptLen());
        this.getSignEncryption().setRandomMode(this.getRandomMode());

        //2.配置AES加解密算法(如果不想每次都生成AES的秘钥，可以在此处生成1个key，再覆写父类getKey方法即可)
        this.setEncEncryption(new AesSecureEncryption());
        this.getEncEncryption().setRandomMode(this.getRandomMode());

        //3.配置SHA-512 HASH算法
        this.setHash(new ShaHash());
    }

    /**
     * 自定义的欧美通用算法简称
     */
    private static final String ALGORITHM = "US";

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "RSA/ECB/PKCS1Padding";
}
