package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHsmSingleSignature;
import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryption.model.RsaType;

/**
 * 国际加密机完整性模拟算法
 *
 * @author BiuQu
 * @date 2023/5/3 23:23
 */
public class UsHsmEncryption extends BaseHsmSingleSignature
{
    /**
     * 构造方法
     */
    public UsHsmEncryption()
    {
        super(ALGORITHM, SIGNATURE_ALG_DEFAULT, PADDING_MODE, RsaType.RSA_2048.getLen());

        //以RSA加密算法的配置为主
        this.setSignEncryption(EncryptionFactory.RSAHsm.createAlgorithm());

        //配置SHA-512 HASH算法
        this.setHash(EncryptionFactory.SHAHsm.createAlgorithm());
    }

    /**
     * 签名算法(默认)
     */
    private static final String SIGNATURE_ALG_DEFAULT = "SHA512WithRSA";

    /**
     * 自定义的国际加密机算法简称
     */
    private static final String ALGORITHM = "UsIntegrityHsm";

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "RSA/ECB/PKCS1Padding";
}
