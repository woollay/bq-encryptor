package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseHsmSingleSignature;
import com.biuqu.encryption.factory.EncryptionFactory;

/**
 * 国密加密机完整性模拟算法
 *
 * @author BiuQu
 * @date 2023/5/3 23:23
 */
public class GmHsmEncryption extends BaseHsmSingleSignature
{
    /**
     * 构造方法
     */
    public GmHsmEncryption()
    {
        super(ALGORITHM, SIGNATURE_ALG, String.valueOf(DEFAULT_MODE), 0);

        //以sm2加密算法的配置为主
        this.setSignEncryption(EncryptionFactory.SM2Hsm.createAlgorithm());

        //配置SM3 HASH算法
        this.setHash(EncryptionFactory.SM3Hsm.createAlgorithm());
    }

    /**
     * SM2签名算法
     */
    private static final String SIGNATURE_ALG = "SM3WithSM2";

    /**
     * 自定义的国密加密机算法简称
     */
    private static final String ALGORITHM = "GmIntegrityHsm";

    /**
     * 默认加密模式为C1C2C3
     */
    private static final int DEFAULT_MODE = 0;
}
