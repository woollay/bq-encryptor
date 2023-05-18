package com.biuqu.hsm.impl;

import com.biuqu.encryptor.BaseHashEncryptor;
import com.biuqu.encryptor.BaseSingleEncryptor;
import com.biuqu.encryptor.BaseSingleSignEncryptor;
import com.biuqu.encryptor.impl.*;
import com.biuqu.hsm.BaseEncryptHsm;
import lombok.Setter;

/**
 * 加密机的实现类
 *
 * @author BiuQu
 * @date 2023/5/7 14:15
 */
@Setter
public class EncryptHsmImpl extends BaseEncryptHsm
{
    public EncryptHsmImpl(boolean gm)
    {
        this.gm = gm;
    }

    /**
     * 获取对称加密机对象(在加密机场景中用于可逆加密，包括敏感信息的加解密)
     *
     * @param gm 是否国密算法,true表示是
     * @return 对称加密机对象
     */
    public BaseSingleEncryptor getSingleEncryptor(boolean gm)
    {
        return gm ? sm4Encryptor : aesEncryptor;
    }

    /**
     * 获取非对称加密算法(当前加密机中因为效率和秘钥问题，一般没有单独使用)
     *
     * @param gm 是否国密算法,true表示是
     * @return 非对称加密机对象
     */
    public BaseSingleSignEncryptor getSignEncryptor(boolean gm)
    {
        return gm ? sm2Encryptor : rsaEncryptor;
    }

    /**
     * 获取hash加密机对象(在加密机场景中用于不可逆加密，包括口令等不需要解出明文的场景)
     *
     * @param gm 是否国密算法,true表示是
     * @return hash加密机对象
     */
    public BaseHashEncryptor getHashEncryptor(boolean gm)
    {
        return gm ? sm3Encryptor : shaEncryptor;
    }

    /**
     * 获取复合加密算法(在加密机场景中用于数据完整性校验)
     *
     * @param gm 是否国密算法,true表示是
     * @return hash加密机对象
     */
    public BaseSingleSignEncryptor getIntegrityEncryptor(boolean gm)
    {
        return gm ? gmIntegrityEncryptor : usIntegrityEncryptor;
    }

    @Override
    public BaseSingleEncryptor getSingleEncryptor()
    {
        return this.getSingleEncryptor(this.gm);
    }

    @Override
    public BaseSingleSignEncryptor getSignEncryptor()
    {
        return this.getSignEncryptor(this.gm);
    }

    @Override
    public BaseHashEncryptor getHashEncryptor()
    {
        return this.getHashEncryptor(this.gm);
    }

    @Override
    public BaseSingleSignEncryptor getIntegrityEncryptor()
    {
        return this.getIntegrityEncryptor(this.gm);
    }

    /**
     * 是否启用国密加密器
     */
    private final boolean gm;

    /**
     * 国密对称加密算法加密器
     */
    private Sm4SecureEncryptor sm4Encryptor;

    /**
     * 国密非对称加密算法加密器
     */
    private Sm2Encryptor sm2Encryptor;

    /**
     * 国密Hash算法加密器
     */
    private Sm3HashEncryptor sm3Encryptor;

    /**
     * 国密完整性的组合加解密加密器
     */
    private GmHsmEncryptor gmIntegrityEncryptor;

    /**
     * 国际对称加密算法加密器
     */
    private AesSecureEncryptor aesEncryptor;

    /**
     * 国际非对称加密算法加密器
     */
    private RsaEncryptor rsaEncryptor;

    /**
     * 国际Hash算法加密器
     */
    private ShaHashEncryptor shaEncryptor;

    /**
     * 国际通用完整性的组合加解密加密器
     */
    private UsHsmEncryptor usIntegrityEncryptor;
}
