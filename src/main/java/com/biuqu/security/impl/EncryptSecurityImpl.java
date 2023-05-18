package com.biuqu.security.impl;

import com.biuqu.encryptor.*;
import com.biuqu.encryptor.impl.*;
import com.biuqu.security.BaseEncryptSecurity;
import lombok.Setter;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * 本地加密安全的实现类
 *
 * @author BiuQu
 * @date 2023/5/7 16:03
 */
@Setter
public class EncryptSecurityImpl extends BaseEncryptSecurity
{
    public EncryptSecurityImpl(boolean gm)
    {
        this.gm = gm;
    }

    public BaseSingleEncryptor getSingleEncryptor(boolean gm)
    {
        return gm ? this.sm4Encryptor : this.aesEncryptor;
    }

    public BaseSingleEncryptor getSecureSingleEncryptor(boolean gm)
    {
        return gm ? this.sm4SecureEncryptor : this.aesSecureEncryptor;
    }

    public BaseSingleSignEncryptor getSignEncryptor(boolean gm)
    {
        return gm ? this.sm2Encryptor : this.rsaEncryptor;
    }

    public BaseHashEncryptor getHashEncryptor(boolean gm)
    {
        return gm ? this.sm3Encryptor : this.shaEncryptor;
    }

    public BaseMultiSignEncryptor getSecureSignEncryptor(boolean gm)
    {
        return gm ? this.gmEncryptor : this.usEncryptor;
    }

    @Override
    public BaseSingleEncryptor getSingleEncryptor()
    {
        return this.getSingleEncryptor(this.gm);
    }

    @Override
    public BaseSingleEncryptor getSecureSingleEncryptor()
    {
        return this.getSecureSingleEncryptor(this.gm);
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
    public BaseMultiSignEncryptor getSecureSignEncryptor()
    {
        return this.getSecureSignEncryptor(this.gm);
    }

    @Override
    public BaseMultiEncryptor<PGPSecretKey> getPgpEncryptor()
    {
        return this.pgpEncryptor;
    }

    /**
     * 是否启用国密加密器
     */
    private final boolean gm;

    /**
     * 国密对称加密算法加密器
     */
    private Sm4Encryptor sm4Encryptor;

    /**
     * 增强的国密对称加密算法加密器
     */
    private Sm4SecureEncryptor sm4SecureEncryptor;

    /**
     * 国密非对称加密算法加密器
     */
    private Sm2Encryptor sm2Encryptor;

    /**
     * 国密Hash算法加密器
     */
    private Sm3HashEncryptor sm3Encryptor;

    /**
     * 国密组合加解密加密器
     */
    private GmEncryptor gmEncryptor;

    /**
     * 国际对称加密算法加密器
     */
    private AesEncryptor aesEncryptor;

    /**
     * 增强的国际对称加密算法加密器
     */
    private AesSecureEncryptor aesSecureEncryptor;

    /**
     * 国际非对称加密算法加密器
     */
    private RsaEncryptor rsaEncryptor;

    /**
     * 国际Hash算法加密器
     */
    private ShaHashEncryptor shaEncryptor;

    /**
     * 国际组合加解密加密器
     */
    private UsEncryptor usEncryptor;

    /**
     * 国际PGP加解密加密器
     */
    private PgpEncryptor pgpEncryptor;
}
