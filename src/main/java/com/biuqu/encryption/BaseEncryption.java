package com.biuqu.encryption;

import com.biuqu.encryption.exception.EncryptionException;
import com.biuqu.encryption.factory.EncryptionFactory;
import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;

/**
 * 加密基类
 *
 * @author BiuQu
 * @date 2023/4/30 09:59
 */
@Data
public abstract class BaseEncryption
{
    /**
     * 创建带初始变量的随机数
     *
     * @param initKey 初始向量
     * @return 安全的随机数对象
     */
    public final SecureRandom createRandom(byte[] initKey)
    {
        try
        {
            SecureRandom random = SecureRandom.getInstance(RANDOM_MODE);
            random.setSeed(initKey);
            return random;
        }
        catch (Exception e)
        {
            throw new EncryptionException("create secure random failed.", e);
        }
    }

    /**
     * 获取服务供应商名称
     *
     * @return 加密算法服务供应商名
     */
    protected final String getProvider()
    {
        return BouncyCastleProvider.PROVIDER_NAME;
    }

    static
    {
        //引入BouncyCastle算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 随机数填充模式
     */
    protected static final String RANDOM_MODE = "SHA1PRNG";

    /**
     * 加密算法长度(如：AES长度为256/512,RSA长度为1024/2048等)，同一种加密算法也可以有不同的加密长度
     */
    private int encryptLen;

    /**
     * 算法名称
     */
    private String algorithm;

    /**
     * 算法别名
     */
    private String algorithmAlias;

    /**
     * 填充模式
     */
    private String paddingMode;

    /**
     * 随机数模式
     */
    private String randomMode;

    @Override
    public String toString()
    {
        String alg = algorithm;
        if (null != algorithmAlias)
        {
            alg = algorithmAlias;
        }
        EncryptionFactory facade = EncryptionFactory.get(this);
        String msg = ",encrypt enable:" + facade.canEncrypt() + ",signature enable:" + facade.canSign() + ".";
        return "Algorithm:" + alg + " is a encrypt type,padding:" + paddingMode + ",key length:" + encryptLen + msg;
    }
}
