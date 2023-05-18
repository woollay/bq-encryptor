package com.biuqu.encryption;

import com.biuqu.encryption.exception.EncryptionException;
import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * Hash算法的基类
 *
 * @author BiuQu
 * @date 2023/4/30 16:38
 */
@Data
public abstract class BaseHash
{
    /**
     * hash计算
     *
     * @param data 原始数据
     * @return hash值
     */
    protected byte[] calc(byte[] data)
    {
        try
        {
            MessageDigest digestAlg = MessageDigest.getInstance(this.getAlgorithm(), this.getProvider());
            digestAlg.update(data);
            return digestAlg.digest();
        }
        catch (Exception e)
        {
            throw new EncryptionException("invalid hash by:" + this.getAlgorithm() + ",exception:" + e.getMessage());
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

    @Override
    public String toString()
    {
        return "Algorithm:" + algorithm + " is a hash type.";
    }

    static
    {
        //引入BouncyCastle算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * hash算法
     */
    private String algorithm;
}
