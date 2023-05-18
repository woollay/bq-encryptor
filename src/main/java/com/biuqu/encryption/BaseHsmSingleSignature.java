package com.biuqu.encryption;

import com.biuqu.encryption.exception.EncryptionException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 模拟加密机的复合加密算法
 * <p>
 * 加密和签名的核心逻辑如下：
 * 1.算法包含1个Hash算法和1个非对称加密算法
 * 2.需要生成1对非对称秘钥；
 * 3.使用Hash算法对报文摘要；
 * 4.使用非对称加密算法的私钥对摘要签名；
 * <p>
 * 解密和验签的逻辑为上述的逆过程，略。
 *
 * @author BiuQu
 * @date 2023/5/3 23:47
 */
public abstract class BaseHsmSingleSignature extends BaseSingleSignature
{
    public BaseHsmSingleSignature(String algorithm, String signatureAlg, String paddingMode, int encryptLen)
    {
        super(algorithm, signatureAlg, paddingMode, encryptLen);
    }

    @Override
    public KeyPair createKey(byte[] initKey)
    {
        return this.signEncryption.createKey(initKey);
    }

    @Override
    public byte[] sign(byte[] data, byte[] key)
    {
        try
        {
            byte[] hashBytes = hash.digest(data);
            byte[] signatureBytes = signEncryption.sign(hashBytes, key);
            return signatureBytes;
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to sign hash data.", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] key, byte[] sign)
    {
        try
        {
            byte[] hashBytes = this.hash.digest(data);
            return this.signEncryption.verify(hashBytes, key, sign);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to verify hash data.", e);
        }
    }

    @Override
    public PublicKey toPubKey(byte[] pubKey)
    {
        return this.signEncryption.toPubKey(pubKey);
    }

    @Override
    public PrivateKey toPriKey(byte[] priKey)
    {
        return this.signEncryption.toPriKey(priKey);
    }

    @Override
    public byte[] doCipher(byte[] data, byte[] key, int cipherMode)
    {
        return new byte[0];
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] pri, byte[] pub)
    {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] pub, byte[] pri)
    {
        return new byte[0];
    }

    public Hash getHash()
    {
        return hash;
    }

    public void setHash(Hash hash)
    {
        this.hash = hash;
    }

    public BaseSingleSignature getSignEncryption()
    {
        return signEncryption;
    }

    public void setSignEncryption(BaseSingleSignature signEncryption)
    {
        this.signEncryption = signEncryption;
    }

    /**
     * 定义hash算法
     */
    private Hash hash;

    /**
     * 非对称加密算法(包括签名)
     */
    private BaseSingleSignature signEncryption;
}
