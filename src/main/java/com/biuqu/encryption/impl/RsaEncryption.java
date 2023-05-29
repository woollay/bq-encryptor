package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.exception.EncryptionException;
import com.biuqu.encryption.model.RsaType;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 国际非对称加密RSA算法实现
 * <p>
 * 签名算法支持SHA512WITHRSA/SHA256WITHRSA等
 *
 * @author BiuQu
 * @date 2022/10/02 00:23
 **/
public class RsaEncryption extends BaseSingleSignature
{
    /**
     * 构造方法
     */
    public RsaEncryption()
    {
        super(ALGORITHM, SIGNATURE_ALG_DEFAULT, PADDING_MODE, RsaType.RSA_2048.getLen());
        this.rsaType = RsaType.RSA_2048;
    }

    /**
     * 创建Key对象
     *
     * @param initKey 初始key
     * @return 秘钥对象
     */
    @Override
    public KeyPair createKey(byte[] initKey)
    {
        try
        {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(this.getAlgorithm(), this.getProvider());
            if (null != initKey)
            {
                SecureRandom random = this.createRandom(initKey);
                keyGenerator.initialize(this.getEncryptLen(), random);
            }
            else
            {
                keyGenerator.initialize(this.getEncryptLen());
            }
            return keyGenerator.generateKeyPair();
        }
        catch (Exception e)
        {
            throw new EncryptionException("create rsa key pair error.", e);
        }
    }

    /**
     * 获取公钥对象
     *
     * @param pubKey 公钥二进制
     * @return 公钥对象
     */
    @Override
    public PublicKey toPubKey(byte[] pubKey)
    {
        try
        {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
            KeyFactory keyFactory = KeyFactory.getInstance(this.getAlgorithm());
            return keyFactory.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new EncryptionException("get rsa public key error.", e);
        }
    }

    /**
     * 获取私钥对象
     *
     * @param priKey 私钥二进制
     * @return 私钥对象
     */
    @Override
    public PrivateKey toPriKey(byte[] priKey)
    {
        try
        {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(priKey);
            KeyFactory keyFactory = KeyFactory.getInstance(this.getAlgorithm());
            return keyFactory.generatePrivate(keySpec);
        }
        catch (Exception e)
        {
            throw new EncryptionException("get rsa private key error.", e);
        }
    }

    /**
     * 二进制加密
     * 支持分段加密
     *
     * @param data 明文
     * @param key  秘钥
     * @return 密文
     */
    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] salt)
    {
        return doCipher(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 二进制解密
     * 支持分段解密
     *
     * @param data 密文
     * @param key  秘钥
     * @return 明文
     */
    @Override
    public byte[] decrypt(byte[] data, byte[] key, byte[] salt)
    {
        return doCipher(data, key, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] sign(byte[] data, byte[] key)
    {
        try
        {
            PrivateKey priKey = this.toPriKey(key);
            Signature signature = Signature.getInstance(this.getSignatureAlg(), this.getProvider());
            signature.initSign(priKey);
            signature.update(data);
            return signature.sign();
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to signature.", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] key, byte[] sign)
    {
        try
        {
            PublicKey pubKey = this.toPubKey(key);
            Signature signature = Signature.getInstance(this.getSignatureAlg(), this.getProvider());
            signature.initVerify(pubKey);
            signature.update(data);
            return signature.verify(sign);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to verify signature.", e);
        }
    }

    /**
     * 抽象加解密
     *
     * @param data       明文/密文
     * @param key        秘钥
     * @param cipherMode 加密/解密(1和2分别表示加密和解密，参见{@link  Cipher#DECRYPT_MODE})
     * @return 加解密处理后的结果
     */
    @Override
    public byte[] doCipher(byte[] data, byte[] key, int cipherMode)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            //1.获取秘钥对象
            Key algKey = toKey(key);

            //2.根据填充类型获取加密对象
            Cipher cipher;
            if (null == this.getPaddingMode())
            {
                cipher = Cipher.getInstance(this.getAlgorithm());
            }
            else
            {
                cipher = Cipher.getInstance(this.getPaddingMode(), this.getProvider());
            }

            //3.初始化加密对象
            cipher.init(cipherMode, algKey);

            //4.根据RSA类型获取每次处理报文的最大字节数
            int maxLen = this.rsaType.getDecryptLen(this.getPaddingMode());
            if (cipherMode == Cipher.DECRYPT_MODE)
            {
                maxLen = this.rsaType.getEncryptLen();
            }

            //5.分段加解密
            int start = 0;
            while (start < data.length)
            {
                //5.1获取每次的起始位置
                int limit = start + maxLen;
                limit = Math.min(limit, data.length);
                
                //5.2分段加解密后，把该段报文写入缓存
                byte[] partData = cipher.doFinal(data, start, limit - start);
                out.write(partData, 0, partData.length);

                //5.3把分段的起始位置挪至上一次的结束位置
                start = limit;
            }
            return out.toByteArray();
        }
        catch (Exception e)
        {
            throw new EncryptionException("do rsa encrypt/decrypt error.", e);
        }
        finally
        {
            IOUtils.closeQuietly(out);
        }
    }

    @Override
    public void setEncryptLen(int encryptLen)
    {
        super.setEncryptLen(encryptLen);
        if (null != this.rsaType)
        {
            if (this.rsaType.getLen() != encryptLen)
            {
                this.rsaType = RsaType.getTye(encryptLen);
            }
        }
    }

    /**
     * 获取秘钥(内部判定是公钥还是私钥)
     *
     * @param key 秘钥
     * @return 秘钥对象
     */
    private Key toKey(byte[] key)
    {
        Key rsaKey;
        if (this.rsaType.isPriKey(key))
        {
            rsaKey = toPriKey(key);
        }
        else
        {
            rsaKey = toPubKey(key);
        }
        return rsaKey;
    }

    /**
     * 算法类型
     */
    private static final String ALGORITHM = "RSA";

    /**
     * 加密模式及填充模式
     */
    private static final String PADDING_MODE = "RSA/ECB/PKCS1Padding";

    /**
     * 签名算法(默认)
     */
    private static final String SIGNATURE_ALG_DEFAULT = "SHA512WithRSA";

    /**
     * RSA类型(1024/2048)
     */
    private RsaType rsaType;
}
