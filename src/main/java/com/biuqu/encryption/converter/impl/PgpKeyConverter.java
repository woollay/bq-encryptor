package com.biuqu.encryption.converter.impl;

import com.biuqu.encryption.exception.EncryptionException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;

/**
 * PGP秘钥转换器
 *
 * @author BiuQu
 * @date 2023/5/1 13:17
 */
public final class PgpKeyConverter
{
    /**
     * 获取PGP密钥对对象(PGP私钥)
     * <p>
     * 默认取第一个秘钥
     *
     * @param path 秘钥路径
     * @return 秘钥对象
     */
    public static PGPSecretKey getSecretKey(String path)
    {
        try
        {
            return getSecretKey(new FileInputStream(path));
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get pgp secret key.", e);
        }
    }

    /**
     * 获取PGP密钥对对象(PGP私钥)
     * <p>
     * 默认取第一个秘钥
     *
     * @param keyBytes 秘钥字节
     * @return 秘钥对象
     */
    public static PGPSecretKey getSecretKey(byte[] keyBytes)
    {
        return getSecretKey(new ByteArrayInputStream(keyBytes));
    }

    /**
     * 获取PGP密钥对对象(PGP私钥)
     * <p>
     * 默认取第一个秘钥
     *
     * @param in 秘钥流(原始文件流或者字节流)
     * @return 秘钥对象
     */
    public static PGPSecretKey getSecretKey(InputStream in)
    {
        InputStream decodeStream = null;
        try
        {
            decodeStream = PGPUtil.getDecoderStream(in);
            JcaKeyFingerprintCalculator keyCalc = new JcaKeyFingerprintCalculator();
            PGPSecretKeyRingCollection ringCollection = new PGPSecretKeyRingCollection(decodeStream, keyCalc);

            Iterator<PGPSecretKeyRing> iterator = ringCollection.iterator();
            while (iterator.hasNext())
            {
                PGPSecretKeyRing keyRing = iterator.next();
                Iterator<PGPSecretKey> keyIterator = keyRing.iterator();
                if (keyIterator.hasNext())
                {
                    PGPSecretKey secretKey = keyIterator.next();
                    if (secretKey.isSigningKey())
                    {
                        return secretKey;
                    }
                }
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get pgp secret key.", e);
        }
        finally
        {
            IOUtils.closeQuietly(in, decodeStream);
        }
        return null;
    }

    /**
     * 获取私钥秘钥d对对象中的PGP私钥对象
     *
     * @param secretKey PGP标准的秘钥对对象(包含了PGP公私钥、私钥密码等信息)
     * @param pwd       私钥密码
     * @return 私钥对象
     */
    public static PGPPrivateKey getPrivateKey(PGPSecretKey secretKey, char[] pwd)
    {
        try
        {
            BcPBESecretKeyDecryptorBuilder db = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(db.build(pwd));
            return privateKey;
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get pgp private key.", e);
        }
    }

    /**
     * 从公钥文件中读取出公钥对象
     *
     * @param path 公钥文件路径
     * @return 公钥对象
     */
    public static PGPPublicKey getPublicKey(String path)
    {
        try
        {
            return getPublicKey(new FileInputStream(path));
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get pgp public key.", e);
        }
    }

    /**
     * 从未编码的字节数组中读取出公钥对象
     *
     * @param keyBytes 公钥字节数组
     * @return 公钥对象
     */
    public static PGPPublicKey getPublicKey(byte[] keyBytes)
    {
        return getPublicKey(new ByteArrayInputStream(keyBytes));
    }

    /**
     * 从未编码的流中读取出公钥对象
     *
     * @param in 公钥流(原始文件流或者字节流)
     * @return 公钥对象
     */
    public static PGPPublicKey getPublicKey(InputStream in)
    {
        InputStream decodeStream = null;
        try
        {
            decodeStream = PGPUtil.getDecoderStream(in);
            JcaKeyFingerprintCalculator keyCalc = new JcaKeyFingerprintCalculator();
            PGPPublicKeyRingCollection ringCollection = new PGPPublicKeyRingCollection(decodeStream, keyCalc);

            Iterator<PGPPublicKeyRing> iterator = ringCollection.iterator();
            while (iterator.hasNext())
            {
                PGPPublicKeyRing keyRing = iterator.next();
                Iterator<PGPPublicKey> keyIterator = keyRing.iterator();
                if (keyIterator.hasNext())
                {
                    PGPPublicKey publicKey = keyIterator.next();
                    if (publicKey.isEncryptionKey())
                    {
                        return publicKey;
                    }
                }
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get pgp public key.", e);
        }
        finally
        {
            IOUtils.closeQuietly(in, decodeStream);
        }
        return null;
    }

    private PgpKeyConverter()
    {
    }
}
