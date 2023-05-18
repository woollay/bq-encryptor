package com.biuqu.encryption.converter.impl;

import com.biuqu.encryption.converter.BasePemConverter;
import com.biuqu.encryption.exception.EncryptionException;
import com.biuqu.encryption.model.RsaType;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * RSA Pem格式文件的转换器
 *
 * @author BiuQu
 * @date 2022/11/11 23:15
 **/
public class RsaPemConverter extends BasePemConverter
{
    @Override
    public byte[] toPubKey(InputStream in)
    {
        try
        {
            Object pemObj = toPemObj(in);
            KeyPair keyPair = null;
            try
            {
                keyPair = toPair(pemObj, null);
            }
            catch (EncryptionException e)
            {
            }

            PublicKey key;
            if (null != keyPair)
            {
                key = keyPair.getPublic();
            }
            else
            {
                key = toPemPubKey(pemObj);
            }
            return key.getEncoded();
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pub stream error.", e);
        }
    }

    @Override
    public byte[] toPriKey(InputStream in, byte[] pwd)
    {
        try
        {
            Object pemObj = toPemObj(in);
            KeyPair keyPair = null;
            try
            {
                keyPair = toPair(pemObj, null);
            }
            catch (EncryptionException e)
            {
            }

            PrivateKey key;
            if (null != keyPair)
            {
                key = keyPair.getPrivate();
            }
            else
            {
                key = toPemPriKey(pemObj, pwd);
            }
            return key.getEncoded();
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pri stream error.", e);
        }
    }

    @Override
    public void toPem(byte[] key, String path)
    {
        PemWriter writer = null;
        try
        {
            File parentDir = FileUtils.createParentDirectories(new File(path));
            if (!parentDir.exists())
            {
                throw new EncryptionException("No pem dir error.");
            }
            writer = new PemWriter(new FileWriter(path));

            String type;
            ASN1Primitive primitive;
            if (RsaType.getType(key).isPriKey(key))
            {
                type = PEMParser.TYPE_RSA_PRIVATE_KEY;

                PrivateKeyInfo priInfo = PrivateKeyInfo.getInstance(key);
                ASN1Encodable priEncode = priInfo.parsePrivateKey();
                primitive = priEncode.toASN1Primitive();
            }
            else
            {
                type = PEMParser.TYPE_RSA_PUBLIC_KEY;

                SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(key);
                primitive = pubInfo.parsePublicKey().toASN1Primitive();
            }
            byte[] pkcs1Bytes = primitive.getEncoded();
            writer.writeObject(new PemObject(type, pkcs1Bytes));
            writer.flush();
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pri stream error.", e);
        }
        finally
        {
            IOUtils.closeQuietly(writer);
        }
    }

    /**
     * 获取Pem格式的对象
     *
     * @param in 输入流
     * @return PEM对象
     */
    public Object toPemObj(InputStream in)
    {
        PEMParser parser = null;
        try
        {
            InputStreamReader reader = new InputStreamReader(in);
            parser = new PEMParser(reader);
            Object pemObj = parser.readObject();
            return pemObj;
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem stream error.", e);
        }
        finally
        {
            IOUtils.closeQuietly(parser);
        }
    }

    /**
     * 获取私钥对象
     *
     * @param pemObj 私钥key
     * @param pwd    秘钥密码
     * @return 私钥对象
     */
    public PrivateKey toPemPriKey(Object pemObj, byte[] pwd)
    {
        try
        {
            KeyPair keyPair = toPair(pemObj, pwd);
            return keyPair.getPrivate();
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pri key error.", e);
        }
    }

    /**
     * 获取公钥
     *
     * @param pemObj 公钥Pem对象
     * @return 公钥对象
     */
    public PublicKey toPemPubKey(Object pemObj)
    {
        try
        {
            PublicKey pubKey = null;

            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();
            pemKeyConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (pemObj instanceof SubjectPublicKeyInfo)
            {
                SubjectPublicKeyInfo pemPubKey = (SubjectPublicKeyInfo)pemObj;
                pubKey = pemKeyConverter.getPublicKey(pemPubKey);
            }
            return pubKey;
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pri key error.", e);
        }
    }

    @Override
    protected KeyPair toPair(InputStream in, byte[] pwd)
    {
        try
        {
            Object pemObj = toPemObj(in);
            return toPair(pemObj, pwd);
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pair error.", e);
        }
    }

    /**
     * 根据Pem对象获取秘钥对
     *
     * @param pemObj Pem对象
     * @param pwd    秘钥的密码
     * @return 秘钥键值对
     */
    private KeyPair toPair(Object pemObj, byte[] pwd)
    {
        try
        {
            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();
            pemKeyConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            PEMKeyPair pemKeyPair = null;
            if (pemObj instanceof PEMEncryptedKeyPair)
            {
                PEMEncryptedKeyPair enPemKeyPair = (PEMEncryptedKeyPair)pemObj;
                PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder().build(Hex.encodeHex(pwd));
                pemKeyPair = enPemKeyPair.decryptKeyPair(provider);
            }
            else if (pemObj instanceof PEMKeyPair)
            {
                pemKeyPair = (PEMKeyPair)pemObj;
            }
            return pemKeyConverter.getKeyPair(pemKeyPair);
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse pem pair error.", e);
        }
    }
}