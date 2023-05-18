package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseMultiEncryption;
import com.biuqu.encryption.converter.PgpKeyBuilder;
import com.biuqu.encryption.converter.impl.PgpKeyConverter;
import com.biuqu.encryption.exception.EncryptionException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.SecureRandom;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * PGP加密算法
 *
 * @author BiuQu
 * @date 2023/5/1 14:34
 */
public class PgpEncryption extends BaseMultiEncryption<PGPSecretKey>
{
    /**
     * 调用此构造方法后，还必须得给kid和pwd赋值
     * <p>
     * 当前只是赋了临时值
     */
    public PgpEncryption()
    {
        this(UUID.randomUUID().toString(), UUID.randomUUID().toString(), 0);
    }

    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     *
     * @param kid    用户唯一标识
     * @param pwd    私钥密码
     * @param expire 过期时间
     */
    public PgpEncryption(String kid, String pwd, long expire)
    {
        super(ALGORITHM, null, 0);
        this.kid = kid;
        this.pwd = pwd.toCharArray();
        this.expire = TimeUnit.MILLISECONDS.toSeconds(expire);
    }

    @Override
    public PGPSecretKey createKey(byte[] initKey)
    {
        try
        {
            PGPKeyRingGenerator keyRingGenerator = PgpKeyBuilder.buildPgpKeyGen(this.pwd, this.kid, this.expire);
            PGPSecretKeyRing keyRing = keyRingGenerator.generateSecretKeyRing();
            return keyRing.getSecretKey();
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to gen pgp secret key.", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] pri, byte[] pub)
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        OutputStream armoredOut = new ArmoredOutputStream(byteOut);
        OutputStream encOut = null;
        OutputStream compressOut = null;
        OutputStream literalOut = null;
        InputStream in = null;
        try
        {
            //1.构造基于对端的公钥的加密器
            BcPGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
            encBuilder.setSecureRandom(new SecureRandom()).setWithIntegrityPacket(true);
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
            PGPPublicKey publicKey = PgpKeyConverter.getPublicKey(pub);
            BcPublicKeyKeyEncryptionMethodGenerator pubEncGen = new BcPublicKeyKeyEncryptionMethodGenerator(publicKey);
            pubEncGen.setSecureRandom(new SecureRandom());
            encGen.addMethod(pubEncGen);

            //2.设置加密数据
            encOut = encGen.open(armoredOut, new byte[BYTE_BUFFER]);

            //3.压缩数据
            PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            compressOut = compressGen.open(encOut, new byte[BYTE_BUFFER]);

            //4.设置PGP签名生成器
            PGPSecretKey secretKey = PgpKeyConverter.getSecretKey(pri);
            int keyAlg = secretKey.getPublicKey().getAlgorithm();
            BcPGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(keyAlg, HashAlgorithmTags.SHA256);
            PGPSignatureGenerator signGen = new PGPSignatureGenerator(signerBuilder);
            PGPPrivateKey privateKey = PgpKeyConverter.getPrivateKey(secretKey, this.pwd);
            signGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            //5.设置签名的分包摘要算法
            PGPSignatureSubpacketGenerator packageSignGen = new PGPSignatureSubpacketGenerator();
            String userId = secretKey.getPublicKey().getUserIDs().next();
            packageSignGen.addSignerUserID(false, userId);
            signGen.setHashedSubpackets(packageSignGen.generate());

            //6.对压缩报文进行签名和编码
            signGen.generateOnePassVersion(false).encode(compressOut);

            PGPLiteralDataGenerator dataGen = new PGPLiteralDataGenerator();
            literalOut = dataGen.open(compressOut, PGPLiteralData.BINARY, "", new Date(), new byte[BYTE_BUFFER]);
            byte[] buffer = new byte[BYTE_BUFFER];
            in = new ByteArrayInputStream(data);
            int len;
            while ((len = in.read(buffer)) > 0)
            {
                literalOut.write(buffer, 0, len);
                signGen.update(buffer, 0, len);
            }

            dataGen.close();
            signGen.generate().encode(compressOut);
            compressGen.close();
            encGen.close();
            IOUtils.closeQuietly(armoredOut);

            return byteOut.toByteArray();
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to encrypt data by pgp.", e);
        }
        finally
        {
            IOUtils.closeQuietly(in);
            IOUtils.closeQuietly(literalOut);
            IOUtils.closeQuietly(compressOut);
            IOUtils.closeQuietly(encOut);
            IOUtils.closeQuietly(armoredOut);
            IOUtils.closeQuietly(byteOut);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] pub, byte[] pri)
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        InputStream decIn = null;
        InputStream decodeIn = null;
        try
        {
            //1.获取公钥加密的数据
            decodeIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(data));
            PGPPublicKeyEncryptedData encryptedData = getEncryptedData(decodeIn);
            //2.获取私钥解密数据
            PGPPrivateKey privateKey = PgpKeyConverter.getPrivateKey(PgpKeyConverter.getSecretKey(pri), this.pwd);
            decIn = encryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
            PGPObjectFactory decFactor = new PGPObjectFactory(decIn, new BcKeyFingerprintCalculator());
            Object decObj = decFactor.nextObject();
            //3.循环读取数据
            PGPOnePassSignatureList onePassList = null;
            PGPSignatureList signList = null;
            while (decObj != null)
            {
                //4.如果是压缩数据，则重新生成压缩数据的解压缩工厂，并继续迭代后续压缩数据
                if (decObj instanceof PGPCompressedData)
                {
                    PGPCompressedData compressData = (PGPCompressedData)decObj;
                    decFactor = new PGPObjectFactory(compressData.getDataStream(), new BcKeyFingerprintCalculator());
                    decObj = decFactor.nextObject();
                }
                //5.如果是PGP包装数据，则还原至字输出节流中
                if (decObj instanceof PGPLiteralData)
                {
                    PGPLiteralData literalData = (PGPLiteralData)decObj;
                    Streams.pipeAll(literalData.getInputStream(), byteOut);
                }
                //6.读取全部数据的整体签名集合对象
                else if (decObj instanceof PGPOnePassSignatureList)
                {
                    onePassList = (PGPOnePassSignatureList)decObj;
                    if (onePassList.isEmpty())
                    {
                        return null;
                    }
                }
                //7.读取分段签名集合对象
                else if (decObj instanceof PGPSignatureList)
                {
                    signList = (PGPSignatureList)decObj;
                }
                decObj = decFactor.nextObject();
            }
            //8.获取解压缩和解密后的数据
            byte[] decBytes = byteOut.toByteArray();
            //9.获取签名算法并对每段都进行签名校验
            PGPOnePassSignature onePassSignature = onePassList.get(0);
            onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), PgpKeyConverter.getPublicKey(pub));
            onePassSignature.update(decBytes);
            for (int i = 0; i < onePassList.size(); i++)
            {
                PGPSignature signature = signList.get(i);
                if (!onePassSignature.verify(signature))
                {
                    return null;
                }
            }
            //10.完整性保护和所有签名都校验通过后，才返回解压缩和解密后的数据
            if (encryptedData.isIntegrityProtected() && encryptedData.verify())
            {
                return decBytes;
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to encrypt data by pgp.", e);
        }
        finally
        {
            IOUtils.closeQuietly(decIn, decodeIn, byteOut);
        }
        return null;
    }

    public void setKid(String kid)
    {
        this.kid = kid;
    }

    public void setPwd(char[] pwd)
    {
        this.pwd = pwd;
    }

    public void setExpire(long expire)
    {
        this.expire = expire;
    }

    /**
     * 获取公钥加密的数据对象
     *
     * @param decodeIn 解码的输入流
     * @return 公钥加密的数据对象
     * @throws IOException 流处理异常
     */
    private PGPPublicKeyEncryptedData getEncryptedData(InputStream decodeIn) throws IOException
    {
        PGPObjectFactory encFactory = new PGPObjectFactory(decodeIn, new BcKeyFingerprintCalculator());
        Object encObj = encFactory.nextObject();
        if (!(encObj instanceof PGPEncryptedDataList))
        {
            encObj = encFactory.nextObject();
        }
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList)encObj;
        PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData)encDataList.iterator().next();
        return encryptedData;
    }

    /**
     * 单次缓存的字节数
     */
    private static final int BYTE_BUFFER = 4096;

    /**
     * PGP算法简称
     */
    private static final String ALGORITHM = "PGP";

    /**
     * 用户的唯一标识(对应一组密钥对)
     */
    private String kid;

    /**
     * 该组用户秘钥的私钥密码
     */
    private char[] pwd;

    /**
     * 过期时间，单位为毫秒
     */
    private long expire;
}
