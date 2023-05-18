package com.biuqu.encryption.converter;

import com.biuqu.encryption.exception.EncryptionException;
import com.biuqu.encryption.model.RsaType;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * PGP秘钥构建器
 *
 * @author BiuQu
 * @date 2023/5/1 10:09
 */
public final class PgpKeyBuilder
{
    /**
     * 构建pgp秘钥生成器
     *
     * @param pwd    私钥密码
     * @param kid    用户唯一标识
     * @param expire pgp秘钥过期时间(秒)
     * @return pgp秘钥生成器
     * @throws PGPException pgp异常
     */
    public static PGPKeyRingGenerator buildPgpKeyGen(char[] pwd, String kid, long expire) throws PGPException
    {
        //1.构建pgp签名生成器
        PGPSignatureSubpacketGenerator signGen = new PGPSignatureSubpacketGenerator();
        signGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signGen.setPreferredSymmetricAlgorithms(false, SYM_ALG_TYPE);
        signGen.setPreferredHashAlgorithms(false, HASH_ALG_TYPE);
        signGen.setPreferredCompressionAlgorithms(false, COMPRESS_ALG_TYPE);
        signGen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        //设置为0表示永不过期
        signGen.setKeyExpirationTime(false, expire);

        //2.构建pgp加密生成器
        PGPSignatureSubpacketGenerator encGen = new PGPSignatureSubpacketGenerator();
        encGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        //3.构建秘钥剪加密器
        PGPDigestCalculatorProvider hashProvider = new BcPGPDigestCalculatorProvider();
        PGPDigestCalculator sha256Calc = hashProvider.get(HashAlgorithmTags.SHA256);
        //秘钥使用AES256加密
        int symEncTag = PGPEncryptedData.AES_256;
        BcPBESecretKeyEncryptorBuilder encBuilder = new BcPBESecretKeyEncryptorBuilder(symEncTag, sha256Calc, S2K);
        PBESecretKeyEncryptor encryptor = encBuilder.build(pwd);

        //4.构造pgp秘钥生成器
        List<PGPKeyPair> pairs = genKeyPair();
        int i = 0;
        PGPKeyPair signKey = pairs.get(i++);
        int signAlg = signKey.getPublicKey().getAlgorithm();
        PGPDigestCalculator sha1Calc = hashProvider.get(HashAlgorithmTags.SHA1);
        BcPGPContentSignerBuilder signBuilder = new BcPGPContentSignerBuilder(signAlg, sha1Calc.getAlgorithm());
        int signType = PGPSignature.POSITIVE_CERTIFICATION;
        PGPSignatureSubpacketVector signVector = signGen.generate();
        PGPKeyRingGenerator ringGen =
            new PGPKeyRingGenerator(signType, signKey, kid, sha1Calc, signVector, null, signBuilder, encryptor);
        PGPKeyPair encryptKey = pairs.get(i);
        ringGen.addSubKey(encryptKey, encGen.generate(), null);

        return ringGen;
    }

    /**
     * 保存pgp秘钥对象到文件
     *
     * @param keyRing 秘钥对象(可以是公钥，也可以是私钥)
     * @param path    文件路径
     */
    public static void savePgpKeyFile(PGPKeyRing keyRing, String path)
    {
        ArmoredOutputStream pgpKeyOut = null;
        try
        {
            FileUtils.forceMkdirParent(new File(path));
            pgpKeyOut = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(path)));
            keyRing.encode(pgpKeyOut);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to save pgp key.", e);
        }
        finally
        {
            IOUtils.closeQuietly(pgpKeyOut);
        }
    }

    /**
     * 生成PGP2组密钥对
     *
     * @return PGP2组密钥对
     * @throws PGPException PGP秘钥生成异常
     */
    private static List<PGPKeyPair> genKeyPair() throws PGPException
    {
        List<PGPKeyPair> pairs = new ArrayList<>();

        //1.构建RSA秘钥对
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        BigInteger pubExponent = BigInteger.valueOf(PUBLIC_EXPONENT);
        int encLen = RsaType.RSA_2048.getLen();
        SecureRandom random = new SecureRandom();
        KeyGenerationParameters kgParam = new RSAKeyGenerationParameters(pubExponent, random, encLen, CERTAINTY);
        kpg.init(kgParam);

        //2.根据RSA密钥对构建pgp加密秘钥和签名秘钥
        PGPKeyPair signKey = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
        pairs.add(signKey);

        PGPKeyPair encryptKey = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
        pairs.add(encryptKey);

        return pairs;
    }

    private PgpKeyBuilder()
    {
    }

    /**
     * S2K函数的迭代计数器
     */
    private static final int S2K = 0xc0;

    /**
     * 公共指数
     */
    private static final int PUBLIC_EXPONENT = 0x10001;

    /**
     * 构建rsa秘钥的固定值(后面会根据这个固定值来随机数)
     */
    private static final int CERTAINTY = 12;

    /**
     * 对称加密算法类型集合(仅保留了安全的对称加密算法)
     */
    private static final int[] SYM_ALG_TYPE = {SymmetricKeyAlgorithmTags.AES_256};

    /**
     * HASH算法类型集合(仅保留了安全的哈希算法)
     */
    private static final int[] HASH_ALG_TYPE = {HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA512};

    /**
     * 压缩算法类型集合
     */
    private static final int[] COMPRESS_ALG_TYPE = {CompressionAlgorithmTags.ZIP, CompressionAlgorithmTags.ZLIB};
}
