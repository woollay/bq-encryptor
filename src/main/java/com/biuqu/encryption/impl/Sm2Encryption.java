package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.constants.EncryptionConst;
import com.biuqu.encryption.exception.EncryptionException;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

/**
 * 国密非对称加密算法
 *
 * @author BiuQu
 * @date 2023/4/30 14:20
 */
public class Sm2Encryption extends BaseSingleSignature
{

    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     */
    public Sm2Encryption()
    {
        //sm2的填充模式被用来指定为SM2Engine.Mode的值(0表示顺序为SM2Engine.Mode.C1C2C3)
        super(ALGORITHM, SIGNATURE_ALG, String.valueOf(DEFAULT_MODE), 0);
        this.setAlgorithmAlias(ALGORITHM_ALIAS);
    }

    @Override
    public KeyPair createKey(byte[] initKey)
    {
        try
        {
            ECGenParameterSpec paramSpec = new ECGenParameterSpec(SM2_VERSION);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, this.getProvider());
            if (null == initKey)
            {
                initKey = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            }
            SecureRandom random = this.createRandom(initKey);
            keyGen.initialize(paramSpec, random);
            return keyGen.generateKeyPair();
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get sm2 key.", e);
        }
    }

    @Override
    public PublicKey toPubKey(byte[] pubKey)
    {
        try
        {
            String hexKey = Hex.toHexString(pubKey);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, this.getProvider());
            if (hexKey.startsWith(STANDARD_HEX_KEY_PREFIX))
            {
                return kf.generatePublic(new X509EncodedKeySpec(pubKey));
            }
            else
            {
                // 获取SM2相关参数
                X9ECParameters ecParam = GMNamedCurves.getByName(SM2_VERSION);
                // 将公钥HEX字符串转换为椭圆曲线对应的点
                ECCurve ecCurve = ecParam.getCurve();
                ECPoint ecPoint = ecCurve.decodePoint(pubKey);
                // 椭圆曲线参数规格
                ECParameterSpec ecSpec = new ECParameterSpec(ecCurve, ecParam.getG(), ecParam.getN(), ecParam.getH());
                // 将椭圆曲线点转为公钥KEY对象
                return kf.generatePublic(new ECPublicKeySpec(ecPoint, ecSpec));
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get sm2 pub key.", e);
        }
    }

    @Override
    public PrivateKey toPriKey(byte[] priKey)
    {
        try
        {
            String hexKey = Hex.toHexString(priKey);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, this.getProvider());
            if (hexKey.startsWith(STANDARD_HEX_KEY_PREFIX))
            {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(priKey);
                return kf.generatePrivate(keySpec);
            }
            else
            {
                // 获取SM2相关参数
                X9ECParameters ecParam = GMNamedCurves.getByName(SM2_VERSION);
                ECCurve ecCurve = ecParam.getCurve();
                // 椭圆曲线参数规格
                ECParameterSpec ecSpec = new ECParameterSpec(ecCurve, ecParam.getG(), ecParam.getN(), ecParam.getH());
                // 将私钥HEX字符串转换为16进制的数字值
                BigInteger bigInteger = new BigInteger(Hex.toHexString(priKey), EncryptionConst.HEX_UNIT);
                // 将X值转为私钥KEY对象
                return kf.generatePrivate(new ECPrivateKeySpec(bigInteger, ecSpec));
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to get sm2 pri key.", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] salt)
    {
        return this.doCipher(data, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key, byte[] salt)
    {
        return this.doCipher(data, key, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] sign(byte[] data, byte[] key)
    {
        try
        {
            Signature signature = Signature.getInstance(this.getSignatureAlg(), this.getProvider());
            signature.initSign(this.toPriKey(key));
            signature.update(data);
            return signature.sign();
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to do sm2 signature.", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] key, byte[] sign)
    {
        try
        {
            Signature signature = Signature.getInstance(this.getSignatureAlg(), this.getProvider());
            signature.initVerify(this.toPubKey(key));
            signature.update(data);
            return signature.verify(sign);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to do sm2 verify.", e);
        }
    }

    @Override
    public byte[] doCipher(byte[] data, byte[] key, int cipherMode)
    {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C2C3;
        if (!this.getPaddingMode().equalsIgnoreCase(String.valueOf(DEFAULT_MODE)))
        {
            mode = SM2Engine.Mode.C1C3C2;
        }

        SM2Engine sm2Engine = new SM2Engine(mode);

        this.initSm2Engine(sm2Engine, key, cipherMode);

        try
        {
            return sm2Engine.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to do sm2 cipher.", e);
        }
    }

    /**
     * 初始化加密引擎
     *
     * @param sm2Engine  sm2加密引擎
     * @param key        秘钥二进制
     * @param cipherMode 加密/解密(公钥加密，私钥解密)
     */
    private void initSm2Engine(SM2Engine sm2Engine, byte[] key, int cipherMode)
    {
        if (Cipher.ENCRYPT_MODE == cipherMode)
        {
            ECPublicKey keyObj = (ECPublicKey)this.toPubKey(key);
            ECDomainParameters domainParam = this.getDomainParam(keyObj);
            ECKeyParameters keyParam = new ECPublicKeyParameters(keyObj.getQ(), domainParam);
            byte[] initKey = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            sm2Engine.init(true, new ParametersWithRandom(keyParam, this.createRandom(initKey)));
        }
        else
        {
            ECPrivateKey keyObj = (ECPrivateKey)this.toPriKey(key);
            ECDomainParameters domainParam = this.getDomainParam(keyObj);
            ECKeyParameters keyParam = new ECPrivateKeyParameters(keyObj.getD(), domainParam);
            sm2Engine.init(false, keyParam);
        }
    }

    /**
     * 获取椭圆曲线的基本参数
     *
     * @param key 秘钥对象
     * @return 椭圆曲线的域参数
     */
    private ECDomainParameters getDomainParam(ECKey key)
    {
        ECParameterSpec spec = key.getParameters();
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
    }

    /**
     * 标准的秘钥hex前缀
     */
    private static final String STANDARD_HEX_KEY_PREFIX = "30";

    /**
     * SM2加密算法版本
     */
    private static final String SM2_VERSION = "sm2p256v1";

    /**
     * SM2签名算法
     */
    private static final String SIGNATURE_ALG = "SM3WithSM2";

    /**
     * 国际上的非对称加密算法简称
     */
    private static final String ALGORITHM = "EC";

    /**
     * 算法别名
     */
    private static final String ALGORITHM_ALIAS = "SM2";

    /**
     * 默认加密模式为C1C2C3(0表示SM2Engine.Mode.C1C2C3)
     */
    private static final int DEFAULT_MODE = 0;
}
