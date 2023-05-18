package com.biuqu.encryption.converter;

import com.biuqu.encryption.exception.EncryptionException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * X509Certificate证书对象构建器
 *
 * @author BiuQu
 * @date 2023/2/17 20:56
 */
public final class X509CertificateBuilder
{
    /**
     * 构建证书构建器的builder对象
     *
     * @param keyPair 秘钥对
     * @return builder对象
     */
    public static X509CertificateBuilder builder(KeyPair keyPair)
    {
        if (null == keyPair)
        {
            throw new EncryptionException("unknown key pair to certificate.");
        }
        return new X509CertificateBuilder(keyPair);
    }

    /**
     * 添加证书有效的开始时间
     *
     * @param startTime 开始时间(ms)
     * @return builder对象
     */
    public X509CertificateBuilder appendStartTime(long startTime)
    {
        this.startTime = startTime;
        return this;
    }

    /**
     * 添加证书有效的截止时间
     *
     * @param expireTime 过期时间(ms)
     * @return builder对象
     */
    public X509CertificateBuilder appendExpireTime(long expireTime)
    {
        this.expireTime = expireTime;
        return this;
    }

    /**
     * 添加签名算法
     *
     * @param signatureAlg 签名算法
     * @return builder对象
     */
    public X509CertificateBuilder appendSignature(String signatureAlg)
    {
        this.signatureAlg = signatureAlg;
        return this;
    }

    /**
     * 构建颁发机构对象
     *
     * @param issuer 颁发机构
     * @return builder对象
     */
    public X509CertificateBuilder appendIssuer(X500Name issuer)
    {
        this.issuer = issuer;
        return this;
    }

    /**
     * 构建使用证书的机构对象
     *
     * @param subject 使用证书的机构
     * @return builder对象
     */
    public X509CertificateBuilder appendSubject(X500Name subject)
    {
        this.subject = subject;
        return this;
    }

    /**
     * build证书构建器对象
     *
     * @return 证书构建器对象
     */
    public X509Certificate build()
    {
        X509v3CertificateBuilder certGen = buildX509CertBuilder();
        try
        {
            // 设置密钥用法
            X509KeyUsage keyUsage = new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation);
            certGen.addExtension(Extension.keyUsage, false, keyUsage);
            // 设置扩展密钥用法：客户端身份认证、安全电子邮件
            certGen.addExtension(Extension.extendedKeyUsage, false, defaultKeyUsage());
            // 基础约束,标识是否是CA证书，这里false标识为实体证书
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            // Netscape Cert Type SSL客户端身份认证
            NetscapeCertType netscapeCertType = new NetscapeCertType(NetscapeCertType.sslClient);
            certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false, netscapeCertType);

            String provider = BouncyCastleProvider.PROVIDER_NAME;
            JcaContentSignerBuilder signer = new JcaContentSignerBuilder(this.signatureAlg);
            ContentSigner sigGen = signer.setProvider(provider).build(keyPair.getPrivate());
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(provider);

            // 将证书构造参数装换为X.509证书对象
            return converter.getCertificate(certGen.build(sigGen));
        }
        catch (Exception e)
        {
            throw new EncryptionException(e.getMessage());
        }
    }

    /**
     * X509Certificate证书构建器
     *
     * @return 构建者
     */
    private X509v3CertificateBuilder buildX509CertBuilder()
    {
        if (this.startTime <= 0)
        {
            this.startTime = System.currentTimeMillis();
        }

        if (this.expireTime <= this.startTime)
        {
            this.expireTime = this.startTime + TimeUnit.DAYS.toMillis(1);
        }

        if (this.issuer == null)
        {
            this.issuer = defaultName();
        }

        if (null == this.subject)
        {
            this.subject = defaultName();
        }

        PublicKey pub = this.keyPair.getPublic();
        if (null == this.signatureAlg)
        {
            this.signatureAlg = RSA_SIGNATURE_ALG;
            if (pub instanceof ECPublicKey)
            {
                this.signatureAlg = SM2_SIGNATURE_ALG;
            }
        }

        // 构造X.509 第3版的证书构建者
        Date valid = new Date(this.startTime);
        Date expire = new Date(this.expireTime);
        BigInteger serial = BigInteger.valueOf(1);
        return new JcaX509v3CertificateBuilder(issuer, serial, valid, expire, subject, pub);
    }

    /**
     * 构建公钥扩展用途
     *
     * @return 封装的扩展向量集合
     */
    private DERSequence defaultKeyUsage()
    {
        // 构造容器对象
        ASN1EncodableVector vector = new ASN1EncodableVector();
        // 客户端身份认证
        vector.add(KeyPurposeId.id_kp_clientAuth);
        // 安全电子邮件
        vector.add(KeyPurposeId.id_kp_emailProtection);
        return new DERSequence(vector);
    }

    /**
     * 构建默认的证书所属信息(颁发者/使用者)
     *
     * @return 命名对象
     */
    private X500Name defaultName()
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        // 国家代码
        builder.addRDN(BCStyle.C, "CN");
        // 组织
        builder.addRDN(BCStyle.O, "BiuQu");
        // 省份
        builder.addRDN(BCStyle.ST, "GD");
        // 地区
        builder.addRDN(BCStyle.L, "ShenZhen");
        return builder.build();
    }

    private X509CertificateBuilder(KeyPair keyPair)
    {
        if (null == keyPair)
        {
            throw new EncryptionException("unknown key pair to certificate.");
        }
        this.keyPair = keyPair;
    }

    /**
     * SM2签名算法
     */
    private static final String SM2_SIGNATURE_ALG = "SM3WithSM2";

    /**
     * RSA签名算法
     */
    private static final String RSA_SIGNATURE_ALG = "SHA512WithRSA";

    /**
     * 证书有效起始时间
     */
    private long startTime;

    /**
     * 证书过期时间
     */
    private long expireTime;

    /**
     * 签名算法
     */
    private String signatureAlg;

    /**
     * 证书颁发机构
     */
    private X500Name issuer;

    /**
     * 证书使用机构
     */
    private X500Name subject;

    /**
     * 密钥对
     */
    private final KeyPair keyPair;
}
