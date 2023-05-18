package com.biuqu.encryption.converter.impl;

import com.biuqu.encryption.converter.CertConverter;
import com.biuqu.encryption.converter.X509CertificateBuilder;
import com.biuqu.encryption.exception.EncryptionException;
import com.biuqu.encryption.model.Cert;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * X509Certificate证书转换实现类
 *
 * @author BiuQu
 * @date 2023/01/02 10:34
 **/
public class X509CertConverter implements CertConverter
{
    @Override
    public X509Certificate genCertificate(X509CertificateBuilder certBuilder)
    {
        return certBuilder.build();
    }

    @Override
    public Cert toCert(String data)
    {
        if (null == data)
        {
            return null;
        }

        String newData = data.replaceAll(INVALID_CHAR_REGEX, SPACE);
        byte[] bytes = Base64.decode(newData);
        return toCert(new ByteArrayInputStream(bytes));
    }

    @Override
    public Cert toCert(InputStream in)
    {
        X509Certificate certificate = toCertificate(in);
        if (null != certificate)
        {
            Cert cert = new Cert();
            cert.setVersion(certificate.getVersion() + SPACE);
            cert.setAlgorithm(certificate.getSigAlgOID());
            cert.setIssuer(certificate.getIssuerDN().toString());
            cert.setSubject(certificate.getSubjectDN().toString());
            cert.setBeginTime(certificate.getNotBefore().getTime());
            cert.setEndTime(certificate.getNotAfter().getTime());
            cert.setSignature(new String(Hex.encode(certificate.getSignature())));
            cert.setSerialNumber(Hex.toHexString(certificate.getSerialNumber().toByteArray()));
            try
            {
                cert.setKey(certificate.getEncoded());
            }
            catch (Exception e)
            {
                throw new EncryptionException("parse cert error.", e);
            }
            return cert;
        }
        return null;
    }

    @Override
    public X509Certificate toCertificate(InputStream in)
    {
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance(CERT_ALG, BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate)cf.generateCertificate(in);
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse cert error.", e);
        }
        finally
        {
            IOUtils.closeQuietly(in);
        }
    }

    @Override
    public void toCertificate(X509Certificate certificate, String path)
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
            writer.writeObject(new JcaMiscPEMGenerator(certificate));
        }
        catch (Exception e)
        {
            throw new EncryptionException("parse cert error.", e);
        }
        finally
        {
            IOUtils.closeQuietly(writer);
        }
    }

    static
    {
        //引入BouncyCastle算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 不能包含的特殊字符
     */
    private static final String INVALID_CHAR_REGEX = "\\s*|\t|r|\n|\r";

    /**
     * 空格
     */
    private static final String SPACE = "";

    /**
     * 证书协议
     */
    private static final String CERT_ALG = "X.509";
}
