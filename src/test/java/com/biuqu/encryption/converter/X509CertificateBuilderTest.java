package com.biuqu.encryption.converter;

import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.converter.impl.X509CertConverter;
import com.biuqu.encryption.impl.RsaEncryption;
import com.biuqu.encryption.impl.Sm2Encryption;
import com.biuqu.encryption.model.Cert;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.X509Certificate;
import java.util.UUID;

public class X509CertificateBuilderTest
{

    @Test
    public void build() throws FileNotFoundException
    {
        BaseSingleSignature[] pairs = {new RsaEncryption(), new Sm2Encryption()};
        for (BaseSingleSignature pair : pairs)
        {
            X509CertificateBuilder builder = X509CertificateBuilder.builder(pair.createKey(null));
            builder.appendStartTime(System.currentTimeMillis() - 7 * 24 * 3600 * 1000);
            builder.appendExpireTime(System.currentTimeMillis() + 7 * 24 * 3600 * 1000);
            X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            issuerBuilder.addRDN(BCStyle.C, "CN");
            issuerBuilder.addRDN(BCStyle.O, "BiuQu");
            issuerBuilder.addRDN(BCStyle.ST, "GD");
            issuerBuilder.addRDN(BCStyle.L, "ShenZhen");
            builder.appendIssuer(issuerBuilder.build());

            X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            subjectBuilder.addRDN(BCStyle.C, "CN");
            subjectBuilder.addRDN(BCStyle.O, "YouWan");
            subjectBuilder.addRDN(BCStyle.ST, "GD");
            subjectBuilder.addRDN(BCStyle.L, "ShenZhen");
            builder.appendIssuer(subjectBuilder.build());

            X509Certificate x509Certificate = builder.build();

            CertConverter converter = new X509CertConverter();
            String path = CertConverter.class.getResource("/").getPath() + "cert/" + UUID.randomUUID() + ".cer";
            System.out.println("path=" + path);
            converter.toCertificate(x509Certificate, path);

            Cert cert = converter.toCert(new FileInputStream(path));
            System.out.println("cert=" + cert);
        }
    }

    @Test
    public void build2() throws FileNotFoundException
    {
        BaseSingleSignature[] pairs = {new RsaEncryption(), new Sm2Encryption()};
        int i = 0;
        for (BaseSingleSignature pair : pairs)
        {
            i++;
            X509CertificateBuilder builder = X509CertificateBuilder.builder(pair.createKey(null));
            X509Certificate x509Certificate = builder.build();

            CertConverter converter = new X509CertConverter();
            String path = CertConverter.class.getResource("/").getPath() + "cert/" + UUID.randomUUID() + ".cer";
            System.out.println(i + "-path=" + path);
            converter.toCertificate(x509Certificate, path);

            Cert cert = converter.toCert(new FileInputStream(path));
            System.out.println(i + "-cert=" + cert);
        }
    }
}