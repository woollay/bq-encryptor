package com.biuqu.encryption.converter.impl;

import com.biuqu.encryption.converter.CertConverter;
import com.biuqu.encryption.model.Cert;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class X509CertConverterTest
{

    @Test
    public void toCert() throws IOException
    {
        String path = basePath + "cert/baidu.cer";
        System.out.println("cert text=" + IOUtils.toString(new FileInputStream(path), StandardCharsets.UTF_8));

        InputStream certIn = new FileInputStream(path);
        CertConverter certConverter = new X509CertConverter();
        Cert cert = certConverter.toCert(certIn);

        System.out.println("cert==" + cert);
    }

    @Test
    public void toCert2() throws IOException
    {
        String path = basePath + "cert/43989a5c-dd63-4ce9-abfa-a0ec7aeaf838.cer";
        System.out.println("cert text=" + IOUtils.toString(new FileInputStream(path), StandardCharsets.UTF_8));

        InputStream certIn = new FileInputStream(path);
        CertConverter certConverter = new X509CertConverter();
        Cert cert = certConverter.toCert(certIn);

        System.out.println("cert==" + cert);
    }

    @Test
    public void testToCert()
    {
    }

    @Test
    public void toCertificate()
    {
    }

    private static String basePath = X509CertConverterTest.class.getResource("/").getPath();
}