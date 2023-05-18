package com.biuqu.encryption.converter.pgp;

import com.biuqu.encryption.converter.impl.PgpKeyConverter;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class PgpKeyConverterTest
{
    @Test
    public void getSecretKey() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String priPath1 = pgpPath + "pri-test-1.asc";
        showSecretKey(priPath1);

        String pubPath1 = pgpPath + "pub-test-1.asc";
        showPublicKey(pubPath1);
    }

    @Test
    public void testGetSecretKey() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String priPath1 = pgpPath + "pri-test-1.asc";
        showSecretKey(new FileInputStream(priPath1), priPath1);

        String pubPath1 = pgpPath + "pub-test-1.asc";
        showPublicKey(new FileInputStream(pubPath1), pubPath1);
    }

    @Test
    public void testGetSecretKey1() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String priPath1 = pgpPath + "pri-test-1.asc";
        String priText1 = IOUtils.toString(new FileInputStream(priPath1), StandardCharsets.UTF_8);
        System.out.println("priText1=" + priText1);

        PGPSecretKey secretKey = PgpKeyConverter.getSecretKey(priText1.getBytes(StandardCharsets.UTF_8));
        System.out.println("secret path=" + priPath1 + ",text=" + priText1 + ",key=" + secretKey.getEncoded());
    }

    @Test
    public void getPrivateKey() throws IOException
    {
        String pwd = "BiuQu";
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        String priPath1 = pgpPath + "pri-test-1.asc";
        String priText1 = IOUtils.toString(new FileInputStream(priPath1), StandardCharsets.UTF_8);
        PGPSecretKey secretKey = PgpKeyConverter.getSecretKey(priPath1);

        PGPPrivateKey privateKey = PgpKeyConverter.getPrivateKey(secretKey, pwd.toCharArray());
        System.out.println("secret path=" + priPath1 + ",text=" + priText1 + ",private key=" + privateKey);
    }

    @Test
    public void getPublicKey() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String pubPath1 = pgpPath + "pub-test-1.asc";
        showPublicKey(pubPath1);
    }

    @Test
    public void testGetPublicKey() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String pubPath1 = pgpPath + "pub-test-1.asc";
        showPublicKey(new FileInputStream(pubPath1), pubPath1);
    }

    @Test
    public void testGetPublicKey1() throws IOException
    {
        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        System.out.println("pgpPath=" + pgpPath);

        String pubPath1 = pgpPath + "pub-test-1.asc";
        String pubText1 = IOUtils.toString(new FileInputStream(pubPath1), StandardCharsets.UTF_8);
        System.out.println("pubText1=" + pubText1);

        PGPPublicKey publicKey = PgpKeyConverter.getPublicKey(pubText1.getBytes(StandardCharsets.UTF_8));
        System.out.println("secret path=" + pubPath1 + ",text=" + pubText1 + ",key=" + publicKey.getEncoded());
    }

    private void showSecretKey(String path) throws IOException
    {
        showSecretKey(new FileInputStream(path), path);
    }

    private void showSecretKey(InputStream in, String path) throws IOException
    {
        String priText = IOUtils.toString(in, StandardCharsets.UTF_8);
        PGPSecretKey secretKey = PgpKeyConverter.getSecretKey(path);
        System.out.println("secret path=" + path + ",text=" + priText + ",key=" + secretKey.getEncoded());
    }

    private void showPublicKey(String path) throws IOException
    {
        showPublicKey(new FileInputStream(path), path);
    }

    private void showPublicKey(InputStream in, String path) throws IOException
    {
        String priText = IOUtils.toString(in, StandardCharsets.UTF_8);
        PGPPublicKey publicKey = PgpKeyConverter.getPublicKey(path);
        System.out.println("public path=" + path + ",text=" + priText + ",key=" + publicKey.getEncoded());
    }
}