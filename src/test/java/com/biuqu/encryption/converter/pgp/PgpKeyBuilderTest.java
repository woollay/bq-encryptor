package com.biuqu.encryption.converter.pgp;

import com.biuqu.encryption.converter.PgpKeyBuilder;
import com.biuqu.encryption.converter.impl.PgpKeyConverter;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class PgpKeyBuilderTest
{

    @Test
    public void buildPgpKeyGen() throws PGPException, IOException
    {
        String pwd = "BiuQu";
        String kid = "BiuQu-testUser-001";
        long timestamp = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365);
        PGPKeyRingGenerator ringGenerator = PgpKeyBuilder.buildPgpKeyGen(pwd.toCharArray(), kid, timestamp);
        PGPSecretKeyRing secretKeyRing = ringGenerator.generateSecretKeyRing();
        System.out.println("secretKeyRing=" + Base64.toBase64String(secretKeyRing.getEncoded()));

        PGPSecretKey secretKey = secretKeyRing.getSecretKey();
        System.out.println("secretKey=" + Base64.toBase64String(secretKey.getEncoded()));

        PGPPublicKey publicKey = secretKey.getPublicKey();
        System.out.println("publicKey=" + Base64.toBase64String(publicKey.getEncoded()));

        PGPPrivateKey privateKey = PgpKeyConverter.getPrivateKey(secretKey, pwd.toCharArray());
        System.out.println("privateKey=" + Base64.toBase64String(privateKey.getPrivateKeyDataPacket().getEncoded()));
    }

    @Test
    public void savePgpKeyFile() throws PGPException
    {
        String pwd = "BiuQu";
        String kid = "BiuQu-testUser-001";
        long timestamp = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365);
        PGPKeyRingGenerator ringGenerator = PgpKeyBuilder.buildPgpKeyGen(pwd.toCharArray(), kid, timestamp);
        PGPSecretKeyRing secretKeyRing = ringGenerator.generateSecretKeyRing();
        String fileName = UUID.randomUUID().toString();
        String priPath = PgpKeyBuilderTest.class.getResource("/").getPath() + "pgp/pri-" + fileName + ".asc";
        System.out.println("priPath=" + priPath);
        PgpKeyBuilder.savePgpKeyFile(secretKeyRing, priPath);

        PGPPublicKeyRing publicKeyRing = ringGenerator.generatePublicKeyRing();
        String pubPath = PgpKeyBuilderTest.class.getResource("/").getPath() + "pgp/pub-" + fileName + ".asc";
        System.out.println("pubPath=" + pubPath);
        PgpKeyBuilder.savePgpKeyFile(publicKeyRing, pubPath);
    }
}