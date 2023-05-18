package com.biuqu.encryption.factory;

import com.biuqu.encryption.BaseMultiSignature;
import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.Hash;
import com.biuqu.encryption.impl.*;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class EncryptionFacadeTest
{
    @Test
    public void hsmTest()
    {
        String text = "It's a very very good day...";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        int i = 0;
        byte[] idBytes = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

        //test1:gmHsm hash
        GmHsmEncryption gmHsm = EncryptionFactory.GmIntegrityHsm.createAlgorithm();
        KeyPair hsmKey = gmHsm.createKey(idBytes);

        byte[] encBytes = gmHsm.sign(data, hsmKey.getPrivate().getEncoded());
        Assert.assertTrue(gmHsm.verify(data, hsmKey.getPublic().getEncoded(), encBytes));
        System.out.println("Test[" + (++i) + "]:" + gmHsm + "encBytes=" + Hex.toHexString(encBytes));

        UsHsmEncryption usHsm = EncryptionFactory.UsIntegrityHsm.createAlgorithm();
        KeyPair hsmKey2 = usHsm.createKey(idBytes);

        byte[] encBytes2 = usHsm.sign(data, hsmKey2.getPrivate().getEncoded());
        Assert.assertTrue(usHsm.verify(data, hsmKey2.getPublic().getEncoded(), encBytes2));
        System.out.println("Test[" + (++i) + "]:" + usHsm + "encBytes=" + Hex.toHexString(encBytes2));
    }

    /**
     * 列举了11种 SHA Hash使用样例：
     * SM3/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SHA3-224/SHA3-256/SHA3-384/SHA3-512/MD5
     */
    @Test
    public void hashTest()
    {
        String text = "It's a very very good day...";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        int i = 0;

        //test1:SM3 hash
        Hash sm3 = EncryptionFactory.SM3.createAlgorithm();
        byte[] sm3HashBytes = sm3.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sm3 + "sm3=" + Hex.toHexString(sm3HashBytes));
        Assert.assertTrue(null != sm3HashBytes);

        //test2:Default SHA hash
        Hash defaultSha = EncryptionFactory.SHAHash.createAlgorithm();
        byte[] hashBytes = defaultSha.digest(data);
        System.out.println("Test[" + (++i) + "]:" + defaultSha + "hashBytes=" + Hex.toHexString(hashBytes));
        Assert.assertTrue(null != hashBytes);

        //test3:SHA512 hash
        Hash sha512 = EncryptionFactory.SHA512.createAlgorithm();
        byte[] sha512Bytes = sha512.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha512 + "hashBytes=" + Hex.toHexString(sha512Bytes));
        Assert.assertTrue(null != sha512Bytes);

        //test4:SHA256 hash
        Hash sha256 = EncryptionFactory.SHA256.createAlgorithm();
        byte[] sha256Bytes = sha256.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha256 + "hashBytes=" + Hex.toHexString(sha256Bytes));
        Assert.assertTrue(null != sha256Bytes);

        //test5:SHA1 hash
        Hash sha1 = EncryptionFactory.SHA1.createAlgorithm();
        byte[] sha1Bytes = sha1.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha1 + "hashBytes=" + Hex.toHexString(sha1Bytes));
        Assert.assertTrue(null != sha1Bytes);

        //test6:MD5 hash
        Hash md5 = EncryptionFactory.MD5.createAlgorithm();
        byte[] md5Bytes = md5.digest(data);
        System.out.println("Test[" + (++i) + "]:" + md5 + "hashBytes=" + Hex.toHexString(md5Bytes));
        Assert.assertTrue(null != md5Bytes);

        //test7:SHA-224 hash
        ShaHash sha224 = EncryptionFactory.SHAHash.createAlgorithm();
        sha224.setAlgorithm("SHA-224");
        byte[] sha224Bytes = sha224.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha224 + "hashBytes=" + Hex.toHexString(sha224Bytes));
        Assert.assertTrue(null != sha224Bytes);

        //test8:SHA-384 hash
        ShaHash sha384 = EncryptionFactory.SHAHash.createAlgorithm();
        sha384.setAlgorithm("SHA-384");
        byte[] sha384Bytes = sha384.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha384 + "hashBytes=" + Hex.toHexString(sha384Bytes));
        Assert.assertTrue(null != sha384Bytes);

        //test9:SHA3-224 hash
        ShaHash sha3224 = EncryptionFactory.SHAHash.createAlgorithm();
        sha3224.setAlgorithm("SHA3-224");
        byte[] sha3224Bytes = sha3224.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha3224 + "hashBytes=" + Hex.toHexString(sha3224Bytes));
        Assert.assertTrue(null != sha3224Bytes);

        //test10:SHA3-256 hash
        ShaHash sha3256 = EncryptionFactory.SHAHash.createAlgorithm();
        sha3256.setAlgorithm("SHA3-256");
        byte[] sha3256Bytes = sha3256.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha3256 + "hashBytes=" + Hex.toHexString(sha3256Bytes));
        Assert.assertTrue(null != sha3256Bytes);

        //test11:SHA3-384 hash
        ShaHash sha3384 = EncryptionFactory.SHAHash.createAlgorithm();
        sha3384.setAlgorithm("SHA3-384");
        byte[] sha3384Bytes = sha3384.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha3384 + "hashBytes=" + Hex.toHexString(sha3384Bytes));
        Assert.assertTrue(null != sha3384Bytes);

        //test12:SHA3-512 hash
        ShaHash sha3512 = EncryptionFactory.SHAHash.createAlgorithm();
        sha3512.setAlgorithm("SHA3-512");
        byte[] sha3512Bytes = sha3512.digest(data);
        System.out.println("Test[" + (++i) + "]:" + sha3512 + "hashBytes=" + Hex.toHexString(sha3512Bytes));
        Assert.assertTrue(null != sha3512Bytes);
    }

    /**
     * 列举了7种 Hmac SHA Hash使用样例：
     * HmacSHA1/HmacSHA224/HmacSHA256/HmacSHA384/HmacSHA512/HmacMD5/HmacSM3
     */
    @Test
    public void hmacHashTest()
    {
        String text = "It's a very very good day...";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = "PwdAbc".getBytes(StandardCharsets.UTF_8);
        int i = 0;

        //test1:HmacSHA(HmacSHA256) default hash
        ShaHmacKeyHash hmacSha = EncryptionFactory.HmacSHA.createAlgorithm();
        byte[] hmacShaBytes = hmacSha.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha + "hashBytes=" + Hex.toHexString(hmacShaBytes));
        Assert.assertTrue(null != hmacShaBytes);

        //test2:HmacSHA256 default hash
        ShaHmacKeyHash hmacSha256 = EncryptionFactory.HmacSHA256.createAlgorithm();
        byte[] hmacSha256Bytes = hmacSha256.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha256 + "hashBytes=" + Hex.toHexString(hmacSha256Bytes));
        Assert.assertTrue(null != hmacSha256Bytes);

        //test3:HmacSHA1 default hash
        ShaHmacKeyHash hmacSha1 = EncryptionFactory.HmacSHA.createAlgorithm();
        hmacSha1.setAlgorithm("HmacSHA1");
        byte[] hmacSha1Bytes = hmacSha1.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha1 + "hashBytes=" + Hex.toHexString(hmacSha1Bytes));
        Assert.assertTrue(null != hmacSha1Bytes);

        //test4:HmacSHA1 default hash
        ShaHmacKeyHash hmacSha224 = EncryptionFactory.HmacSHA.createAlgorithm();
        hmacSha224.setAlgorithm("HmacSHA224");
        byte[] hmacSha224Bytes = hmacSha224.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha224 + "hashBytes=" + Hex.toHexString(hmacSha224Bytes));
        Assert.assertTrue(null != hmacSha224Bytes);

        //test5:HmacSHA1 default hash
        ShaHmacKeyHash hmacSha384 = EncryptionFactory.HmacSHA.createAlgorithm();
        hmacSha384.setAlgorithm("HmacSHA384");
        byte[] hmacSha384Bytes = hmacSha384.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha384 + "hashBytes=" + Hex.toHexString(hmacSha384Bytes));
        Assert.assertTrue(null != hmacSha384Bytes);

        //test6:Hmac512 default hash
        ShaHmacKeyHash hmacSha512 = EncryptionFactory.HmacSHA512.createAlgorithm();
        byte[] hmacSha512Bytes = hmacSha512.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSha512 + "hashBytes=" + Hex.toHexString(hmacSha512Bytes));
        Assert.assertTrue(null != hmacSha512Bytes);

        //test7:HmacMD5 default hash
        ShaHmacKeyHash hmacMd5 = EncryptionFactory.HmacSHA.createAlgorithm();
        hmacMd5.setAlgorithm("HmacMD5");
        byte[] hmacMd5Bytes = hmacMd5.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacMd5 + "hashBytes=" + Hex.toHexString(hmacMd5Bytes));
        Assert.assertTrue(null != hmacMd5Bytes);

        //test8:HmacSM3 default hash
        Sm3HmacKeyHash hmacSm3 = EncryptionFactory.SM3Hmac.createAlgorithm();
        byte[] hmacSm3Bytes = hmacSm3.digest(data, key);
        System.out.println("Test[" + (++i) + "]:" + hmacSm3 + "hashBytes=" + Hex.toHexString(hmacSm3Bytes));
        Assert.assertTrue(null != hmacSm3Bytes);
    }

    /**
     * 1.列举了秘钥长度为128/192/256的AES加密算法使用样例：AES256/AES192/AES128
     * 2.以AES256为例，列举了不同的填充模式
     * 加密算法的PADDING_MODE(加密算法模式)由3部分构成：(如：AES/ECB/PKCS5Padding)
     * 1.第一部分为加密算法名称，如:AES；
     * 2.第二部分为工作模式，如:ECB/CBC/CFB/OFB/CTR/PCBC；
     * 3.第三部分为填充模式，如:NoPadding/PKCS5Padding/PKCS7Padding/ISO10126Padding/ISO7816-4Padding/ZeroBytePadding/X923Padding/PKCS1Padding/TBCPadding(Trailing-Bit-Compliment）
     */
    @Test
    public void aesEncryptTest() throws NoSuchAlgorithmException
    {
        String text = "It's a very very good day...";
        AtomicInteger i = new AtomicInteger(0);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);

        //test1:AES256 encrypt and decrypt
        AesEncryption aes = EncryptionFactory.AES.createAlgorithm();
        testSingleEncryptionLen(aes, aes.getEncryptLen(), saltBytes, text, i);

        //test2:AES192 encrypt and decrypt
        testSingleEncryptionLen(aes, 192, saltBytes, text, i);

        //test3:AES128 encrypt and decrypt
        testSingleEncryptionLen(aes, 128, saltBytes, text, i);

        //test4:AES256 with salt encrypt and decrypt
        //复原加密长度
        aes.setEncryptLen(256);
        testSingleEncryption(aes, aes.getPaddingMode(), saltBytes, text, i);

        //test5:AES256 with salt with AES/ECB/PKCS5Padding encrypt and decrypt
        testSingleEncryption(aes, "AES/ECB/PKCS5Padding", saltBytes, text, i);

        //test6:AES256 with salt with AES/CTR/NoPadding encrypt and decrypt
        testSingleEncryption(aes, "AES/CTR/NoPadding", saltBytes, text, i);
    }

    @Test
    public void des3EncryptTest() throws NoSuchAlgorithmException
    {
        String text = "It's a very very good day...";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        AtomicInteger i = new AtomicInteger(0);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] saltBytes = new byte[24];
        random.nextBytes(saltBytes);

        //test1:3DES encrypt and decrypt
        Des3Encryption encryption = EncryptionFactory.DES3.createAlgorithm();
        byte[] key = encryption.createKey(saltBytes).getEncoded();
        //盐值和秘钥相同
        System.out.println("saltBytes=" + Hex.toHexString(saltBytes) + ",keys=" + Hex.toHexString(key));

        byte[] encBytes = encryption.encrypt(data, key, null);
        Assert.assertTrue(null != encBytes);
        byte[] aesDecBytes = encryption.decrypt(encBytes, key, null);
        Assert.assertTrue(text.equals(new String(aesDecBytes)));
        System.out.println(
            "Test[" + i.incrementAndGet() + "]:" + encryption + "key=" + Hex.toHexString(key) + ",encBytes="
                + Hex.toHexString(encBytes));
    }

    @Test
    public void sm4EncryptTest() throws NoSuchAlgorithmException
    {
        String text = "It's a very very good day...";
        AtomicInteger i = new AtomicInteger(0);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);

        //test1:SM4 encrypt and decrypt
        Sm4Encryption encryption = EncryptionFactory.SM4.createAlgorithm();
        testSingleEncryptionLen(encryption, 0, saltBytes, text, i);

        //test2:SM4 with salt encrypt and decrypt
        testSingleEncryption(encryption, "SM4/CBC/PKCS5Padding", saltBytes, text, i);

        //test3:SM4 with salt with SM4/ECB/PKCS5Padding encrypt and decrypt
        testSingleEncryption(encryption, "SM4/ECB/PKCS5Padding", saltBytes, text, i);

        //test4:SM4 with salt with SM4/CTR/NoPadding encrypt and decrypt
        testSingleEncryption(encryption, "SM4/CTR/NoPadding", saltBytes, text, i);
    }

    /**
     * 1.列举了秘钥长度为1024/2048的RSA加密算法，使用样例：RSA/ECB/PKCS1Padding
     * 2.以RSA2048为例，列举了不同的填充模式
     * <p>
     * 加密算法的PADDING_MODE(加密算法模式)由3部分构成：(如：RSA/ECB/PKCS1Padding)
     * 1.第一部分为加密算法名称，如:RSA；
     * 2.第二部分为工作模式，如:ECB/NONE；
     * 3.第三部分为填充模式，如:NoPadding/PKCS1Padding
     */
    @Test
    public void rsaEncryptTest()
    {
        String text = "It's a very very good day...";
        byte[] initKey = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        AtomicInteger i = new AtomicInteger(0);

        //default RSA2048 encrypt/decrypt,signature and verify
        RsaEncryption rsa = EncryptionFactory.RSA.createAlgorithm();
        KeyPair keyPair = rsa.createKey(initKey);
        testSingleSignature(rsa, keyPair, text, i);

        //RSA1024 encrypt/decrypt,signature and verify
        RsaEncryption rsa1024 = EncryptionFactory.RSA.createAlgorithm();
        rsa1024.setEncryptLen(1024);
        //也可以重新设置签名算法
        rsa1024.setSignatureAlg("SHA256WithRSA");
        KeyPair keyPair1024 = rsa1024.createKey(initKey);
        testSingleSignature(rsa1024, keyPair1024, text, i);
    }

    /**
     * 1.列举了国密非对称加密算法SM2,与RSA算法功能相近
     */
    @Test
    public void sm2EncryptTest()
    {
        String text = "It's a very very good day...";
        byte[] initKey = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        AtomicInteger i = new AtomicInteger(0);

        //SM2 encrypt/decrypt,signature and verify
        Sm2Encryption encryption = EncryptionFactory.SM2.createAlgorithm();
        KeyPair keyPair = encryption.createKey(initKey);
        testSingleSignature(encryption, keyPair, text, i);
    }

    /**
     * 多秘钥的加密算法(PGP)
     */
    @Test
    public void multiEncryptionTest() throws IOException
    {
        PgpEncryption encryption = EncryptionFactory.PGP.createAlgorithm();
        //必须要设置秘钥的密码
        encryption.setPwd("PwdAbc".toCharArray());
        encryption.setKid("bqTestUser001");
        encryption.setExpire(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365));
        byte[] initKey = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

        PGPSecretKey secretKey1 = encryption.createKey(initKey);
        byte[] pri1 = secretKey1.getEncoded();
        byte[] pub1 = secretKey1.getPublicKey().getEncoded();

        PGPSecretKey secretKey2 = encryption.createKey(UUID.randomUUID().toString().getBytes());
        byte[] pri2 = secretKey2.getEncoded();
        byte[] pub2 = secretKey2.getPublicKey().getEncoded();

        String text = "It's a very very good day...";
        byte[] encBytes = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), pri1, pub2);
        System.out.println("encrypt message:\n" + new String(encBytes, StandardCharsets.UTF_8));
        byte[] decBytes = encryption.decrypt(encBytes, pub1, pri2);
        Assert.assertTrue(text.equals(new String(decBytes)));
        System.out.println("Test[1]:" + encryption + "encBytes=" + Hex.toHexString(encBytes));
    }

    /**
     * 多秘钥的加密+签名算法(GM/US)
     */
    @Test
    public void multiSignatureTest()
    {
        byte[] initKey1 = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] initKey2 = UUID.randomUUID().toString().getBytes();
        AtomicInteger i = new AtomicInteger(0);

        BaseMultiSignature encryption1 = EncryptionFactory.US.createAlgorithm();
        testMultiSignature(encryption1, initKey1, initKey2, i);

        BaseMultiSignature encryption2 = EncryptionFactory.GM.createAlgorithm();
        testMultiSignature(encryption2, initKey1, initKey2, i);
    }

    private void testMultiSignature(BaseMultiSignature encryption, byte[] initKey1, byte[] initKey2, AtomicInteger i)
    {
        KeyPair keyPair1 = encryption.createKey(initKey1);
        byte[] pri1 = keyPair1.getPrivate().getEncoded();
        byte[] pub1 = keyPair1.getPublic().getEncoded();

        KeyPair keyPair2 = encryption.createKey(initKey2);
        byte[] pri2 = keyPair2.getPrivate().getEncoded();
        byte[] pub2 = keyPair2.getPublic().getEncoded();

        String text = "It's a very very good day...";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        //Test1: multi key encrypt and decrypt.
        byte[] encBytes = encryption.encrypt(data, pri1, pub2);
        byte[] decBytes = encryption.decrypt(encBytes, pub1, pri2);
        Assert.assertTrue(text.equals(new String(decBytes)));
        System.out.println("Test[" + i.incrementAndGet() + "]:" + encryption + "encBytes=" + Hex.toHexString(encBytes));

        //Test2: multi key sign and decrypt.
        byte[] signBytes = encryption.sign(data, pri1, pub2);
        boolean verifyResult = encryption.verify(signBytes, pub1, pri2);
        Assert.assertTrue(verifyResult);
        System.out.println(
            "Test[" + i.incrementAndGet() + "]:" + encryption + "signBytes=" + Hex.toHexString(encBytes));
    }

    private void testSingleEncryptionLen(BaseSingleEncryption encryption, int encLen, byte[] salt, String text,
        AtomicInteger i)
    {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        encryption.setEncryptLen(encLen);
        byte[] key = encryption.createKey(salt).getEncoded();
        byte[] encBytes = encryption.encrypt(data, key, null);
        Assert.assertTrue(null != encBytes);
        byte[] aesDecBytes = encryption.decrypt(encBytes, key, null);
        Assert.assertTrue(text.equals(new String(aesDecBytes)));
        System.out.println(
            "Test[" + i.incrementAndGet() + "]:" + encryption + "key=" + Hex.toHexString(key) + ",encBytes="
                + Hex.toHexString(encBytes));
    }

    private void testSingleEncryption(BaseSingleEncryption encryption, String padding, byte[] salt, String text,
        AtomicInteger i)
    {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        //test i:AES256 with salt with padding encrypt and decrypt
        encryption.setPaddingMode(padding);
        byte[] key = encryption.createKey(salt).getEncoded();
        byte[] encBytes = encryption.encrypt(data, key, salt);
        Assert.assertTrue(null != encBytes);
        byte[] decBytes = encryption.decrypt(encBytes, key, salt);
        Assert.assertTrue(text.equals(new String(decBytes)));
        System.out.println("Test[" + i.incrementAndGet() + "]:" + encryption + "key=" + Hex.toHexString(key) + ",salt="
            + Hex.toHexString(salt) + ",encBytes=" + Hex.toHexString(encBytes));
    }

    private void testSingleSignature(BaseSingleSignature signature, KeyPair keyPair, String text, AtomicInteger i)
    {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        byte[] pri = keyPair.getPrivate().getEncoded();
        byte[] pub = keyPair.getPublic().getEncoded();
        System.out.println("pri key len=" + pri.length + ",pub key len=" + pub.length);
        //test1:RSA2048/RSA1024 private key encrypted
        byte[] encBytes1 = signature.encrypt(data, pub, null);
        Assert.assertTrue(null != encBytes1);
        byte[] decBytes1 = signature.decrypt(encBytes1, pri, null);
        Assert.assertTrue(text.equals(new String(decBytes1)));
        System.out.println(
            "Test[" + i.incrementAndGet() + "]:" + signature + "encBytes1=" + Hex.toHexString(encBytes1));

        //国密sm2不支持私钥加密，公钥解密(该场景也)
        if (signature instanceof RsaEncryption)
        {
            //test2:RSA2048/RSA1024 public key encrypted
            byte[] encBytes2 = signature.encrypt(data, pri, null);
            Assert.assertTrue(null != encBytes2);
            byte[] decBytes2 = signature.decrypt(encBytes2, pub, null);
            Assert.assertTrue(text.equals(new String(decBytes2)));
            System.out.println(
                "Test[" + i.incrementAndGet() + "]:" + signature + "encBytes2=" + Hex.toHexString(encBytes2));
        }

        //test3:RSA2048/RSA1024 private key signature
        byte[] signBytes2 = signature.sign(data, pri);
        Assert.assertTrue(null != signBytes2);
        boolean verify2 = signature.verify(data, pub, signBytes2);
        Assert.assertTrue(verify2);
        System.out.println(
            "Test[" + i.incrementAndGet() + "]:" + signature + "signBytes2=" + Hex.toHexString(signBytes2));
    }
}