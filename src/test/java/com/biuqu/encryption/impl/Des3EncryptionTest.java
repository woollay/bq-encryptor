package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.BaseSingleEncryptionTest;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Des3EncryptionTest extends BaseSingleEncryptionTest
{
    @Test
    public void createKey() throws NoSuchAlgorithmException
    {
        BaseSingleEncryption encryption = new Des3Encryption();
        try
        {
            //3DES不允许低于24byte的秘钥,因为无法解析出3个8byte的DES秘钥
            super.createKey(encryption, 192);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void testGetKey() throws NoSuchAlgorithmException
    {
        BaseSingleEncryption encryption = new Des3Encryption();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] keyBytes = new byte[24];
        random.nextBytes(keyBytes);

        //test1: 任意24byte的内容均可以作为3DES的秘钥(而AES/SM4仅支持自己生成的秘钥转换成秘钥对象)
        SecretKey secretKey = encryption.toKey(keyBytes);
        System.out.println("init key=" + Hex.toHexString(keyBytes));
        System.out.println("3des key=" + Hex.toHexString(secretKey.getEncoded()));
        Assert.assertTrue(secretKey.getEncoded().length == 24);

        //test2:秘钥对象的二进制和原始秘钥的二进制并不相同
        Assert.assertFalse(Hex.toHexString(secretKey.getEncoded()).equals(Hex.toHexString(keyBytes)));

        byte[] keyBytes2 = new byte[25];
        random.nextBytes(keyBytes2);
        //test3: 任意大于24byte的内容均可以作为3DES的秘钥，而且只会截取前24byte
        SecretKey secretKey2 = encryption.toKey(keyBytes2);
        System.out.println("init key2=" + Hex.toHexString(keyBytes2));
        System.out.println("3des key2=" + Hex.toHexString(secretKey2.getEncoded()));
        Assert.assertTrue(secretKey2.getEncoded().length == 24);
        byte[] subBytes2 = ArrayUtils.subarray(keyBytes2, 0, 24);
        System.out.println("3des sub key2=" + Hex.toHexString(subBytes2));
        Assert.assertFalse(Hex.toHexString(secretKey2.getEncoded()).equals(Hex.toHexString(subBytes2)));
    }

    @Test
    public void testEncryptLen() throws NoSuchAlgorithmException
    {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] keyBytes = new byte[24];
        random.nextBytes(keyBytes);

        BaseSingleEncryption encryption = new Des3Encryption();
        super.encrypt(encryption, 192, 8);
    }

    @Test
    public void testEncrypt()
    {
        int[] keyLenList = {192};
        String[] modes = {"ECB", "CBC", "CTR", "CFB"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        //test1:分段(分组)加密明文长度为n的明文数据，密文长度为(n/encGroupLen+1)*encGroupLen的倍数(除法取整)
        for (int len : keyLenList)
        {
            BaseSingleEncryption encryption = new Des3Encryption();
            super.doCipher(encryption, len, 8, paddings, modes);
        }

        BaseSingleEncryption encryption = new Des3Encryption();
        //test2:超长的秘钥和正常长度的秘钥加密效果是一样的
        byte[] keyBytes2 = RandomUtils.nextBytes(25);
        byte[] salt = RandomUtils.nextBytes(16);
        String text = "It's a very very good day...";
        System.out.println("init key=" + Hex.toHexString(keyBytes2));
        byte[] encBytes2 = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), keyBytes2, salt);
        System.out.println("3des encBytes=" + Hex.toHexString(encBytes2));
        Assert.assertTrue(encBytes2.length == 32);
        byte[] keyBytes3 = ArrayUtils.subarray(keyBytes2, 0, 24);
        byte[] encBytes3 = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), keyBytes3, salt);
        Assert.assertTrue(encBytes2.length == 32);
        Assert.assertArrayEquals(encBytes3, encBytes2);
    }
}