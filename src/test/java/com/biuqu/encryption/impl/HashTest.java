package com.biuqu.encryption.impl;

import com.biuqu.encryption.Hash;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class HashTest
{
    @Test
    public void hashTest()
    {
        String text = "TestAbc123~!@#$%^&*(3";
        Hash shaHash = new ShaHash();
        byte[] sha512 = shaHash.digest(text.getBytes(StandardCharsets.UTF_8));
        System.out.println(((ShaHash)shaHash).getAlgorithm() + "==" + Hex.toHexString(sha512));

        ShaHash otherHash = new ShaHash();
        otherHash.setAlgorithm("SHA-256");
        byte[] sha256 = otherHash.digest(text.getBytes(StandardCharsets.UTF_8));
        System.out.println(otherHash.getAlgorithm() + "==" + Hex.toHexString(sha256));

        otherHash.setAlgorithm("MD5");
        byte[] md5 = otherHash.digest(text.getBytes(StandardCharsets.UTF_8));
        System.out.println(otherHash.getAlgorithm() + "==" + Hex.toHexString(md5));
    }

    @Test
    public void hmacHashTest()
    {
        String text = "TestAbc123~!@#$%^&*(3";
        ShaHmacKeyHash hmacShaHash = new ShaHmacKeyHash();
        byte[] key = "PwdAbc".getBytes(StandardCharsets.UTF_8);
        byte[] hmacSha256 = hmacShaHash.digest(text.getBytes(StandardCharsets.UTF_8), key);
        System.out.println(hmacShaHash.getAlgorithm() + "==" + Hex.toHexString(hmacSha256));

        hmacShaHash.setAlgorithm("HmacSHA512");
        byte[] hmacSha512 = hmacShaHash.digest(text.getBytes(StandardCharsets.UTF_8), key);
        System.out.println(hmacShaHash.getAlgorithm() + "==" + Hex.toHexString(hmacSha512));
    }
}