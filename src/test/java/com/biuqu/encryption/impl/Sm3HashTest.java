package com.biuqu.encryption.impl;

import com.biuqu.encryption.Hash;
import com.biuqu.encryption.KeyHash;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class Sm3HashTest
{

    @Test
    public void testSm3()
    {
        String text = "TestAbc123~!@#$%^&*(3";
        Hash sm3 = new Sm3Hash();
        byte[] sm3Hash = sm3.digest(text.getBytes(StandardCharsets.UTF_8));
        System.out.println("sm3Hash==" + Hex.toHexString(sm3Hash));
    }

    @Test
    public void testHmacSm3()
    {
        String text = "TestAbc123~!@#$%^&*(3";
        KeyHash hmacSm3 = new Sm3HmacKeyHash();

        byte[] key = "PwdAbc".getBytes(StandardCharsets.UTF_8);
        byte[] sm3HmacHash = hmacSm3.digest(text.getBytes(StandardCharsets.UTF_8), key);
        System.out.println("sm3HmacHash==" + Hex.toHexString(sm3HmacHash));
    }
}