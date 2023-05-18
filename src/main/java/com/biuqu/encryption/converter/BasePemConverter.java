package com.biuqu.encryption.converter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;

/**
 * 抽象的Pem格式文件转换器
 *
 * @author BiuQu
 * @date 2022/11/11 23:05
 **/
public abstract class BasePemConverter implements PemConverter
{
    /**
     * 获取秘钥键值对
     *
     * @param in  秘钥文件流
     * @param pwd 秘钥key
     * @return 秘钥键值对对象
     */
    protected abstract KeyPair toPair(InputStream in, byte[] pwd);

    static
    {
        //引入BouncyCastle算法支持
        Security.addProvider(new BouncyCastleProvider());
    }
}