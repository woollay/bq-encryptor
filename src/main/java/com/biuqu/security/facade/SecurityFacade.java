package com.biuqu.security.facade;

import com.biuqu.encryption.BaseSecureSingleEncryption;
import com.biuqu.encryption.impl.GmEncryption;
import com.biuqu.encryption.impl.UsEncryption;
import com.biuqu.encryptor.BaseEncryptorFacade;
import com.biuqu.encryptor.factory.EncryptorFactory;
import com.biuqu.encryptor.impl.*;
import com.biuqu.encryptor.model.EncryptorKeys;
import com.biuqu.security.EncryptSecurity;
import com.biuqu.security.impl.EncryptSecurityImpl;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 加密安全门面
 * <p>
 * 1.为加密器的核心用途，支持对外加解密
 * 2.加密安全门面简化了加解密使用，若要针对二进制加解密可以EncryptSecurity中的接口
 *
 * @author BiuQu
 * @date 2023/5/8 01:12
 */
public class SecurityFacade extends BaseEncryptorFacade
{
    public SecurityFacade(EncryptorKeys keys)
    {
        super(keys);
        //初始化本地加密安全服务
        EncryptSecurityImpl encryptSecurity = new EncryptSecurityImpl(keys.isGm());
        this.initSecurity(encryptSecurity);
        this.encryptSecurity = encryptSecurity;
    }

    /**
     * 本地不可逆加密或者hash
     *
     * @param data 原始数据
     * @return 摘要数据
     */
    @Override
    public String hash(String data)
    {
        byte[] encBytes = this.getEncryptSecurity().hash(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encBytes);
    }

    /**
     * 本地可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    @Override
    public String encrypt(String data)
    {
        byte[] encBytes = this.getEncryptSecurity().encrypt(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encBytes);
    }

    /**
     * 本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    @Override
    public String decrypt(String data)
    {
        byte[] decBytes = this.getEncryptSecurity().decrypt(Hex.decode(data));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 本地签名
     *
     * @param data 原始数据
     * @return 签名值
     */
    @Override
    public String sign(String data)
    {
        byte[] decBytes = this.getEncryptSecurity().sign(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(decBytes);
    }

    /**
     * 本地验证签名
     *
     * @param data      原始数据
     * @param signature 签名值
     * @return true表示签名验证通过
     */
    @Override
    public boolean verify(String data, String signature)
    {
        return this.getEncryptSecurity().verify(data.getBytes(StandardCharsets.UTF_8), Hex.decode(signature));
    }

    /**
     * 本地可逆加密
     *
     * @param data 原始报文
     * @param salt 盐值
     * @return 加密后的报文
     */
    public String encrypt(String data, String salt)
    {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = Hex.decode(salt.getBytes());
        byte[] encBytes = this.getEncryptSecurity().encrypt(dataBytes, saltBytes);
        return Hex.toHexString(encBytes);
    }

    /**
     * 增强的本地可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    public String secureEncrypt(String data)
    {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] encBytes = this.getEncryptSecurity().secureEncrypt(dataBytes);
        return Hex.toHexString(encBytes);
    }

    /**
     * 非对称的本地加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    public String signEncrypt(String data)
    {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] encBytes = this.getEncryptSecurity().signEncrypt(dataBytes);
        return Hex.toHexString(encBytes);
    }

    /**
     * 非对称的本地加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    public String pgpEncrypt(String data)
    {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] encBytes = this.getEncryptSecurity().pgpEncrypt(dataBytes);
        return new String(encBytes, StandardCharsets.UTF_8);
    }

    /**
     * 本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @param salt 盐值
     * @return 解密后的报文
     */
    public String decrypt(String data, String salt)
    {
        byte[] dataBytes = Hex.decode(data);
        byte[] saltBytes = Hex.decode(salt);
        byte[] decBytes = this.getEncryptSecurity().decrypt(dataBytes, saltBytes);
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 增强的本地解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    public String secureDecrypt(String data)
    {
        byte[] decBytes = this.getEncryptSecurity().secureDecrypt(Hex.decode(data));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 非对称本地解密
     *
     * @param data 原始数据
     * @return 解密后的数据
     */
    public String signDecrypt(String data)
    {
        byte[] decBytes = this.getEncryptSecurity().signDecrypt(Hex.decode(data));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 非对称本地解密
     *
     * @param data 原始数据
     * @return 解密后的数据
     */
    public String pgpDecrypt(String data)
    {
        byte[] decBytes = this.getEncryptSecurity().pgpDecrypt(data.getBytes(StandardCharsets.UTF_8));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 本地签名(使用复合加密算法)
     *
     * @param data 原始数据
     * @return 签名值
     */
    public String secureSign(String data)
    {
        byte[] encBytes = this.getEncryptSecurity().secureSign(data.getBytes(StandardCharsets.UTF_8));
        return new String(encBytes, StandardCharsets.UTF_8);
    }

    /**
     * 本地验证签名(使用复合加密算法)
     *
     * @param data 原始数据(带签名)
     * @return true表示签名验证通过
     */
    public boolean secureVerify(String data)
    {
        return this.getEncryptSecurity().secureVerify(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 获取加密安全类
     *
     * @return 加密安全类
     */
    public EncryptSecurity getEncryptSecurity()
    {
        return encryptSecurity;
    }

    /**
     * 初始化加密安全类
     *
     * @param encryptSecurity 加密安全类
     */
    private void initSecurity(EncryptSecurityImpl encryptSecurity)
    {
        //初始化国际加密算法封装之后的本地加密器
        RsaEncryptor rsaEncryptor = this.getEncryptor(EncryptorFactory.RSA.getAlgorithm());
        encryptSecurity.setRsaEncryptor(rsaEncryptor);
        AesEncryptor aesEncryptor = this.getEncryptor(EncryptorFactory.AES.getAlgorithm());
        encryptSecurity.setAesEncryptor(aesEncryptor);
        AesSecureEncryptor aesSecureEncryptor = this.getEncryptor(EncryptorFactory.SecureAES.getAlgorithm());
        encryptSecurity.setAesSecureEncryptor(aesSecureEncryptor);
        ShaHashEncryptor shaEncryptor = this.getEncryptor(EncryptorFactory.SHA.getAlgorithm());
        encryptSecurity.setShaEncryptor(shaEncryptor);
        //把国际复合加密器中的算法对象都替换成加密机中已有的加密器中的算法对象
        UsEncryptor usEncryptor = this.getEncryptor(EncryptorFactory.US.getAlgorithm());
        UsEncryption usEncryption = (UsEncryption)usEncryptor.getEncryption();
        usEncryptor.setPri(rsaEncryptor.getPri());
        usEncryptor.setPub(rsaEncryptor.getPub());
        usEncryption.setSignEncryption(rsaEncryptor.getEncryption());
        usEncryption.setEncEncryption((BaseSecureSingleEncryption)aesSecureEncryptor.getEncryption());
        usEncryption.setHash(shaEncryptor.getHash());
        encryptSecurity.setUsEncryptor(usEncryptor);
        //设置pgp算法
        PgpEncryptor pgpEncryptor = this.getEncryptor(EncryptorFactory.PGP.getAlgorithm());
        encryptSecurity.setPgpEncryptor(pgpEncryptor);

        //初始化国际加密算法封装之后的本地加密器
        Sm2Encryptor sm2Encryptor = this.getEncryptor(EncryptorFactory.SM2.getAlgorithm());
        encryptSecurity.setSm2Encryptor(sm2Encryptor);
        Sm4Encryptor sm4Encryptor = this.getEncryptor(EncryptorFactory.SM4.getAlgorithm());
        encryptSecurity.setSm4Encryptor(sm4Encryptor);
        Sm4SecureEncryptor sm4SecureEncryptor = this.getEncryptor(EncryptorFactory.SecureSM4.getAlgorithm());
        encryptSecurity.setSm4SecureEncryptor(sm4SecureEncryptor);
        Sm3HashEncryptor sm3Encryptor = this.getEncryptor(EncryptorFactory.SM3.getAlgorithm());
        encryptSecurity.setSm3Encryptor(sm3Encryptor);
        //把国际复合加密器中的算法对象都替换成加密机中已有的加密器中的算法对象
        GmEncryptor gmEncryptor = this.getEncryptor(EncryptorFactory.GM.getAlgorithm());
        GmEncryption gmEncryption = (GmEncryption)gmEncryptor.getEncryption();
        gmEncryptor.setPri(sm2Encryptor.getPri());
        gmEncryptor.setPub(sm2Encryptor.getPub());
        gmEncryption.setSignEncryption(sm2Encryptor.getEncryption());
        gmEncryption.setEncEncryption((BaseSecureSingleEncryption)sm4SecureEncryptor.getEncryption());
        gmEncryption.setHash(sm3Encryptor.getHash());
        encryptSecurity.setGmEncryptor(gmEncryptor);
    }

    /**
     * 本地使用的加密安全类
     */
    private final EncryptSecurity encryptSecurity;
}
