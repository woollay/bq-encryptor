package com.biuqu.security.impl;

import com.biuqu.encryptor.EncryptEncryptor;
import com.biuqu.encryptor.Encryptor;
import com.biuqu.encryptor.impl.PgpEncryptor;
import com.biuqu.security.BaseEncryptSecurity;
import com.biuqu.security.ClientSecurity;
import com.biuqu.security.facade.SecurityFacade;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 定制的本地秘钥加密服务
 *
 * @author BiuQu
 * @date 2023/5/11 10:46
 */
public class ClientSecurityImpl implements ClientSecurity
{
    public ClientSecurityImpl(SecurityFacade securityFacade)
    {
        this.securityFacade = securityFacade;
    }

    @Override
    public String encrypt(String algName, String data)
    {
        Encryptor encryptor = securityFacade.getEncryptor(algName);
        if (encryptor instanceof PgpEncryptor)
        {
            if (encryptor == ((BaseEncryptSecurity)securityFacade.getEncryptSecurity()).getPgpEncryptor())
            {
                return securityFacade.pgpEncrypt(data);
            }
            PgpEncryptor encEncryptor = (PgpEncryptor)encryptor;
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] encBytes = encEncryptor.encrypt(dataBytes, null);
            return new String(encBytes, StandardCharsets.UTF_8);
        }
        else if (encryptor instanceof EncryptEncryptor)
        {
            EncryptEncryptor encEncryptor = (EncryptEncryptor)encryptor;
            byte[] encBytes = encEncryptor.encrypt(data.getBytes(StandardCharsets.UTF_8), null);
            return Hex.toHexString(encBytes);
        }
        return null;
    }

    @Override
    public String decrypt(String algName, String data)
    {
        Encryptor encryptor = securityFacade.getEncryptor(algName);
        if (encryptor instanceof PgpEncryptor)
        {
            if (encryptor == ((BaseEncryptSecurity)securityFacade.getEncryptSecurity()).getPgpEncryptor())
            {
                return securityFacade.pgpDecrypt(data);
            }
            PgpEncryptor encEncryptor = (PgpEncryptor)encryptor;
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] decBytes = encEncryptor.decrypt(dataBytes, null);
            return new String(decBytes, StandardCharsets.UTF_8);
        }
        else if (encryptor instanceof EncryptEncryptor)
        {
            EncryptEncryptor encEncryptor = (EncryptEncryptor)encryptor;
            byte[] decBytes = encEncryptor.decrypt(Hex.decode(data), null);
            return new String(decBytes, StandardCharsets.UTF_8);
        }
        return null;
    }

    /**
     * 真实的本地秘钥加密门面
     */
    private final SecurityFacade securityFacade;
}

