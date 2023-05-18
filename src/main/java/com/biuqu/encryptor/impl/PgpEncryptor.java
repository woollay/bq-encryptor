package com.biuqu.encryptor.impl;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryption.impl.PgpEncryption;
import com.biuqu.encryptor.BaseMultiEncryptor;
import com.biuqu.encryptor.model.EncryptorKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;

/**
 * PGP加密器
 *
 * @author BiuQu
 * @date 2023/5/3 01:12
 */
public class PgpEncryptor extends BaseMultiEncryptor<PGPSecretKey>
{
    public PgpEncryptor(EncryptorKey key)
    {
        super(EncryptionFactory.PGP.createAlgorithm(), Hex.decode(key.getPri()), Hex.decode(key.getPub()));
        PgpEncryption encryption = (PgpEncryption)this.getEncryption();

        encryption.setPwd(key.getPwd().toCharArray());
        encryption.setKid(key.getKid());
        encryption.setExpire(key.getExpire());
    }
}
