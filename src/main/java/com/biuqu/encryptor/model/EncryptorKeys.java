package com.biuqu.encryptor.model;

import lombok.Data;

import java.util.List;

/**
 * 加密器的入参集合
 *
 * @author BiuQu
 * @date 2023/5/3 11:46
 */
@Data
public class EncryptorKeys
{
    /**
     * 是否启用国密加密器
     */
    private boolean gm;

    /**
     * 多个加密器的秘钥配置参数
     */
    private List<EncryptorKey> keys;
}
