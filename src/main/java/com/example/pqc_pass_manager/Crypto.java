package com.example.pqc_pass_manager;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class Crypto {

    public static AsymmetricCipherKeyPair genKeyPair() {

        KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber768);
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(genParam);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static SecretWithEncapsulation getSecretWithEncapsulationFromPublicKeyByteArray (byte[] publicKey) {
        KyberPublicKeyParameters pubKey = new KyberPublicKeyParameters(KyberParameters.kyber768, publicKey);
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretWithEncapsulation = kemGenerator.generateEncapsulated(pubKey);
        return secretWithEncapsulation;
    }

    public static byte[] extractSecretFromEcanpsulatedSecret(byte[] encapsulatedSecret, KyberPrivateKeyParameters privParameters) {
        KyberKEMExtractor frodoDecCipher = new KyberKEMExtractor(privParameters);
        byte[] recipientSecret = frodoDecCipher.extractSecret(encapsulatedSecret);
        return recipientSecret;

    }

    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] key, byte[] data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }
}
