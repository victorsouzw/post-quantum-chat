package com.example.pqc_pass_manager;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.google.gson.Gson;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;



import java.security.SecureRandom;

import static org.bouncycastle.pqc.crypto.frodo.FrodoParameters.frodokem640aes;

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
}
