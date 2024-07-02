package com.example.pqc_pass_manager;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PQCOtherInfoGenerator;


import java.io.IOException;
import java.security.SecureRandom;

import static org.bouncycastle.pqc.crypto.frodo.FrodoParameters.frodokem640aes;
import static org.bouncycastle.pqc.crypto.ntru.NTRUParameters.ntruhps2048509;

public class Benchmark {

    public static void main(String[] args) throws Exception {
        benchmarkCK();
        System.out.println("-------");
        benchmarkFRODO();
        System.out.println("-------");
        benchmarkNTRU();
    }

    public static void benchmarkCK() throws Exception {
        long[] resCK = benchmarkCKKeyGeneration();
        long[] resEDCK = benchmarkEncryptionDecryptionCK();
        System.out.println("Tempo médio para geração de chaves com CK kyber768: " + resCK[0] + " ns");
        System.out.println("Tamanho da chave do kyber768: " + resCK[1] + " bytes");
        //System.out.println("Tempo médio para codificação de mensagem CK kyber768: " + resEDCK[0] + " ns");
        //System.out.println("Tempo médio para codificação de mensagem com CK kyber768: " + resEDCK[1] + " ns");
    }

    public static void benchmarkFRODO() throws Exception {
        long[] res = benchmarkFrodoKeyGeneration();
        System.out.println("Tempo médio para geração de chaves com FRODO frodokem640aes: " + res[0] + " ns");
        System.out.println("Tamanho da chave do frodokem640aes: " + res[1] + " bytes");
    }

    public static void benchmarkNTRU() throws Exception {
        long[] resCK = benchmarkNTRUKEMKeyGeneration();
        //long[] resEDCK = benchmarkEncryptionDecryptionCK();
        System.out.println("Tempo médio para geração de chaves com ntruhps2048509: " + resCK[0] + " ns");
        System.out.println("Tamanho da chave do ntruhps2048509: " + resCK[1] + " bytes");
       // System.out.println("Tempo médio para codificação de mensagem CK kyber768: " + resEDCK[0] + " ns");
       // System.out.println("Tempo médio para codificação de mensagem com CK kyber768: " + resEDCK[1] + " ns");
    }

    public static long[] benchmarkCKKeyGeneration(){
        long totalTime = 0;
        int iterations = 10000;
        long[] result = new long[2];

        int kyberPublicKeySize = 0;

        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            AsymmetricCipherKeyPair kyberKeyPair = Crypto.genKeyPair();
            long endTime = System.nanoTime();
            long kyberKeyGenTime = endTime - startTime;

            totalTime += kyberKeyGenTime;

            // Capture the public key size only once, since it's the same for all iterations
            if (i == 0) {
                kyberPublicKeySize = ((KyberPublicKeyParameters) kyberKeyPair.getPublic()).getEncoded().length;
            }
        }

        long averageTime = totalTime / iterations;
        result[0] = averageTime;
        result[1] = kyberPublicKeySize;

        return result;
    }

    public static long[] benchmarkFrodoKeyGeneration() {
        long totalKeyGenTime = 0;
        int iterations = 10;
        long[] result = new long[2];

        int frodoPublicKeySize = 0;

        for (int i = 0; i < iterations; i++) {
            FrodoKeyGenerationParameters genParam = new FrodoKeyGenerationParameters(new SecureRandom(), frodokem640aes);
            FrodoKeyPairGenerator keyPairGenerator = new FrodoKeyPairGenerator();
            keyPairGenerator.init(genParam);

            long startTime = System.nanoTime();
            AsymmetricCipherKeyPair frodoKeyPair = keyPairGenerator.generateKeyPair();
            long endTime = System.nanoTime();
            long frodoKeyGenTime = endTime - startTime;

            totalKeyGenTime += frodoKeyGenTime;

            if (i == 0) {
                frodoPublicKeySize = ((FrodoPublicKeyParameters) frodoKeyPair.getPublic()).getEncoded().length;
            }
        }

        long averageKeyGenTime = totalKeyGenTime / iterations;
        result[0] = averageKeyGenTime;
        result[1] = frodoPublicKeySize;

        return result;
    }

    public static long[] benchmarkNTRUKEMKeyGeneration() throws IOException {
        long totalKeyGenTime = 0;
        int iterations = 10000;
        long[] result = new long[2];

        int ntruPublicKeySize = 0;

        for (int i = 0; i < iterations; i++) {
            NTRUKeyGenerationParameters gen = new NTRUKeyGenerationParameters(new SecureRandom(), ntruhps2048509);
            NTRUKeyPairGenerator keypairGenerator = new NTRUKeyPairGenerator();
            keypairGenerator.init(gen);

            long startTime = System.nanoTime();
            AsymmetricCipherKeyPair ntruKeyPair = keypairGenerator.generateKeyPair();
            long endTime = System.nanoTime();
            long ntruKeyGenTime = endTime - startTime;

            totalKeyGenTime += ntruKeyGenTime;

            if (i == 0) {
                NTRUPublicKeyParameters publicKeyParams = (NTRUPublicKeyParameters) ntruKeyPair.getPublic();
                ntruPublicKeySize = publicKeyParams.getEncoded().length;
            }
        }

        long averageKeyGenTime = totalKeyGenTime / iterations;
        result[0] = (int) averageKeyGenTime;
        result[1] = ntruPublicKeySize;

        return result;
    }


    public static long[] benchmarkEncryptionDecryptionCK() throws Exception {
        long totalEncryptionTime = 0;
        long totalDecryptionTime = 0;
        int iterations = 10000;
        long[] res = new long[2];

        AsymmetricCipherKeyPair kyberKeyPair = Crypto.genKeyPair();
        byte[] publicKey = ((KyberPublicKeyParameters) kyberKeyPair.getPublic()).getEncoded();
        byte[] privateKey = ((KyberPrivateKeyParameters) kyberKeyPair.getPrivate()).getEncoded();
        byte[] symmetricKey = Crypto.extractSecretFromEcanpsulatedSecret(
                Crypto.getSecretWithEncapsulationFromPublicKeyByteArray(publicKey).getEncapsulation(),
                (KyberPrivateKeyParameters) kyberKeyPair.getPrivate()
        );
        byte[] data = "Eu estou sendo codificado".getBytes();

        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            byte[] encryptedData = Crypto.encrypt(symmetricKey, data);
            long encryptionTime = System.nanoTime() - startTime;
            totalEncryptionTime += encryptionTime;

            startTime = System.nanoTime();
            byte[] decryptedData = Crypto.decrypt(symmetricKey, encryptedData);
            long decryptionTime = System.nanoTime() - startTime;
            totalDecryptionTime += decryptionTime;
        }

        long averageEncryptionTime = totalEncryptionTime / iterations;
        long averageDecryptionTime = totalDecryptionTime / iterations;

        res[0] = averageEncryptionTime;
        res[1] = averageDecryptionTime;

        return res;
    }

//    public static long[] benchmarkFrodoEncryptionDecryption() throws Exception {
//        long totalEncryptionTime = 0;
//        long totalDecryptionTime = 0;
//        int iterations = 10000;
//        long[] res = new long[2];
//
//        FrodoKeyGenerationParameters genParam = new FrodoKeyGenerationParameters(new SecureRandom(), frodokem640aes);
//        FrodoKeyPairGenerator keyPairGenerator = new FrodoKeyPairGenerator();
//        keyPairGenerator.init(genParam);
//        AsymmetricCipherKeyPair frodoKeyPair = keyPairGenerator.generateKeyPair();
//        byte[] publicKey = ((FrodoPublicKeyParameters) frodoKeyPair.getPublic()).getEncoded();
//        byte[] privateKey = ((FrodoPrivateKeyParameters) frodoKeyPair.getPrivate()).getEncoded();
//
//        for (int i = 0; i < iterations; i++) {
//            FrodoKEMGenerator frodoKEM = new FrodoKEMGenerator(new SecureRandom(), frodokem640aes);
//            byte[] encapsulatedKey = frodoKEM.generateEncapsulated(publicKey);
//            byte[] ciphertext = frodoKEM.encapsulate(encapsulatedKey, "Eu estou sendo codificado".getBytes());
//
//            long startTime = System.nanoTime();
//            // Decrypt
//            byte[] encapsulatedKeyDecaps = frodoKEM.decapsulate(privateKey, ciphertext);
//            byte[] decryptedData = frodoKEM.decapsulate(encapsulatedKeyDecaps, ciphertext);
//            long decryptionTime = System.nanoTime() - startTime;
//
//            totalDecryptionTime += decryptionTime;
//        }
//
//        long averageDecryptionTime = totalDecryptionTime / iterations;
//
//        res[1] = averageDecryptionTime;
//
//        return res;
//    }

}
