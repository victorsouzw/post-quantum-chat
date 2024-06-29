package com.example.pqc_pass_manager;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

import static org.bouncycastle.pqc.crypto.frodo.FrodoParameters.frodokem640aes;

//@SpringBootApplication
public class PqcPassManagerApplication {

	public static void main(String[] args) throws Exception {

		FrodoKeyGenerationParameters genParam = new FrodoKeyGenerationParameters(new SecureRandom(), frodokem640aes);
		FrodoKeyPairGenerator keyPairGenerator = new FrodoKeyPairGenerator();
		keyPairGenerator.init(genParam);

		//Temos aqui um keyPair gerado pelo FrodoKeyPairGenerator
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

		//Para gerar o segredo compartilhado e o encapsulamento desse segredo, precisaremos de um KEMGenerator
		//Como o algorítimo utilizado para gerar o par de chaves foi o Frodo, utilizaremos o FrodoKEMGenerator
		FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(new SecureRandom());

		//Nesse momento é passado a chave pública referente a qual queremos gerar um segredo compartilhado
		//Para demonstração, estamos utilizando o par de chaves gerado anteriormente
		//Em um caso de comunicação real, seria a chave pública da outra ponta
		//Aqui geramos o segredo compartilhado e o encapsulamento desse segredo
		SecretWithEncapsulation secretWithEncapsulation = frodoEncCipher.generateEncapsulated(keyPair.getPublic());

		// Aqui podemos acessar tanto o segredo compartilhado quando o encapsulamento deste
		byte[] encapSharedSecret = secretWithEncapsulation.getEncapsulation();
		byte[] initiatorSharedSecret = secretWithEncapsulation.getSecret();

		//O segredo compartilhado está sendo utilizado para cifrar mensagems com o AES
		var encMessage = Base64.encode(encrypt(initiatorSharedSecret, "Mensagem teste".getBytes()));

		//Com o encapsulamento do segredo compartilhado, podemos agora desencapsular o segredo na outra ponta
		//Para isso basta instanciar o FrodoKEMExtractor com a chave privada correspondente e extrair o segredo compartilhado
		FrodoPrivateKeyParameters privParameters = (FrodoPrivateKeyParameters)keyPair.getPrivate();
		FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParameters);
		byte[] recipientSecret = frodoDecCipher.extractSecret(encapSharedSecret);

		// Com o segredo compartilhado em mãos, podemos decifrar a mensagem
		var decMessage = new String(decrypt(recipientSecret, Base64.decode(encMessage)));

		System.out.println("Segredo compartilhado gerado na ponta A: " + Hex.toHexString(initiatorSharedSecret));
		System.out.println("Segredo compartilhado gerado na ponta B: " + Hex.toHexString(recipientSecret));
		System.out.println();
		System.out.println("Mensagem cifrada: " + new String(encMessage));
		System.out.println("Mensagem decifrada: " + decMessage);
	}
	private static byte[] encrypt(byte[] key, byte[] data) throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		return cipher.doFinal(data);
	}

	private static byte[] decrypt(byte[] key, byte[] data) throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		return cipher.doFinal(data);
	}

	private static SecretWithEncapsulation genSecretWithEncapsulation() {
		KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber768);
		KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
		keyPairGenerator.init(genParam);
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		KyberKEMGenerator kemGenerator = new KyberKEMGenerator(new SecureRandom());
		SecretWithEncapsulation secretWithEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());
		byte[] encapsulation = secretWithEncapsulation.getEncapsulation();
		byte[] secret = secretWithEncapsulation.getSecret();
		return  secretWithEncapsulation;
	}
}
