package com.example.post_quantum_chat;



import com.example.pqc_pass_manager.Crypto;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;


import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;



import static org.bouncycastle.pqc.crypto.frodo.FrodoParameters.frodokem640aes;


import java.security.SecureRandom;



class PostQuantumChatApplicationTests {


	void contextLoads() {
	}
	@Test
	public void frodoTest() throws Exception {
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
		byte[] encMessage = Base64.encode(Crypto.encrypt(initiatorSharedSecret, "Mensagem teste".getBytes()));

		//Com o encapsulamento do segredo compartilhado, podemos agora desencapsular o segredo na outra ponta
		//Para isso basta instanciar o FrodoKEMExtractor com a chave privada correspondente e extrair o segredo compartilhado
		FrodoPrivateKeyParameters privParameters = (FrodoPrivateKeyParameters)keyPair.getPrivate();
		org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParameters);
		byte[] recipientSecret = frodoDecCipher.extractSecret(encapSharedSecret);

		// Com o segredo compartilhado em mãos, podemos decifrar a mensagem
		String decMessage = new String(Crypto.decrypt(recipientSecret, Base64.decode(encMessage)));

		System.out.println("Segredo compartilhado gerado na ponta A: " + Hex.toHexString(initiatorSharedSecret));
		System.out.println("Segredo compartilhado gerado na ponta B: " + Hex.toHexString(recipientSecret));
		System.out.println();
		System.out.println("Mensagem cifrada: " + new String(encMessage));
		System.out.println("Mensagem decifrada: " + decMessage);
		Assertions.assertEquals("Mensagem teste", decMessage);
	}

	@Test
	public void kyberTest() throws Exception{

		KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber768);
		KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
		keyPairGenerator.init(genParam);
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		KyberKEMGenerator kemGenerator = new KyberKEMGenerator(new SecureRandom());
		SecretWithEncapsulation secretWithEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());
		byte[] encapsulation = secretWithEncapsulation.getEncapsulation();
		byte[] secret = secretWithEncapsulation.getSecret();

		byte[] encapSharedSecret = secretWithEncapsulation.getEncapsulation();
		byte[] initiatorSharedSecret = secretWithEncapsulation.getSecret();

		//O segredo compartilhado está sendo utilizado para cifrar mensagems com o AES
		byte[] encMessage = Base64.encode(Crypto.encrypt(initiatorSharedSecret, "Mensagem teste".getBytes()));

		//Com o encapsulamento do segredo compartilhado, podemos agora desencapsular o segredo na outra ponta
		//Para isso basta instanciar o FrodoKEMExtractor com a chave privada correspondente e extrair o segredo compartilhado
		KyberPrivateKeyParameters privParameters = (KyberPrivateKeyParameters) keyPair.getPrivate();
		KyberKEMExtractor frodoDecCipher = new KyberKEMExtractor(privParameters);
		byte[] recipientSecret = frodoDecCipher.extractSecret(encapSharedSecret);

		// Com o segredo compartilhado em mãos, podemos decifrar a mensagem
		String decMessage = new String(Crypto.decrypt(recipientSecret, Base64.decode(encMessage)));

		System.out.println("Segredo compartilhado gerado na ponta A: " + Hex.toHexString(initiatorSharedSecret));
		System.out.println("Segredo compartilhado gerado na ponta B: " + Hex.toHexString(recipientSecret));
		System.out.println();
		System.out.println("Mensagem cifrada: " + new String(encMessage));
		System.out.println("Mensagem decifrada: " + decMessage);
		Assertions.assertEquals("Mensagem teste", decMessage);

	}

	@Test
	public void instatianteKyberPublicKeyFromByteArrayTest() throws Exception {
		KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber768);
		KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
		keyPairGenerator.init(genParam);
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		KyberPublicKeyParameters publicKeyParameters = (KyberPublicKeyParameters) keyPair.getPublic();
		byte[] publicKeyBytes = publicKeyParameters.getEncoded();

		KyberPublicKeyParameters publicKeyParameters2 = new KyberPublicKeyParameters(KyberParameters.kyber768, publicKeyBytes);



		Assertions.assertArrayEquals(publicKeyParameters.getEncoded(), publicKeyParameters2.getEncoded());
	}

	@Test
	public void instatianteFrodoPublicKeyFromByteArrayTest() throws Exception {
		FrodoKeyGenerationParameters genParam = new FrodoKeyGenerationParameters(new SecureRandom(), frodokem640aes);
		FrodoKeyPairGenerator keyPairGenerator = new FrodoKeyPairGenerator();
			keyPairGenerator.init(genParam);
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		FrodoPublicKeyParameters publicKeyParameters = (FrodoPublicKeyParameters) keyPair.getPublic();
		byte[] publicKeyBytes = publicKeyParameters.getEncoded();

		FrodoPublicKeyParameters publicKeyParameters2 = new FrodoPublicKeyParameters(frodokem640aes, publicKeyBytes);
		Assertions.assertArrayEquals(publicKeyParameters.getEncoded(), publicKeyParameters2.getEncoded());
	}
}
