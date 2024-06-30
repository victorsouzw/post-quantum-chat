package com.example.pqc_pass_manager;


import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Base64;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
@Getter
@Setter
public class Client {
    //socket client, sera o usuario A
    private boolean firstMessage = true;
    private AsymmetricCipherKeyPair keyPair;
    private byte[] secret;

    public void run() {
        final String HOST = "localhost";
        final int PORT = 12345;

        try (Socket socket = new Socket(HOST, PORT)) {
            System.out.println("Connected to server. Just type to send messages.");

            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));

            String clientMessage;
            String serverMessage;
            System.out.println("Antessssssssssss");
            if (firstMessage) {
                // Enviar a chave pública em byte[]
                System.out.println("Antes");
                this.setKeyPair(Crypto.genKeyPair());
                System.out.println("Depois");
                KyberPublicKeyParameters publicKeyParameters = (KyberPublicKeyParameters) keyPair.getPublic();
                byte[] message = publicKeyParameters.getEncoded();
                Gson gson = new Gson();
                output.println(gson.toJson(new Message(message)));
                firstMessage = false;
                //Aguarda receber o segredo encapsulado
                while (true) {
                    if (input.ready()) {
                        serverMessage = input.readLine();
                        byte [] secretWithEncap = gson.fromJson(serverMessage, Message.class).getMessage();
                        KyberPrivateKeyParameters privParameters = (KyberPrivateKeyParameters) keyPair.getPrivate();

                        setSecret(Crypto.extractSecretFromEcanpsulatedSecret(secretWithEncap, privParameters));

                        System.out.println("SECRETTTT ARMAZENDO: " + Base64.getEncoder().encodeToString(getSecret()));
                        break;
                    }
                }
            }
            System.out.println("Até aqui foi");
            while (true) {

                if (consoleInput.ready()) {
                    clientMessage = consoleInput.readLine();

                    Gson gson = new Gson();
                    output.println(gson.toJson(new Message(Crypto.encrypt(getSecret(), clientMessage.getBytes()))));
                    //output.println(clientMessage);
                }

                if (input.ready()) {
                    serverMessage = input.readLine();
                    Gson gson = new Gson();
                    Message cihperedMessage = gson.fromJson(serverMessage, Message.class);
                    serverMessage = new String(Crypto.decrypt(getSecret(), cihperedMessage.getMessage()));
                    System.out.println("Server cifrada:" + org.bouncycastle.util.encoders.Base64.toBase64String(cihperedMessage.getMessage()));
                    System.out.println("Server decifrada:" + serverMessage);
                }

            }
        } catch (UnknownHostException ex) {
            System.out.println("Server not found: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

}
