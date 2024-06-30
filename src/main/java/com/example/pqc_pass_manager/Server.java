package com.example.pqc_pass_manager;

import com.google.gson.Gson;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

@Getter
@Setter
public class Server {
    //socket server, sera como o usuario B
    private boolean firstMessage = true;
    private byte[] secret;
    final int PORT = 12345;


    public void run() {
		try (
            ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);
            Socket socket = serverSocket.accept();
            System.out.println("Client connected. Just type to send messages.");

            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));

            String clientMessage;
            String serverMessage;
            System.out.println("Versão nova 2!");
            while (firstMessage) {
                System.out.println("ENTREI ANTES SERVER");
                if (input.ready()) {
                    System.out.println("ENTREI AQ SERVER");
                    //Recebe a chave publica
                    clientMessage = input.readLine();
                    Gson gson = new Gson();
                    Message message = gson.fromJson(clientMessage, Message.class);
                    System.out.println("Client1: " + message.getMessage());
                    SecretWithEncapsulation secretWithEncapsulation = Crypto.getSecretWithEncapsulationFromPublicKeyByteArray(message.getMessage());
                    this.setSecret(secretWithEncapsulation.getSecret());
                    System.out.println("\n \n Secret: " + secretWithEncapsulation.getSecret());
                    //Envia segredo encapsulado
                    String secretWithEncapsulationJson = gson.toJson(new Message(secretWithEncapsulation.getEncapsulation()));
                    output.println(secretWithEncapsulationJson);
                    this.setFirstMessage(false);
                }
            }
            while (true) {
                if (input.ready()) {
                    clientMessage = input.readLine();
                    Gson gson = new Gson();
                    Message cihperedMessage = gson.fromJson(clientMessage, Message.class);
                    clientMessage = new String(Crypto.decrypt(getSecret(), cihperedMessage.getMessage()));
                    System.out.println("Client cifrada:" + Base64.toBase64String(cihperedMessage.getMessage()));
                    System.out.println("Client decifrada: " + clientMessage);
                }

                if (consoleInput.ready()) {
                    serverMessage = consoleInput.readLine();
                    Gson gson = new Gson();
                    output.println(gson.toJson(new Message(Crypto.encrypt(getSecret(), serverMessage.getBytes()))));
                    //output.println("Server: " + serverMessage);
                }
            }

    } catch (
    IOException ex) {
        System.out.println("Server exception: " + ex.getMessage());
        ex.printStackTrace();
    } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
