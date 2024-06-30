package com.example.pqc_pass_manager;

import org.bouncycastle.pqc.crypto.frodo.*;

import java.util.Scanner;


public class PostQuantumChatApplication {


	public static void main(String[] args) throws Exception {
		Scanner scanner = new Scanner(System.in);
		System.out.println("Enter your ID:");
		String id = scanner.nextLine();
		if (id.equals("1")) {
			Server server = new Server();
			server.run();
		} else {
			Client client = new Client();
			client.run();
		}
	}
}


