package org.sasanarakkha;

import java.io.IOException;
import java.util.List;

import org.sasanarakkha.FritzBoxClient.FritzBoxException;
import org.sasanarakkha.FritzBoxCommunicator.HttpException;

public class FritzBoxClientMain {

	/* example usage of FritzBoxClient class */
	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("usage: fritzBoxClient username password [clientip]");
			System.exit(1);
		}
		FritzBoxClient client = new FritzBoxClient(args[0], args[1]);

		try {
			System.out.println("logging in with credentials " + args[0] + "/" + args[1]);

			client.login();

			System.out.println("fetching tickets...");

			List<String> tickets = client.getTickets();
			System.out.println("got " + tickets.size() + " tickets:");
			for (String ticket : tickets) {
				System.out.println("\t" + ticket);
			}

			System.out.println("logging out...");
			client.logout();

			if (args.length >= 3) {
				String ticket = tickets.get(0);
				System.out.println("rendeeming first ticket (" + ticket + ") for client " + args[2]);
				client.rendeemTicket(args[2], ticket);
			}

		} catch (IOException | InterruptedException | FritzBoxException | HttpException e) {
			System.err.println(e.toString());
			e.printStackTrace();
		}

	}

}
