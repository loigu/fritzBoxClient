package org.sasanarakkha;

import java.net.PasswordAuthentication;
import java.io.IOException;
import java.net.Authenticator;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class FritzBoxClient {
	private static String fritzAddr = "http://fritz.box";

	private static String authUrl = "/login_sid.lua";

	private static String ticketUseUrl = "/tools/kids_not_allowed.lua";
	// account=default-${IP} ticket=${TICKET_ID}

	private static String ticketGetUrl = "/data.lua";
	// xhr=1 lang=en page=kidPro sid=${SID}

	private String sid;
	private HttpClient client;

	class PasswordAuthenticator extends Authenticator {
		String username, password;

		public PasswordAuthenticator(String username, String password) {
			super();

			this.username = username;
			this.password = password;
		}

		public PasswordAuthentication getPasswordAuthentication() {
			return (new PasswordAuthentication(username, password.toCharArray()));
		}
	}

	class AuthenticationException extends Exception {
		private static final long serialVersionUID = 2029949672590455025L;

	}

	public FritzBoxClient(String username, String password) {
		this.client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
				.followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(20))
				.authenticator(new PasswordAuthenticator(username, password)).build();
	}

	public void login() throws AuthenticationException, InterruptedException, IOException {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(FritzBoxClient.authUrl)).build();

		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		// TODO: check result, save SSID
	}

	public String[] getTickets() {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(FritzBoxClient.ticketGetUrl))
				.POST(HttpRequest.BodyPublishers.ofString("page=kidPro")).build();

		HttpResponse<Stream<String>> response = client.send(request, BodyHandlers.ofLines());
		/*
		 * ... <table
		 * id="uiTickets"><tr><td>113265</td><td>849441</td><td>029965</td><td>990786</
		 * td><td>399360</td></tr><tr><td>208531</td><td>242994</td><td>839139</td><td>
		 * 996254</td><td>170741</td></tr></table> ...
		 */
		// check result
		response.statusCode();

		List<String> table = response.body()
				.filter(line -> Pattern.compile("<table> id=\"uiTickets\">.*</table>").matcher(line).matches());

	}

	public void rendeemTicket(String clientIP, String ticket) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(FritzBoxClient.ticketUseUrl))
				.POST(HttpRequest.BodyPublishers.ofString(new StringBuilder("ticket=").append(ticket)
						.append("&account=default-").append(clientIP).toString()))
				.build();

		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		// TODO: check status code
	}
}
