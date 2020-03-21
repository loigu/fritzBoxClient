package org.sasanarakkha;

import java.net.PasswordAuthentication;
import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class FritzBoxClient {
	
	/// default address of fritzBox
	private String fritzAddr = "http://fritz.box";

	/** url for logging-in/getting SID */
	private static String authUrl = "/login_sid.lua";

	/** url for rendeeming tickets, params:
	 *  account=default-${COMPUTER_IP} ticket=${TICKET_ID}
	 */
	private static String ticketUseUrl = "/tools/kids_not_allowed.lua";

	/** generic data interface url. 
	 * for getting ticket list "page" use params
	 * xhr=1 lang=en page=kidPro sid=${SID}
	 */
	private static String ticketGetUrl = "/data.lua";

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
		
		public AuthenticationException(String string) {
			super(string);
		}
	}
	
	class HttpException extends IOException {
		private static final long serialVersionUID = 7419409691036710946L;
		
		public HttpException(String string)
		{
			super(string);
		}
	}
	
	class InvalidTicketException extends Exception {
		private static final long serialVersionUID = 4786555000843723640L;

		public InvalidTicketException(String string) {
			super(string);
		}
		
	}

	public FritzBoxClient(String username, String password) {
		this.client = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_2)
				.followRedirects(HttpClient.Redirect.ALWAYS)
				.connectTimeout(Duration.ofSeconds(20))
				.authenticator(new PasswordAuthenticator(username, password))
				.build();
	}
	
	private HttpResponse<String> sendRequest(String uri, BodyPublisher requestBody) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(fritzAddr + uri))
				.POST(requestBody)
				.build();

		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		
		if (response.statusCode() != HttpURLConnection.HTTP_OK) {
			throw new HttpException("invalid http return code " + response.statusCode());
		}
		
		return response;
	}
	
	private static NodeList getElements(String xml, String xPath) throws IOException
	{
		try {
			return (NodeList) XPathFactory.newInstance().newXPath()
					.evaluate(xPath, 
							DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml),
							XPathConstants.NODESET);
		} catch (SAXException | XPathExpressionException | ParserConfigurationException sux) {
			return null;
		}
	    
	}

	public void login() throws AuthenticationException, InterruptedException, IOException {
		HttpResponse<String> response = sendRequest(FritzBoxClient.authUrl, BodyPublishers.noBody());
		
		/* <?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>447214ccb1aa8e16</SID><Challenge>c2fb35bd</Challenge><BlockTime>0</BlockTime><Rights><Name>Phone</Name><Access>2</Access><Name>App</Name><Access>2</Access><Name>Dial</Name><Access>2</Access><Name>BoxAdmin</Name><Access>2</Access></Rights></SessionInfo> */
		NodeList SIDList = getElements(response.body(), "/SessionInfo/SID");
		if (SIDList.getLength() != 1) {
			throw new AuthenticationException("invalid number of SID elements in result xml:\n" + response.body());
		}
		
		// fritzBox doesn't return http error on invalid credentials but rather zero SID
		this.sid = SIDList.item(0).getTextContent();
		if (sid.matches("^0+$"))
		{
			throw new AuthenticationException("invalid SID: " + sid);
		}
	}

	public List<String> getTickets() throws IOException, InterruptedException {
		HttpResponse<String> response = sendRequest(FritzBoxClient.ticketGetUrl,HttpRequest.BodyPublishers.ofString("page=kidPro"));

		/*
		 * ... <table
		 * id="uiTickets"><tr><td>113265</td><td>849441</td><td>029965</td><td>990786</
		 * td><td>399360</td></tr><tr><td>208531</td><td>242994</td><td>839139</td><td>
		 * 996254</td><td>170741</td></tr></table> ...
		 */
		NodeList tickets = getElements(
				new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?><body>")
					.append(response.body())
					.append("</body>").toString(),
				"/body/table[@id=\"uiTickets\"/tr/td");
		
		List<String> result = new ArrayList<String>(10);
		for (int i = 0; i < tickets.getLength(); i++) {
			result.add(tickets.item(i).getTextContent());
		}
		
		return result;
	}

	public void rendeemTicket(String clientIP, String ticket) throws IOException, InterruptedException, InvalidTicketException {
		HttpResponse<String> response = sendRequest(FritzBoxClient.ticketUseUrl,
				HttpRequest.BodyPublishers.ofString(new StringBuilder("ticket=").append(ticket)
						.append("&account=default-").append(clientIP).toString()));
		
		/* check response text:
		 * failure:
			Internet access is blocked
			Redeeming ticket failed.
		
		 * success: The ticket was successfully redeemed.
		 */
		if (!response.body().contains("The ticket was successfully rendeemed")) {
			throw new InvalidTicketException("Rendeeming ticket failed");
		}
	}
}
