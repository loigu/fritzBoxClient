package org.sasanarakkha;

import java.io.IOException;
import java.io.StringReader;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.sasanarakkha.FritzBoxCommunicator.HttpException;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class FritzBoxClient {

	/** url for logging-in/getting SID */
	private static String authUrl = "/login_sid.lua";

	/** logout is done through index.lua post sid=$SID&logout=1 */
	private static String logoutUrl = "/index.lua";

	/**
	 * url for rendeeming tickets, params: account=default-${COMPUTER_IP}
	 * ticket=${TICKET_ID}
	 */
	private static String ticketUseUrl = "/tools/kids_not_allowed.lua";

	/**
	 * generic data interface url. for getting ticket list "page" use params xhr=1
	 * lang=en page=kidPro sid=${SID}
	 */
	private static String ticketGetUrl = "/data.lua";

	private FritzBoxCommunicator communicator;

	private String username, password;
	private String sid;

	class FritzBoxException extends Exception {
		private static final long serialVersionUID = 5605971011660206227L;

		public FritzBoxException(String string) {
			super(string);
		}

		public FritzBoxException(String string, Throwable cause) {
			super(string, cause);
		}
	}

	class AuthenticationException extends FritzBoxException {
		private static final long serialVersionUID = 2029949672590455025L;

		public AuthenticationException(String str, Throwable e) {
			super(str, e);
		}

		public AuthenticationException(String string) {
			super(string);
		}
	}

	class InvalidTicketException extends FritzBoxException {
		private static final long serialVersionUID = 4786555000843723640L;

		public InvalidTicketException(String string) {
			super(string);
		}

	}

	public FritzBoxClient(String username, String password) {
		this.username = username;
		this.password = password;

		this.communicator = new FritzBoxCommunicator();
	}

	/// parse xml and get elements according to xpath expression
	private static NodeList getElements(String xml, String xPath) throws IOException {
		try {
			return (NodeList) XPathFactory.newInstance().newXPath().evaluate(xPath, DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(new InputSource(new StringReader(xml))), XPathConstants.NODESET);
		} catch (SAXException | XPathExpressionException | ParserConfigurationException sux) {
			return null;
		}

	}

	/**
	 * Login to fritzbox
	 * 
	 * @throws HttpException
	 */
	public void login() throws FritzBoxException, InterruptedException, IOException, HttpException {
		HttpResponse<String> challengeGet = communicator.sendGet(FritzBoxClient.authUrl);

		// <?xml version="1.0"
		// encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID><Challenge>8f833829</Challenge><BlockTime>0</BlockTime><Rights></Rights></SessionInfo>
		NodeList challengeNodes = getElements(challengeGet.body(), "/SessionInfo/Challenge");
		if (challengeNodes.getLength() != 1) {
			throw new AuthenticationException(
					"invalid number of challenge elements in result xml:\n" + challengeGet.body());
		}

		String challengeStr = challengeNodes.item(0).getTextContent();
		String responseDigest = null;

		try {
			responseDigest = FritzBoxMd5.getResponseDigest(challengeStr, password);
		} catch (NoSuchAlgorithmException e) {
			throw new FritzBoxException("can not initialize md5", e);
		}

		// "response=${CHALLENGE}-${RESPONSE}&username=${FRITZUSER}"
		String params = new StringBuilder("response=").append(challengeStr).append('-').append(responseDigest)
				.append("&username=").append(username).toString();

		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.authUrl, params);

		/*
		 * <?xml version="1.0"
		 * encoding="utf-8"?><SessionInfo><SID>447214ccb1aa8e16</SID><Challenge>c2fb35bd
		 * </Challenge><BlockTime>0</BlockTime><Rights><Name>Phone</Name><Access>2</
		 * Access><Name>App</Name><Access>2</Access><Name>Dial</Name><Access>2</Access><
		 * Name>BoxAdmin</Name><Access>2</Access></Rights></SessionInfo>
		 */
		NodeList SIDList = getElements(response.body(), "/SessionInfo/SID");
		if (SIDList.getLength() != 1) {
			throw new AuthenticationException("invalid number of SID elements in result xml:\n" + response.body());
		}

		// fritzBox doesn't return http error on invalid credentials but rather zero SID
		this.sid = SIDList.item(0).getTextContent();
		if (sid.matches("^0+$")) {
			throw new AuthenticationException("invalid SID: " + sid);
		}
	}

	/**
	 * logout - release sid
	 * 
	 * @throws HttpException
	 */
	public void logout() throws IOException, InterruptedException, HttpException {
		communicator.sendPost(FritzBoxClient.logoutUrl, "logout=1&sid=" + sid);
		this.sid = null;
	}

	/*
	 * NOTE: xml parser is unable to parse the result, get the table by regex ...
	 * <table
	 * id="uiTickets"><tr><td>113265</td><td>849441</td><td>029965</td><td>990786</
	 * td><td>399360</td></tr><tr><td>208531</td><td>242994</td><td>839139</td><td>
	 * 996254</td><td>170741</td></tr></table> ...
	 */
	private static final Pattern ticketTablePattern = Pattern.compile("<table id=\"uiTickets\">.*</table>");

	protected List<String> parseTicketTableResponse(String body) throws FritzBoxException, IOException {
		Matcher m = ticketTablePattern.matcher(body);

		if (!m.find()) {
			throw new FritzBoxException("malformed response, no ticket table found:\n" + body);
		}

		NodeList tickets = getElements(m.group(), "/table/tr/td");

		List<String> result = new ArrayList<String>(10);
		for (int i = 0; i < tickets.getLength(); i++) {
			result.add(tickets.item(i).getTextContent());
		}

		return result;
	}

	/**
	 * get list of active tickets for fritzBox. client must be logged in first
	 * 
	 * @throws HttpException
	 */
	public List<String> getTickets() throws IOException, InterruptedException, FritzBoxException, HttpException {
		if (sid == null) {
			throw new FritzBoxException("not logged in");
		}

		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.ticketGetUrl, "page=kidPro&sid=" + sid);

		return parseTicketTableResponse(response.body());
	}

	/**
	 * rendeem @p ticket for given client ip - client does not have to be logged in
	 * for this
	 */
	public void rendeemTicket(String clientIP, String ticket)
			throws IOException, InterruptedException, InvalidTicketException, HttpException {
		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.ticketUseUrl,
				"ticket=" + ticket + "&account=default-" + clientIP);

		/*
		 * check response text: failure: Internet access is blocked Redeeming ticket
		 * failed.
		 * 
		 * success: The ticket was successfully redeemed.
		 */
		if (response.body().indexOf("The ticket was successfully redeemed") == -1) {
			throw new InvalidTicketException("Rendeeming ticket failed");
		}
	}
}
