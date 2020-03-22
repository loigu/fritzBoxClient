package org.sasanarakkha;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class FritzBoxClient {
	
	/// default address of fritzBox
	private String fritzAddr = "http://fritz.box";

	/** url for logging-in/getting SID */
	private static String authUrl = "/login_sid.lua";
	
	/** logout is done through index.lua post sid=$SID&logout=1 */
	private static String logoutUrl = "/index.lua";

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
	private String username, password;

	/*
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
	*/
	
	class FritzBoxException extends Exception {
		private static final long serialVersionUID = 5605971011660206227L;

		public FritzBoxException(String string) {
			super(string);
		}
		public FritzBoxException(String string, Throwable cause) {
			super(string, cause);
		}
	}
	
	class UnauthorizedException extends FritzBoxException {
		private static final long serialVersionUID = 221013356022993518L;

		public UnauthorizedException(String string) {
			super(string);
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
	
	class HttpException extends FritzBoxException {
		private static final long serialVersionUID = 7419409691036710946L;
		
		public HttpException(String string)
		{
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
		
		this.client = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.followRedirects(HttpClient.Redirect.ALWAYS)
				.connectTimeout(Duration.ofSeconds(20))
				//.authenticator(new PasswordAuthenticator(username, password))
				.build();
	}
	
	private HttpResponse<String> sendRequest(HttpRequest request) throws FritzBoxException, IOException, InterruptedException
	{
		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		
		if (response.statusCode() == HttpURLConnection.HTTP_FORBIDDEN)
		{
			throw new UnauthorizedException("got http response " + response.statusCode());
		}
		if (response.statusCode() != HttpURLConnection.HTTP_OK) {
			throw new HttpException("invalid http return code " + response.statusCode());
		}
		
		return response;
	}
	
	private HttpResponse<String> sendGet(String url) throws FritzBoxException, IOException, InterruptedException {
		return sendRequest(HttpRequest.newBuilder()
				.uri(URI.create(this.fritzAddr + url))
				.header("Accept", "*/*")
				.GET()
				.build());
	}
	
	private HttpResponse<String> sendPost(String url, BodyPublisher requestBody) throws IOException, InterruptedException, FritzBoxException {
		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(fritzAddr + url))
				.header("Accept", "*/*")
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(requestBody)
				.build();
		/*
		Accept: *\/*
		Accept-Encoding: gzip, deflate
		Accept-Language: en-US,en;q=0.9
		Connection: keep-alive
		Content-Length: 59
		Content-Type: application/x-www-form-urlencoded
		Host: fritz.box
		Origin: http://fritz.box
		Referer: http://fritz.box/
		User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36
		*/
		
		return sendRequest(request);
	}
	
	private static NodeList getElements(String xml, String xPath) throws IOException
	{
		try {
			return (NodeList) XPathFactory.newInstance().newXPath()
					.evaluate(xPath, 
							DocumentBuilderFactory.newInstance().newDocumentBuilder().
							parse(new InputSource(new StringReader(xml))),
							XPathConstants.NODESET);
		} catch (SAXException | XPathExpressionException | ParserConfigurationException sux) {
			return null;
		}
	    
	}
	
	/// replace chars > 255 by '.'
	private String makeDots(String str) {
		StringBuilder ret = new StringBuilder();
		for (char c : str.toCharArray())
		{
			if (c > 255) ret.append('.');
			else ret.append(c);
		}
		
		return ret.toString();
	}
	
	/// adds zero byte after each byte
	 private static byte[] to16bit(byte[] bytes) {
		 byte[] ret = new byte[bytes.length * 2];
		 for (int i = 0; i < bytes.length; i++)
		 {
			 ret[i*2] = bytes[i];
			 ret[i*2+1] = 0x0;
		 }
		 return ret;
	 }
	
	static String[] hexArray = { 
			"00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
			 "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
			 "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
			 "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
			 "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
			 "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
			 "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
			 "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
			 "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
			 "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
			 "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
			 "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
			 "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
			 "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
			 "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
			 "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"
			 };
	
	 protected static String bin2hex(byte[] digest) {
		  
	        StringBuilder str = new StringBuilder(34);
	        for (byte n : digest) {
	            str.append(FritzBoxClient.hexArray[(n & 0xFF)]);
	        }
	        return str.toString();
	 }
	 
		/** emulate fritzBox js md5digest for challenge-response auth
		 *  
		 *  js fritzbox md5 emulation:
		 *  (1) replace high value bytes by '.'
		 *  (2) expand to 16bit
		 *  (3) compute md5 and 
		 *  (4) use hex representation 
		 */
	 protected String getResponseDigest(String challengeStr) throws AuthenticationException, UnsupportedEncodingException
	 {
		 // toHexa(md5sum(expandTo16bit(challenge-replaceDots(password))))
			try {
				
				MessageDigest md5 = MessageDigest.getInstance("MD5", "SUN");
				md5.reset();

				md5.update(to16bit(new StringBuilder(challengeStr).append("-").append(makeDots(password)).toString().getBytes("UTF-8")));
				return FritzBoxClient.bin2hex(md5.digest());
				
				//return MD5Utils.binl2hex(MD5Utils.core_md5(MD5Utils.str2binl(challengeStr), 16));
				 
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new AuthenticationException("configuration error, no md5", e);
			}
			
	 }
	
	/** Login to fritzbox */
	public void login() throws FritzBoxException, InterruptedException, IOException {
		HttpResponse<String> challengeGet = sendGet(FritzBoxClient.authUrl);
		
		// <?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID><Challenge>8f833829</Challenge><BlockTime>0</BlockTime><Rights></Rights></SessionInfo>
		NodeList challengeNodes = getElements(challengeGet.body(), "/SessionInfo/Challenge");
		if (challengeNodes.getLength() != 1) {
			throw new AuthenticationException("invalid number of challenge elements in result xml:\n" + challengeGet.body());
		}
		
		String challengeStr = challengeNodes.item(0).getTextContent();
		String responseDigest = getResponseDigest(challengeStr);
		
		// "response=${CHALLENGE}-${RESPONSE}&username=${FRITZUSER}"
		HttpResponse<String> response = sendPost(FritzBoxClient.authUrl, BodyPublishers.ofString(
				new StringBuilder("response=").append(challengeStr).append('-').append(responseDigest)
						.append("&username=").append(username).toString()));
		
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
	
	/** logout - release sid */
	public void logout() throws IOException, InterruptedException, FritzBoxException
	{
		sendPost(FritzBoxClient.logoutUrl, BodyPublishers.ofString("logout=1&sid=" + sid));
		this.sid = null;
	}

	/* NOTE: xml parser is unable to parse the result, get the table by regex
	 * ... <table
	 * id="uiTickets"><tr><td>113265</td><td>849441</td><td>029965</td><td>990786</
	 * td><td>399360</td></tr><tr><td>208531</td><td>242994</td><td>839139</td><td>
	 * 996254</td><td>170741</td></tr></table> ...
	 */	
	private static final Pattern ticketTablePattern = Pattern.compile("<table id=\"uiTickets\">.*</table>");
	
	protected List<String> parseTicketTableResponse(String body) throws FritzBoxException, IOException {
		Matcher m = ticketTablePattern.matcher(body);

	    if (!m.find())
	    {
	    	throw new FritzBoxException("malformed response, no ticket table found:\n" + body);
	    }
	    
	    NodeList tickets = getElements(m.group(), "/table/tr/td");
	
	    List<String> result = new ArrayList<String>(10);
	    for (int i = 0; i < tickets.getLength(); i++) {
	    	result.add(tickets.item(i).getTextContent());
	    }
	    
	    return result;
	}
	
	/** get list of active tickets for fritzBox. client must be logged in first */
	public List<String> getTickets() throws IOException, InterruptedException, FritzBoxException {
		if (sid == null) {
			throw new UnauthorizedException("not logged in");
		}
		
		HttpResponse<String> response = sendPost(FritzBoxClient.ticketGetUrl,HttpRequest.BodyPublishers.ofString("page=kidPro&sid=" + sid));

		return parseTicketTableResponse(response.body());
	}

	/** rendeem @p ticket for given client ip */
	public void rendeemTicket(String clientIP, String ticket) throws IOException, InterruptedException, FritzBoxException {
		HttpResponse<String> response = sendPost(FritzBoxClient.ticketUseUrl,
				HttpRequest.BodyPublishers.ofString(new StringBuilder("ticket=").append(ticket)
						.append("&account=default-").append(clientIP).toString()));
		
		/* check response text:
		 * failure:
			Internet access is blocked
			Redeeming ticket failed.
		
		 * success: The ticket was successfully redeemed.
		 */
		if (response.body().indexOf("The ticket was successfully redeemed") == -1) {
			throw new InvalidTicketException("Rendeeming ticket failed");
		}
	}
}
