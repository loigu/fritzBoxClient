package org.sasanarakkha;

import java.io.IOException;
import java.io.StringReader;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
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
	private static String dataUrl = "/data.lua";
	
	/**
	 * url for changing device setting
	 */
	private static String changeDeviceUrl = "/net/edit_device.lua";

	private FritzBoxCommunicator communicator;

	private String username, password;
	private String sid;

	public class FritzBoxException extends Exception {
		private static final long serialVersionUID = 5605971011660206227L;

		public FritzBoxException(String message) {
			super(message);
		}

		public FritzBoxException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	public class AuthenticationException extends FritzBoxException {
		private static final long serialVersionUID = 2029949672590455025L;

		public AuthenticationException(String message, Throwable e) {
			super(message, e);
		}

		public AuthenticationException(String message) {
			super(message);
		}
	}

	public class InvalidTicketException extends FritzBoxException {
		private static final long serialVersionUID = 4786555000843723640L;

		public InvalidTicketException(String message) {
			super(message);
		}

	}
	

	public class DeviceInactiveException extends FritzBoxException {

		private static final long serialVersionUID = 6410571346795351048L;

		public DeviceInactiveException(String message) {
			super(message);
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




	/**
	 * get list of active tickets for fritzBox. client must be logged in first
	 * 
	 */
	public List<String> getTickets() throws IOException, InterruptedException, FritzBoxException, HttpException {
		if (sid == null) {
			throw new FritzBoxException("not logged in");
		}

		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.dataUrl, "page=kidPro&sid=" + sid);

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
			throw new InvalidTicketException("Rendeeming ticket failed:\n" + response.body());
		}
		
	}
	
	/**
	 * get fritzbox info of an active device (connected to hotspot)
	 * @throws DeviceInactiveException 
	 * 
	 */
	public Optional<Device> getActiveDeviceInfo(String ipAddress) 
			throws HttpException, IOException, InterruptedException, DeviceInactiveException {
		
		Optional<Device> device = Optional.empty();
		
		String params = new StringBuilder("xhr=1")
				.append("&sid=" + this.sid)
				.append("&lang=en")
				.append("&page=netDev")
				.append("&xhrId=all")
				.append("&no_sidrenew=")
				.toString();		
		
		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.dataUrl, params);	
		
	    JSONObject jsonObject = new JSONObject(response.body());
	    JSONObject data = jsonObject.getJSONObject("data");
	    JSONArray actives = data.getJSONArray("active");
	    
		for (int i = 0; i < actives.length(); i++) {
			JSONObject active = actives.getJSONObject(i);
			if (active.getString("ipv4").equalsIgnoreCase(ipAddress)) {

				Device dev = new Device(active.getString("name"), active.getString("ipv4"), active.getString("UID"));
				device = Optional.of(dev);
				break;
			}
		}
	    
	    if (device.isEmpty()) {
	    	throw new DeviceInactiveException("This device is inactive in Fritzbox. Probably has problem with your network connection.");	
	    }
	    
	    
	    //get device profile
		params = new StringBuilder("xhr=1")
				.append("&sid=" + this.sid)
				.append("&lang=en")
				.append("&no_sidrenew=")
				.append("&oldpage=net/edit_device.lua")
				.append("&back_to_pid=")
				.append("&dev=" + device.get().getUID())
				.append("&initalRefreshParamsSaved=true")
				.toString();		
		
		response = communicator.sendPost(FritzBoxClient.dataUrl, params);	
		
	    Document doc = Jsoup.parse(response.body());
	    Elements select =  doc.getElementsByAttributeValue("name", "kisi_profile");
	    if (select == null) {
			return Optional.empty();    	
	    }	 
	    
	    
	    Optional<AccessProfile> profile = Optional.empty();
	    
	    Elements options = select.get(0).children();
	    for (Element option : options) {
	        if (option.hasAttr("selected")) {
	            profile = AccessProfile.create(option.val());
	            break;
	        }
	    }
	    
	    
	    if (profile.isPresent()) {
		    device.get().setProfile(profile.get());
	    }
	    
	    
	    return device;
	}
	
	
	
	
	/**
	 * change profile setting of an active device 
	 * 
	 */
//	public Optional<Device> changeActiveDevice(String ipAddress, AccessProfile profile) 
//			throws HttpException, IOException, InterruptedException, FritzBoxException, DeviceInactiveException {
//		
//		Optional<Device> device = this.getActiveDeviceInfo(ipAddress);
//		if (device.isEmpty()) {
//	    	throw new DeviceInactiveException("This device is inactive in Fritzbox. Probably has problem with your network connection.");		
//		}
//		
//		this.changeDevice(ipAddress, profile, device.get().getName(), device.get().getUID());
//		
//		return device;		
//	}
//	
	
	
	/**
	 * change settings of a device 
	 * 
	 */		
	public void changeDevice(Device device) 
			throws HttpException, IOException, InterruptedException, FritzBoxException {
		this.changeDevice(device.getIpAddress(), device.getProfile(), device.getName(), device.getUID());
	}	
	

	
	
	/**
	 * change settings of a device 
	 * 
	 */	
	protected void changeDevice(String ipAddress, AccessProfile profile, String deviceName, String UID) 
			throws HttpException, IOException, InterruptedException, FritzBoxException {
		
		String params = new StringBuilder("sid=" + this.sid)
				.append("&plc_desc=" + deviceName)
				.append("&dev_name=" + deviceName)
				.append("&btn_reset_name=")
				.append("&dev_ip=" + ipAddress)
				.append("&static_dhcp=on")
				.append("&kisi_profile=" + profile.getName())
				.append("&back_to_page=%2Fnet%2Fnet_overview.lua")
				.append("&dev=" + UID)
				.append("&last_action=")
				.append("&validate=btn_save&xhr=1&useajax=1")
				.toString();
		
		HttpResponse<String> response = communicator.sendPost(FritzBoxClient.changeDeviceUrl, params);
		
	    if (! response.body().equalsIgnoreCase("{\"tomark\":[],\"validate\":\"btn_save\",\"result\":\"ok\",\"ok\":true}")) {
	    	throw new FritzBoxException("malformed response, unable to change device:\n" + response.body());
	    }
	    
		params = new StringBuilder("xhr=1")
				.append("&sid=" + this.sid)
				.append("&lang=en")
				.append("&no_sidrenew=")
				.append("&plc_desc=" + deviceName)
				.append("&dev_name=" + deviceName)
				.append("&dev_ip=" + ipAddress)
				.append("&static_dhcp=on")
				.append("&kisi_profile=" + profile.getName())
				.append("&back_to_page=%2Fnet%2Fnet_overview.lua")
				.append("&dev=" + UID)	
				.append("&last_action=")
				.append("&btn_save=&oldpage=%2Fnet%2Fedit_device.lua")
				.toString();
			    
		response = communicator.sendPost(FritzBoxClient.dataUrl, params);
		
	    if (! response.body().equalsIgnoreCase("{\"pid\":\"netDev\"}")) {
	    	throw new FritzBoxException("malformed response, change device failed:\n" + response.body());	    	
	    }
	    
	}
	
	
	
	/**
	 * convert ticket response to list of ticket numbers
	 * 
	 */
	protected List<String> parseTicketTableResponse(String body) throws FritzBoxException, IOException {
		/*
		 * <table
		 * id="uiTickets"><tr><td>113265</td><td>849441</td><td>029965</td><td>990786</
		 * td><td>399360</td></tr><tr><td>208531</td><td>242994</td><td>839139</td><td>
		 * 996254</td><td>170741</td></tr></table> ...
		 */
		
		
		List<String> result = new ArrayList<String>();
		
	    Document doc = Jsoup.parse(body);
	    
	    Element table =  doc.getElementById("uiTickets");
	    if (table == null) {
			throw new FritzBoxException("malformed response, no ticket table found:\n" + body);	    	
	    }
	    
        for (Element row : table.select("tr")) {
            Elements tds = row.select("td");
            for (Element td : tds) {
            	result.add(td.text());
            }
        }
        
	    if (result.size() != 10) {
			throw new FritzBoxException("malformed response, ticket numbers count:\n" + result.size());	    	
	    }        
        
		return result;
	}


	
}
