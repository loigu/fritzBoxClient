package org.sasanarakkha;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;

/// wrappers for http communication with fritz.box
public class FritzBoxCommunicator {
	/// default address of fritzBox
	private String fritzAddr = "http://fritz.box";

	private HttpClient client;

	public FritzBoxCommunicator() {
		this.client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
				.followRedirects(HttpClient.Redirect.ALWAYS).connectTimeout(Duration.ofSeconds(20))
				.build();
	}

	class HttpException extends Exception {
		private static final long serialVersionUID = 7419409691036710946L;

		public HttpException(String string) {
			super(string);
		}
	}

	class UnauthorizedException extends HttpException {
		private static final long serialVersionUID = 221013356022993518L;

		public UnauthorizedException(String string) {
			super(string);
		}

	}

	public HttpResponse<String> sendRequest(HttpRequest request)
			throws HttpException, IOException, InterruptedException {
		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

		if (response.statusCode() == HttpURLConnection.HTTP_FORBIDDEN) {
			throw new UnauthorizedException("got http response " + response.statusCode());
		}
		if (response.statusCode() != HttpURLConnection.HTTP_OK) {
			throw new HttpException("invalid http return code " + response.statusCode());
		}

		return response;
	}

	public HttpResponse<String> sendGet(String url) throws HttpException, IOException, InterruptedException {
		return sendRequest(
				HttpRequest.newBuilder().uri(URI.create(this.fritzAddr + url)).header("Accept", "*/*").GET().build());
	}

	/// send http-post with content type application/x-www-form-urlencoded
	public HttpResponse<String> sendPost(String url, String params)
			throws HttpException, IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(fritzAddr + url)).header("Accept", "*/*")
				.header("Content-Type", "application/x-www-form-urlencoded").POST(BodyPublishers.ofString(params))
				.build();

		return sendRequest(request);
	}

}
