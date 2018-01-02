
//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// TESTING_ONLY

package org.openvpn.ovpn3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;

public class Client implements OpenVPNClientThread.EventReceiver {
	private OpenVPNClientThread client_thread;

	public void setClient_thread(OpenVPNClientThread client_thread) {
		this.client_thread = client_thread;
	}

	public OpenVPNClientThread getClient_thread() {
		return client_thread;
	}



	public static class ConfigError extends Exception {
		/**
			 * 
			 */
		private static final long serialVersionUID = 1L;

		public ConfigError(String msg) {
			super(msg);
		}
	}

	public static class CredsUnspecifiedError extends Exception {
		/**
			 * 
			 */
		private static final long serialVersionUID = 1L;

		public CredsUnspecifiedError(String msg) {
			super(msg);
		}
	}

	// Load OpenVPN core (implements OpenVPNClient) from shared library
	static {
		initOVPN3LIB();
	}

	public static void initOVPN3LIB() {
		File libovpncli = null;
		try {
			boolean archI386 = System.getProperty("os.arch").equals("i386");
			String libName =  archI386 ? "libovpncli.i368" : "libovpncli";
			InputStream is = Client.class.getResourceAsStream(libName+".so");
			libovpncli = File.createTempFile(libName+"-", ".so");
			OutputStream os = new FileOutputStream(libovpncli);
			byte[] buffer = new byte[1024];
			int length;
			while ((length = is.read(buffer)) != -1) {
				os.write(buffer, 0, length);
			}
			is.close();
			os.close();
		} catch (Exception e) {
			// TODO: handle exception
		}
		System.load(libovpncli.getAbsolutePath());
		libovpncli.deleteOnExit();
		// System.loadLibrary("ovpncli");
		OpenVPNClient.init_process();
		String test = OpenVPNClient.crypto_self_test();
		System.out.format("CRYPTO SELF TEST:\n  %s", test);
	}

	public Client(String config_text,
				  String username,
				  String password ,
				  String proxyHost,
				  String proxyPort) throws ConfigError, CredsUnspecifiedError {

//		defineConfigWithProxy(proxyHost, proxyPort);
		initClient(config_text, username, password, proxyHost, proxyPort, null, null);
	}
	public Client(String config_text,
				  String username,
				  String password ,
				  String proxyHost,
				  String proxyPort,
				  String proxyUsername,
				  String proxyPassword) throws ConfigError, CredsUnspecifiedError {

//		defineConfigWithProxy(proxyHost, proxyPort, proxyUsername,proxyPassword);
		initClient(config_text, username, password, proxyHost, proxyPort, proxyUsername,proxyPassword);
	}
	public Client(String config_text, String username, String password) throws ConfigError, CredsUnspecifiedError {
		initClient(config_text, username, password, null, null, null, null);
	}

	public Client(File config_file,
				  String username,
				  String password ,
				  String proxyHost,
				  String proxyPort) throws ConfigError, CredsUnspecifiedError, IOException {

//		defineConfigWithProxy(proxyHost, proxyPort);
		initClient(readFile(config_file), username, password,proxyHost, proxyPort, null, null);
	}

	public Client(File config_file,
				  String username,
				  String password ,
				  String proxyHost,
				  String proxyPort,
				  String proxyUsername,
				  String proxyPassword) throws ConfigError, CredsUnspecifiedError, IOException {

//		defineConfigWithProxy(proxyHost, proxyPort, proxyUsername,proxyPassword);
		initClient(readFile(config_file), username, password, proxyHost, proxyPort, proxyUsername,proxyPassword);
	}

	public Client(File config_file, String username, String password) throws ConfigError, CredsUnspecifiedError, IOException{
		initClient(readFile(config_file), username, password, null, null, null, null);
	}

	public Client() {

	}


	public void initClient(String config_text, String username, String password,
						   String proxyHost,
						   String proxyPort,
						   String proxyUsername,
						   String proxyPassword)
			throws ConfigError, CredsUnspecifiedError{
		// init client implementation object
		client_thread = new OpenVPNClientThread();

		// load/eval config
		if(config == null) config = getConfig();
		config.setContent(config_text);
		config.setCompressionMode("yes");
		if(proxyHost != null && proxyPort != null) {
			config.setProxyHost(proxyHost);
			config.setProxyPort(proxyPort);
		}

		if(proxyUsername != null && proxyPassword != null) {
			config.setProxyUsername(proxyUsername);
			config.setProxyPassword(proxyPassword);
		}



		EvalConfig ec = client_thread.eval_config(config);
		if (ec.getError())
			throw new ConfigError("OpenVPN config file parse error: " + ec.getMessage());

		// handle creds
		ProvideCreds creds = new ProvideCreds();
		if (!ec.getAutologin()) {
			if (username.length() > 0) {
				creds.setUsername(username);
				creds.setPassword(password);
				creds.setReplacePasswordWithSessionID(true);
			} else
				throw new CredsUnspecifiedError("OpenVPN config file requires username/password but none provided");
		}
		client_thread.provide_creds(creds);
	}

	Config config;

	public void setConfig(Config config) {
		this.config = config;
	}

	public Config getConfig() {
		return config != null ? config : new Config();
	}

	public void defineConfigWithProxy(String proxyHost, String proxyPort) {
		config = getConfig();
		config.setProxyHost(proxyHost);
		config.setProxyPort(proxyPort);
	}

	public void defineConfigCredsforProxy(String proxyUsername,
										  String proxyPassword) {
		config = getConfig();
		config.setProxyUsername(proxyUsername);
		config.setProxyPassword(proxyPassword);
	}
	public void defineConfigWithProxy(String proxyHost,
									  String proxyPort,
									  String proxyUsername,
									  String proxyPassword) {
		config = getConfig();
		config.setProxyHost(proxyHost);
		config.setProxyPort(proxyPort);
		config.setProxyUsername(proxyUsername);
		config.setProxyPassword(proxyPassword);
	}

	// utility method to read a file and return as a String
	public String readFile(String filename) throws IOException {
		return readStream(new FileInputStream(filename));
	}

	public String readFile(File filename) throws IOException {
		return readStream(new FileInputStream(filename));
	}

	private String readStream(InputStream stream) throws IOException {
		// No real need to close the BufferedReader/InputStreamReader
		// as they're only wrapping the stream
		try {
			Reader reader = new BufferedReader(new InputStreamReader(stream));
			StringBuilder builder = new StringBuilder();
			char[] buffer = new char[4096];
			int read;
			while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
				builder.append(buffer, 0, read);
			}
			return builder.toString();
		} finally {
			// Potential issue here: if this throws an IOException,
			// it will mask any others. Normally I'd use a utility
			// method which would log exceptions and swallow them
			stream.close();
		}
	}

	Thread mainThread;
	public void connectVpn() {
		final Thread mainThread = Thread.currentThread();
		this.mainThread = mainThread;
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				client_thread.stop();
				try {
					mainThread.join();
				} catch (InterruptedException e) {
				}
			}
		});

		// execute client session
		connect();

		// show stats before exit
		show_stats();
	}

	public void stopThread() {
		stop();
	}

	public void connect() {
		// connect
		client_thread.connect(this);

		// wait for worker thread to exit
		client_thread.wait_thread_long();
	}

	public void stop() {
		client_thread.stop();
	}

	public void show_stats() {
		int n = OpenVPNClient.stats_n();
		for (int i = 0; i < n; ++i) {
			String name = OpenVPNClient.stats_name(i);
			long value = client_thread.stats_value(i);
			if (value > 0)
				System.out.format("STAT %s=%s%n", name, value);
		}
	}

	@Override
	public void event(Event event) {
		boolean error = event.getError();
		String name = event.getName();
		String info = event.getInfo();
		System.out.format("EVENT: err=%b name=%s info='%s'%n", error, name, info);
	}

	// Callback to get a certificate
	@Override
	public void external_pki_cert_request(ExternalPKICertRequest req) {
		req.setError(true);
		req.setErrorText("cert request failed: external PKI not implemented");
	}

	// Callback to sign data
	@Override
	public void external_pki_sign_request(ExternalPKISignRequest req) {
		req.setError(true);
		req.setErrorText("sign request failed: external PKI not implemented");
	}

	@Override
	public void log(LogInfo loginfo) {
		String text = loginfo.getText();
		System.out.format("LOG: %s", text);
	}

	@Override
	public void done(Status status) {
		System.out.format("DONE Status: err=%b msg='%s'%n", status.getError(), status.getMessage());
	}

	@Override
	public boolean socket_protect(int socket) {
		return false;
	}

	@Override
	public boolean pause_on_connection_timeout() {
		return false;
	}

	@Override
	public OpenVPNClientThread.TunBuilder tun_builder_new() {
		return null;
	}
}
