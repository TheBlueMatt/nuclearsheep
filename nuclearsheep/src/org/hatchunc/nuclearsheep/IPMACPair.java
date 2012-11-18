package org.hatchunc.nuclearsheep;

import java.net.Inet4Address;

public class IPMACPair {
	public Inet4Address ip;
	public byte[] mac;
	public IPMACPair(byte[] mac, Inet4Address ip) {
		this.mac = mac;
		this.ip = ip;
	}
}
