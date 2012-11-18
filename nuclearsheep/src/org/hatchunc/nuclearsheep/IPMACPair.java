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

import java.net.Inet4Address;

public class IPMACPair {
	public Inet4Address ip;
	public byte[] mac;
	public IPMACPair(byte[] mac, Inet4Address ip) {
		this.mac = mac;
		this.ip = ip;
	}
}
