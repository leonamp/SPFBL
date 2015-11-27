/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.spfbl.dnsbl;

import java.io.Serializable;
import java.net.InetAddress;

/**
 *
 * @author Leandro
 */
public class ServerDNSBL implements Serializable, Comparable<ServerDNSBL> {
    
    private static final long serialVersionUID = 1L;
    
    private final String hostname;
    private InetAddress address;
    private String message;
    
    public ServerDNSBL(String hostname, InetAddress address, String message) {
        this.hostname = hostname;
        this.address = address;
        this.message = message;
    }
    
    public void setInetAddress(InetAddress address) {
        this.address = address;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public String getHostName() {
        return hostname;
    }

    public InetAddress getInetAddress() {
        return address;
    }
    
    public String getHostAddress() {
        return address.getHostAddress();
    }
    
    public String getMessage() {
        return message;
    }
    
    @Override
    public int compareTo(ServerDNSBL other) {
        if (other == null) {
            return -1;
        } else {
            return this.hostname.compareTo(other.hostname);
        }
    }
    
    @Override
    public String toString() {
        return hostname;
    }

}
