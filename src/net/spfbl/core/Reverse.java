/*
 * This file is part of SPFBL.
 * 
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SPFBL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SPFBL.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.TreeSet;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Classe que representa o cache do IP reverso.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.ne
 */
public final class Reverse implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final String ip;
    private TreeSet<String> addressSet = null;
    private int queryCount = 0;
    private long lastQuery;
    
    /**
     * Mapa de atributos da verificação do reverso.
     */
    private static final HashMap<String,Reverse> MAP = new HashMap<String,Reverse>();
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    /**
     * O próximo registro de reverso que deve ser atualizado.
     */
    private static Reverse refresh = null;
    
    private static synchronized Reverse dropExact(String ip) {
        Reverse ret = MAP.remove(ip);
        if (ret != null) {
            CHANGED = true;
        }
        return ret;
    }

    private static synchronized Reverse putExact(String key, Reverse value) {
        Reverse reverse = MAP.put(key, value);
        if (!value.equals(reverse)) {
            CHANGED = true;
        }
        return reverse;
    }

    private static synchronized TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<String>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }

    private static synchronized HashMap<String,Reverse> getMap() {
        HashMap<String,Reverse> map = new HashMap<String,Reverse>();
        map.putAll(MAP);
        return map;
    }

    private static synchronized Reverse getExact(String ip) {
        return MAP.get(ip);
    }

    private static synchronized Reverse getRefreshReverse() {
        Reverse reverse = refresh;
        refresh = null;
        return reverse;
    }

    private static synchronized void addQuery(Reverse reverse) {
        reverse.queryCount++;
        reverse.lastQuery = System.currentTimeMillis();
        if (refresh == null) {
            refresh = reverse;
        } else if (refresh.queryCount < reverse.queryCount) {
            refresh = reverse;
        }
        CHANGED = true;
    }
    
    private synchronized boolean contains(String host) {
        if (!Domain.isHostname(host)) {
            return false;
        } else if (addressSet == null) {
            return false;
        } else {
            host = Domain.normalizeHostname(host, true);
            return addressSet.contains(host);
        }
    }
    
    public synchronized TreeSet<String> getAddressSet() {
        if (addressSet == null) {
            return new TreeSet<String>();
        } else {
            TreeSet<String> resultSet = new TreeSet<String>();
            resultSet.addAll(addressSet);
            return resultSet;
        }
    }
    
    private synchronized int getQueryCount() {
        return queryCount;
    }
    
    private synchronized String getAddressOnly() {
        try {
            if (addressSet == null) {
                return null;
            } else if (addressSet.size() == 1) {
                return addressSet.first();
            } else {
                return null;
            }
        } catch (NoSuchElementException ex) {
            return null;
        }
    }
    
    private Reverse(String ip) {
        this.ip = Subnet.normalizeIP(ip);
        refresh();
        this.lastQuery = System.currentTimeMillis();
    }
    
    public synchronized void refresh() {
        long time = System.currentTimeMillis();
        try {
            byte[] address1;
            String reverse;
            TreeSet<String> reverseSet = new TreeSet<String>();
            if (SubnetIPv4.isValidIPv4(ip)) {
                reverse = "in-addr.arpa";
                address1 = SubnetIPv4.split(ip);
                for (byte octeto : address1) {
                    reverse = ((int) octeto & 0xFF) + "." + reverse;
                }
            } else if (SubnetIPv6.isValidIPv6(ip)) {
                reverse = "ip6.arpa";
                address1 = SubnetIPv6.splitByte(ip);
                for (byte octeto : address1) {
                    String hexPart = Integer.toHexString((int) octeto & 0xFF);
                    if (hexPart.length() == 1) {
                        hexPart = "0" + hexPart;
                    }
                    for (char digit : hexPart.toCharArray()) {
                        reverse = digit + "." + reverse;
                    }
                }
            } else {
                address1 = null;
                reverse = null;
            }
            if (address1 != null && reverse != null) {
                Attributes atributes = Server.getAttributesDNS(
                        reverse, new String[]{"PTR"}
                );
                if (atributes != null) {
                    Attribute attributePTR = atributes.get("PTR");
                    if (attributePTR != null) {
                        for (int indexPTR = 0; indexPTR < attributePTR.size(); indexPTR++) {
                            String host = (String) attributePTR.get(indexPTR);
                            host = Domain.normalizeHostname(host, true);
                            if (host != null) {
                                reverseSet.add(host);
                            }
                        }
                    }
                }
                this.addressSet = reverseSet;
                Server.logReverseDNS(time, ip, reverseSet.toString());
            }
        } catch (CommunicationException ex) {
            Server.logReverseDNS(time, ip, "TIMEOUT");
        } catch (ServiceUnavailableException ex) {
            Server.logReverseDNS(time, ip, "SERVFAIL");
        } catch (NameNotFoundException ex) {
            this.addressSet = null;
            Server.logReverseDNS(time, ip, "NXDOMAIN");
        } catch (NamingException ex) {
            this.addressSet = null;
            Server.logReverseDNS(time, ip, "ERROR " + ex.getClass() + " " + ex.getExplanation());
        } finally {
            this.queryCount = 0;
            CHANGED = true;
        }
    }

    public synchronized boolean isExpired7() {
        return System.currentTimeMillis() - lastQuery > 604800000;
    }

    public synchronized boolean isExpired14() {
        return System.currentTimeMillis() - lastQuery > 1209600000;
    }
    
    public static String getHostname(String ip) {
        Reverse reverse = Reverse.get(ip);
        if (reverse == null) {
            return null;
        } else {
            return reverse.getAddressOnly();
        }
    }
    
    public static Reverse get(String ip) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            Reverse reverse = getExact(ip);
            if (reverse == null) {
                reverse = new Reverse(ip);
                putExact(ip, reverse);
            } else if (reverse.isExpired7()) {
                reverse.refresh();
            } else {
                addQuery(reverse);
            }
            return reverse;
        }
    }
    
    /**
     * Atualiza o registro mais consultado.
     */
    public static void refreshLast() {
        Reverse reverseMax = getRefreshReverse();
        if (reverseMax == null) {
            for (String ip : keySet()) {
                Reverse reverse = getExact(ip);
                if (reverse != null) {
                    if (reverseMax == null) {
                        reverseMax = reverse;
                    } else if (reverseMax.getQueryCount() < reverse.getQueryCount()) {
                        reverseMax = reverse;
                    }
                }
            }
        }
        if (reverseMax != null && reverseMax.getQueryCount() > 3) {
            reverseMax.refresh();
        }
    }
    
    public static void dropExpired() {
        for (String ip : keySet()) {
            long time = System.currentTimeMillis();
            Reverse reverse = getExact(ip);
            if (reverse != null && reverse.isExpired14()) {
                reverse = dropExact(ip);
                if (reverse != null) {
                    Server.logReverseDNS(time, ip, "EXPIRED");
                }
            }
        }
    }
    
    private static synchronized boolean isChanged() {
        return CHANGED;
    }
    
    private static synchronized void setStored() {
        CHANGED = false;
    }

    protected static void store() {
        if (isChanged()) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/reverse.map");
                HashMap<String,Reverse> map = getMap();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    setStored();
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    protected static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/reverse.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Reverse) {
                        Reverse reverse = (Reverse) value;
                        putExact(key, reverse);
                    }
                }
                setStored();
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
