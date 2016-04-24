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
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
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

    private static TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<String>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }

    private static HashMap<String,Reverse> getMap() {
        HashMap<String,Reverse> map = new HashMap<String,Reverse>();
        map.putAll(MAP);
        return map;
    }

    private static Reverse getExact(String ip) {
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
    
    private boolean contains(String host) {
        if (!Domain.isHostname(host)) {
            return false;
        } else if (addressSet == null) {
            return false;
        } else {
            host = Domain.normalizeHostname(host, true);
            return addressSet.contains(host);
        }
    }
    
    public TreeSet<String> getAddressSet() {
        if (addressSet == null) {
            return new TreeSet<String>();
        } else {
            TreeSet<String> resultSet = new TreeSet<String>();
            resultSet.addAll(addressSet);
            return resultSet;
        }
    }
    
    public static TreeSet<String> getValidSet(String ip) {
        Reverse reverse = Reverse.get(ip);
        return reverse.getAddressSet(ip);
    }
    
    public TreeSet<String> getAddressSet(String ip) {
        if (addressSet == null) {
            return new TreeSet<String>();
        } else {
            TreeSet<String> resultSet = new TreeSet<String>();
            for (String hostname : addressSet) {
                if (SPF.matchHELO(ip, hostname)) {
                    resultSet.add(hostname);
                }
            }
            return resultSet;
        }
    }
    
    private int getQueryCount() {
        return queryCount;
    }
    
    private String getAddressOnly() {
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
    
    public static String getListed(String ip, String server, Set<String> valueSet) {
        String host = Reverse.getHostReverse(ip, server);
        if (host == null) {
            return null;
        } else {
            try {
                TreeSet<String> IPv4Set = null;
                TreeSet<String> IPv6Set = null;
                for (String value : valueSet) {
                    if (SubnetIPv4.isValidIPv4(value)) {
                        if (IPv4Set == null) {
                            IPv4Set = getIPv4Set(host);
                        }
                        if (IPv4Set.contains(value)) {
                            return value;
                        }
                    } else if (SubnetIPv6.isValidIPv6(value)) {
                        if (IPv6Set == null) {
                            IPv6Set = getIPv6Set(host);
                        }
                        if (IPv6Set.contains(value)) {
                            return value;
                        }
                    }
                }
                return null;
            } catch (CommunicationException ex) {
                Server.logDebug("DNSBL service '" + server + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNSBL service '" + server + "' unavailable.");
                return null;
            } catch (NameNotFoundException ex) {
                // Não listado.
                return null;
            } catch (NamingException ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static boolean isListed(String ip, String dnsbl, String value) {
        String host = Reverse.getHostReverse(ip, dnsbl);
        if (host == null) {
            return false;
        } else {
            try {
                if (SubnetIPv4.isValidIPv4(value)) {
                    return getIPv4Set(host).contains(value);
                } else if (SubnetIPv6.isValidIPv6(value)) {
                    return getIPv6Set(host).contains(value);
                } else {
                    return false;
                }
            } catch (CommunicationException ex) {
                Server.logDebug("DNSBL service '" + dnsbl + "' unreachable.");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNSBL service '" + dnsbl + "' unavailable.");
                return false;
            } catch (NameNotFoundException ex) {
                // Não listado.
                return false;
            } catch (NamingException ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static String getHostReverse(String ip, String domain) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            String reverse = domain;
            byte[] address = SubnetIPv4.split(ip);
            for (byte octeto : address) {
                reverse = ((int) octeto & 0xFF) + "." + reverse;
            }
            return reverse;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            String reverse = domain;
            byte[] address = SubnetIPv6.splitByte(ip);
            for (byte octeto : address) {
                String hexPart = Integer.toHexString((int) octeto & 0xFF);
                if (hexPart.length() == 1) {
                    hexPart = "0" + hexPart;
                }
                for (char digit : hexPart.toCharArray()) {
                    reverse = digit + "." + reverse;
                }
            }
            return reverse;
        } else {
            return null;
        }
    }
    
    private static TreeSet<String> getPointerSet(String host) throws NamingException {
        TreeSet<String> reverseSet = new TreeSet<String>();
        Attributes atributes = Server.getAttributesDNS(
                host, new String[]{"PTR"}
        );
        if (atributes != null) {
            Attribute attribute = atributes.get("PTR");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    host = (String) attribute.get(index);
                    host = Domain.normalizeHostname(host, true);
                    if (host != null) {
                        reverseSet.add(host);
                    }
                }
            }
        }
        return reverseSet;
    }
    
    private static TreeSet<String> getIPv4Set(String host) throws NamingException {
        TreeSet<String> ipSet = new TreeSet<String>();
        Attributes atributes = Server.getAttributesDNS(
                host, new String[]{"A"}
        );
        if (atributes != null) {
            Attribute attribute = atributes.get("A");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    String ip = (String) attribute.get(index);
                    if (SubnetIPv4.isValidIPv4(ip)) {
                        ip = SubnetIPv4.normalizeIPv4(ip);
                        ipSet.add(ip);
                    }
                }
            }
        }
        return ipSet;
    }
    
    private static TreeSet<String> getIPv6Set(String host) throws NamingException {
        TreeSet<String> ipSet = new TreeSet<String>();
        Attributes atributes = Server.getAttributesDNS(
                host, new String[]{"AAAA"}
        );
        if (atributes != null) {
            Attribute attribute = atributes.get("AAAA");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    String ip = (String) attribute.get(index);
                    if (SubnetIPv6.isValidIPv6(ip)) {
                        ip = SubnetIPv6.normalizeIPv6(ip);
                        ipSet.add(ip);
                    }
                }
            }
        }
        return ipSet;
    }
    
    public void refresh() {
        long time = System.currentTimeMillis();
        try {
            String reverse;
            if (SubnetIPv4.isValidIPv4(ip)) {
                reverse = getHostReverse(ip, "in-addr.arpa");
            } else if (SubnetIPv6.isValidIPv6(ip)) {
                reverse = getHostReverse(ip, "ip6.arpa");
            } else {
                reverse = null;
            }
            if (reverse != null) {
                TreeSet<String> ptrSet = getPointerSet(reverse);
                this.addressSet = ptrSet;
                Server.logReverseDNS(time, ip, ptrSet.toString());
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

    public boolean isExpired7() {
        return System.currentTimeMillis() - lastQuery > 604800000;
    }

    public boolean isExpired14() {
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
    
    private static boolean isChanged() {
        return CHANGED;
    }
    
    private static void setStored() {
        CHANGED = false;
    }

    public static void store() {
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

    public static void load() {
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
