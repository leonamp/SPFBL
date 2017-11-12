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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
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
    
    public TreeSet<String> getAddressSet(boolean refresh) {
        if (addressSet == null) {
            return new TreeSet<String>();
        } else {
            if (refresh) {
                refresh();
            }
            TreeSet<String> resultSet = new TreeSet<String>();
            resultSet.addAll(addressSet);
            return resultSet;
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
    
    public static TreeSet<String> getValidSet(String ip, boolean refresh) {
        Reverse reverse = Reverse.get(ip, refresh);
        return reverse.getAddressSet(ip, refresh);
    }
    
    public static TreeSet<String> getValidSet(String ip) {
        Reverse reverse = Reverse.get(ip);
        return reverse.getAddressSet(ip, false);
    }
    
    public static TreeSet<String> getSet(String ip, boolean refresh) {
        Reverse reverse = Reverse.get(ip);
        if (refresh) {
            reverse.refresh();
        }
        return reverse.getAddressSet();
    }
    
    public TreeSet<String> getAddressSet(String ip, boolean refresh) {
        if (addressSet == null) {
            return new TreeSet<String>();
        } else {
            if (refresh) {
                refresh();
            }
            TreeSet<String> resultSet = new TreeSet<String>();
            for (String hostname : addressSet) {
                if (SPF.matchHELO(ip, hostname, refresh)) {
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
    
    public static String getListedIP(String ip, String server, String... valueSet) {
        return getListedIP(ip, server, Arrays.asList(valueSet));
    }
    
    public static String getListedIP(String ip, String server, Collection<String> valueSet) {
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
                Server.logDebug("DNS service '" + server + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNS service '" + server + "' unavailable.");
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
    
    public static String getListedHost(String host, String server, String... valueSet) {
        return getListedHost(host, server, Arrays.asList(valueSet));
    }
    
    public static String getListedHost(String host, String zone, Collection<String> valueSet) {
        host = Domain.normalizeHostname(host, false);
        if (host == null) {
            return null;
        } else {
            try {
                host = host + '.' + zone;
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
                Server.logDebug("DNS service '" + zone + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNS service '" + zone + "' unavailable.");
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
    
    public static boolean isListedIP(String ip, String zone, String value) {
        String host = Reverse.getHostReverse(ip, zone);
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
                Server.logDebug("DNS service '" + zone + "' unreachable.");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNS service '" + zone + "' unavailable.");
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
    
    public static boolean isListedHost(String host, String zone, String value) {
        host = Domain.normalizeHostname(host, true);
        if (host == null) {
            return false;
        } else {
            try {
                host = host + '.' + zone;
                if (SubnetIPv4.isValidIPv4(value)) {
                    return getIPv4Set(host).contains(value);
                } else if (SubnetIPv6.isValidIPv6(value)) {
                    return getIPv6Set(host).contains(value);
                } else {
                    return false;
                }
            } catch (CommunicationException ex) {
                Server.logDebug("DNS service '" + zone + "' unreachable.");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNS service '" + zone + "' unavailable.");
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
    
    public static String getResult(String ip, String zone) {
        String host = Reverse.getHostReverse(ip, zone);
        if (host == null) {
            return null;
        } else {
            try {
                for (String result : getIPv4Set(host)) {
                    if (result.startsWith("127.0.")) {
                        return result;
                    }
                }
                return null;
            } catch (CommunicationException ex) {
                Server.logDebug("DNS service '" + zone + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logDebug("DNS service '" + zone + "' unavailable.");
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
    
    public static String getHostReverse(String ip, String zone) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            String reverse = zone;
            byte[] address = SubnetIPv4.split(ip);
            for (byte octeto : address) {
                reverse = ((int) octeto & 0xFF) + "." + reverse;
            }
            return reverse;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            String reverse = zone;
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
    
    public static boolean isInexistentDomain(String hostname) {
        try {
            hostname = Domain.normalizeHostname(hostname, false);
            Server.getAttributesDNS(hostname, new String[]{"NS"});
            return false;
        } catch (NameNotFoundException ex) {
            return true;
        } catch (NamingException ex) {
            return false;
        }
    }
    
    public static boolean isUnavailableDomain(String hostname) {
        try {
            hostname = Domain.normalizeHostname(hostname, false);
            Server.getAttributesDNS(hostname, new String[]{"NS"});
            return false;
        } catch (ServiceUnavailableException ex) {
            return true;
        } catch (NamingException ex) {
            return false;
        }
    }
    
    public static boolean hasValidMailExchange(String hostname) {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return false;
        } else {
            try {
                Attributes attributesNS = Server.getAttributesDNS(
                        hostname, new String[]{"MX"}
                );
                if (attributesNS != null) {
                    Enumeration enumerationNS = attributesNS.getAll();
                    while (enumerationNS.hasMoreElements()) {
                        Attribute attributeNS = (Attribute) enumerationNS.nextElement();
                        NamingEnumeration enumeration = attributeNS.getAll();
                        while (enumeration.hasMoreElements()) {
                            String ns = (String) enumeration.next();
                            if (Domain.isHostname(ns)) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            } catch (NamingException ex) {
                return false;
            }
        }
    }
    
    public static boolean hasValidNameServers(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return false;
        } else {
            try {
                Attributes attributesNS = Server.getAttributesDNS(
                        hostname, new String[]{"NS"}
                );
                if (attributesNS != null) {
                    Enumeration enumerationNS = attributesNS.getAll();
                    while (enumerationNS.hasMoreElements()) {
                        Attribute attributeNS = (Attribute) enumerationNS.nextElement();
                        NamingEnumeration enumeration = attributeNS.getAll();
                        while (enumeration.hasMoreElements()) {
                            String ns = (String) enumeration.next();
                            if (Domain.isHostname(ns)) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            } catch (NameNotFoundException ex) {
                return false;
            }
        }
    }
    
    public static TreeSet<String> getAddressSetSafe(String hostname) {
        try {
            TreeSet<String> addressSet = getAddressSet(hostname);
            if (addressSet == null) {
                return new TreeSet<>();
            } else {
                return addressSet;
            }
        } catch (NamingException ex) {
            return new TreeSet<>();
        }
    }
    
    public static TreeSet<String> getAddressSet(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            NamingException exception = null;
            TreeSet<String> ipSet = new TreeSet<>();
            try {
                Attributes attributesA = Server.getAttributesDNS(
                        hostname, new String[]{"A"}
                );
                if (attributesA != null) {
                    Enumeration enumerationA = attributesA.getAll();
                    while (enumerationA.hasMoreElements()) {
                        Attribute attributeA = (Attribute) enumerationA.nextElement();
                        NamingEnumeration enumeration = attributeA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String address = (String) enumeration.next();
                            if (SubnetIPv4.isValidIPv4(address)) {
                                address = SubnetIPv4.normalizeIPv4(address);
                                ipSet.add(address);
                            }
                        }
                    }
                }
            } catch (NamingException ex) {
                exception = ex;
            }
            try {
                Attributes attributesAAAA = Server.getAttributesDNS(
                        hostname, new String[]{"AAAA"}
                );
                if (attributesAAAA != null) {
                    Enumeration enumerationAAAA = attributesAAAA.getAll();
                    while (enumerationAAAA.hasMoreElements()) {
                        Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                        NamingEnumeration enumeration = attributeAAAA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String address = (String) enumeration.next();
                            if (SubnetIPv6.isValidIPv6(address)) {
                                address = SubnetIPv6.normalizeIPv6(address);
                                ipSet.add(address);
                            }
                        }
                    }
                }
                return ipSet;
            } catch (NamingException ex) {
                exception = ex;
            }
            if (!ipSet.isEmpty() || exception == null) {
                return ipSet;
            } else {
                throw exception;
            }
        }
    }
    
    public static TreeSet<String> getPointerSet(String host) throws NamingException {
        if (host == null) {
            return null;
        } else {
            TreeSet<String> reverseSet = new TreeSet<>();
            if (Subnet.isValidIP(host)) {
                if (SubnetIPv4.isValidIPv4(host)) {
                    host = getHostReverse(host, "in-addr.arpa");
                } else if (SubnetIPv6.isValidIPv6(host)) {
                    host = getHostReverse(host, "ip6.arpa");
                }
            }
            Attributes atributes = Server.getAttributesDNS(
                    host, new String[]{"PTR"}
            );
            if (atributes != null) {
                Attribute attribute = atributes.get("PTR");
                if (attribute != null) {
                    for (int index = 0; index < attribute.size(); index++) {
                        host = (String) attribute.get(index);
                        if (host != null) {
                            host = host.trim();
                            if (host.endsWith(".")) {
                                int endIndex = host.length() - 1;
                                host = host.substring(0, endIndex);
                            }
                            if (Domain.isHostname(host)) {
                                host = Domain.normalizeHostname(host, true);
                                reverseSet.add(host);
                            }
                        }
                    }
                }
            }
            return reverseSet;
        }
    }
    
    public static ArrayList<String> getMXSet(String host) throws NamingException {
        TreeMap<Integer,TreeSet<String>> mxMap = new TreeMap<>();
        Attributes atributes = Server.getAttributesDNS(
                host, new String[]{"MX"}
        );
        if (atributes == null || atributes.size() == 0) {
            atributes = Server.getAttributesDNS(
                    host, new String[]{"CNAME"}
            );
            Attribute attribute = atributes.get("CNAME");
            if (attribute != null) {
                String cname = (String) attribute.get(0);
                return getMXSet(cname);
            }
        } else {
            Attribute attribute = atributes.get("MX");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    try {
                        String mx = (String) attribute.get(index);
                        int space = mx.indexOf(' ');
                        String value = mx.substring(0, space);
                        int priority = Integer.parseInt(value);
                        mx = mx.substring(space + 1);
                        int last = mx.length() - 1;
                        TreeSet<String> mxSet = mxMap.get(priority);
                        if (mxSet == null) {
                            mxSet = new TreeSet<>();
                            mxMap.put(priority, mxSet);
                        }
                        if (Subnet.isValidIP(mx.substring(0, last))) {
                            mxSet.add(Subnet.normalizeIP(mx.substring(0, last)));
                        } else if (Domain.isHostname(mx)) {
                            mxSet.add(Domain.normalizeHostname(mx, true));
                        }
                    } catch (NumberFormatException ex) {
                    }
                }
            }
        }
        ArrayList<String> mxList = new ArrayList<>();
        if (mxMap.isEmpty()) {
            // https://tools.ietf.org/html/rfc5321#section-5
            mxList.add(Domain.normalizeHostname(host, true));
        } else {
            for (int priority : mxMap.keySet()) {
                TreeSet<String> mxSet = mxMap.get(priority);
                for (String mx : mxSet) {
                    if (!mxList.contains(mx)) {
                        mxList.add(mx);
                    }
                }
            }
        }
        return mxList;
    }
    
    private static TreeSet<String> getIPv4Set(String host) throws NamingException {
        TreeSet<String> ipSet = new TreeSet<>();
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
        TreeSet<String> ipSet = new TreeSet<>();
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
    
    public static String getValidHostname(String ip) {
        Reverse reverse = Reverse.get(ip);
        if (reverse == null) {
            return null;
        } else {
            String hostname = reverse.getAddressOnly();
            if (SPF.matchHELO(ip, hostname)) {
                return hostname;
            } else {
                return null;
            }
        }
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
        return get(ip, false);
    }
    
    public static Reverse get(String ip, boolean refresh) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            Reverse reverse = getExact(ip);
            if (reverse == null) {
                reverse = new Reverse(ip);
                putExact(ip, reverse);
            } else if (refresh) {
                reverse.refresh();
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
//                Server.logTrace("storing reverse.map");
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
