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
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
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
    private static final HashMap<String,Reverse> MAP = new HashMap<>();
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
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }

    private static synchronized HashMap<String,Reverse> getMap() {
        HashMap<String,Reverse> map = new HashMap<>();
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
        if (!isHostname(host)) {
            return false;
        } else if (addressSet == null) {
            return false;
        } else {
            host = Domain.normalizeHostname(host, true);
            return addressSet.contains(host);
        }
    }
    
    public boolean isEmpty() {
        if (addressSet == null) {
            return true;
        } else {
            return addressSet.isEmpty();
        }
    }
    
    public TreeSet<String> getAddressSet() {
        if (addressSet == null) {
            return new TreeSet<>();
        } else {
            TreeSet<String> resultSet = new TreeSet<>();
            resultSet.addAll(addressSet);
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
    
    public static String getListedIP(String ip, String zone, String... valueSet) {
        return getListedIP(ip, zone, null, Arrays.asList(valueSet));
    }
    
    public static String getListedIP(String ip, String zone, String server, Collection<String> valueSet) {
        String host = Reverse.getHostReverse(ip, zone);
        if (host == null) {
            return null;
        } else {
            try {
                TreeSet<String> IPv4Set = null;
                TreeSet<String> IPv6Set = null;
                for (String value : valueSet) {
                    if (isValidIPv4(value)) {
                        if (IPv4Set == null) {
                            IPv4Set = getIPv4Set(server, host);
                        }
                        if (IPv4Set.contains(value)) {
                            return value;
                        }
                    } else if (isValidIPv6(value)) {
                        if (IPv6Set == null) {
                            IPv6Set = getIPv6Set(server, host);
                        }
                        if (IPv6Set.contains(value)) {
                            return value;
                        }
                    }
                }
                return null;
            } catch (CommunicationException ex) {
                Server.logError("DNS service '" + zone + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logError("DNS service '" + zone + "' unavailable.");
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
                    if (isValidIPv4(value)) {
                        if (IPv4Set == null) {
                            IPv4Set = getIPv4Set(host);
                        }
                        if (IPv4Set.contains(value)) {
                            return value;
                        }
                    } else if (isValidIPv6(value)) {
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
                Server.logError("DNS service '" + zone + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logError("DNS service '" + zone + "' unavailable.");
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
                if (isValidIPv4(value)) {
                    return getIPv4Set(host).contains(value);
                } else if (isValidIPv6(value)) {
                    return getIPv6Set(host).contains(value);
                } else {
                    return false;
                }
            } catch (CommunicationException ex) {
                Server.logError("DNS service '" + zone + "' unreachable.");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logError("DNS service '" + zone + "' unavailable.");
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
                if (isValidIPv4(value)) {
                    return getIPv4Set(host).contains(value);
                } else if (isValidIPv6(value)) {
                    return getIPv6Set(host).contains(value);
                } else {
                    return false;
                }
            } catch (CommunicationException ex) {
                Server.logError("DNS service '" + zone + "' unreachable.");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logError("DNS service '" + zone + "' unavailable.");
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
                    if (result.startsWith("127.")) {
                        return result;
                    }
                }
                return null;
            } catch (CommunicationException ex) {
                Server.logError("DNS service '" + zone + "' unreachable.");
                return null;
            } catch (ServiceUnavailableException ex) {
                Server.logError("DNS service '" + zone + "' unavailable.");
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
        if (isValidIPv4(ip)) {
            String reverse = zone;
            byte[] address = SubnetIPv4.split(ip);
            for (byte octeto : address) {
                reverse = ((int) octeto & 0xFF) + "." + reverse;
            }
            return reverse;
        } else if (isValidIPv6(ip)) {
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
            Server.getAttributesDNS(hostname, "NS");
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
            Server.getAttributesDNS(hostname, "NS");
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
                boolean hasMX = false;
                Attributes attributesMX = Server.getAttributesDNS(hostname, "MX");
                if (attributesMX != null) {
                    Enumeration enumerationMX = attributesMX.getAll();
                    while (enumerationMX.hasMoreElements()) {
                        Attribute attributeMX = (Attribute) enumerationMX.nextElement();
                        NamingEnumeration enumeration = attributeMX.getAll();
                        while (enumeration.hasMoreElements()) {
                            hasMX = true;
                            String mx = (String) enumeration.next();
                            int index = mx.indexOf(' ');
                            if (index > 0) {
                                String priority = mx.substring(0, index);
                                if (Core.isInteger(priority)) {
                                    String fqdn = mx.substring(index+1);
                                    if (isHostname(fqdn)) {
                                        return true;
                                    }
                                }
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
    
    public static boolean isRouteableForMail(String hostname) {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return false;
        } else {
            ArrayList<String> mxList = Reverse.getMXSetSafe(hostname);
            if (mxList == null) {
                return false;
            } else {
                for (String mx : mxList) {
                    for (String ip : Reverse.getAddressSetSafe(mx)) {
                        if (isValidIP(ip) && !Subnet.isReservedIP(ip)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }
    
    public static boolean hasValidNameServersSafe(String hostname) {
        try {
            return hasValidNameServers(hostname);
        } catch (NamingException ex) {
            return false;
        }
    }
    
    public static boolean hasValidNameServers(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return false;
        } else {
            try {
                Attributes attributesNS = Server.getAttributesDNS(hostname, "NS");
                if (attributesNS != null) {
                    Enumeration enumerationNS = attributesNS.getAll();
                    while (enumerationNS.hasMoreElements()) {
                        Attribute attributeNS = (Attribute) enumerationNS.nextElement();
                        NamingEnumeration enumeration = attributeNS.getAll();
                        while (enumeration.hasMoreElements()) {
                            String ns = (String) enumeration.next();
                            if (isHostname(ns)) {
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
    
    public static TreeSet<String> getAddressSetNotNull(
            String hostname
    ) throws NamingException {
        TreeSet<String> addressSet = getAddressSet(hostname);
        if (addressSet == null) {
            return new TreeSet<>();
        } else {
            return addressSet;
        }
    }
    
    public static TreeSet<String> getAddressSet(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            NamingException exception;
            TreeSet<String> ipSet = new TreeSet<>();
            try {
                Attributes attributesA = Server.getAttributesDNS(hostname, "A");
                if (attributesA != null) {
                    Enumeration enumerationA = attributesA.getAll();
                    while (enumerationA.hasMoreElements()) {
                        Attribute attributeA = (Attribute) enumerationA.nextElement();
                        NamingEnumeration enumeration = attributeA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String address = (String) enumeration.next();
                            if (isValidIPv4(address)) {
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
                Attributes attributesAAAA = Server.getAttributesDNS(hostname, "AAAA");
                if (attributesAAAA != null) {
                    Enumeration enumerationAAAA = attributesAAAA.getAll();
                    while (enumerationAAAA.hasMoreElements()) {
                        Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                        NamingEnumeration enumeration = attributeAAAA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String address = (String) enumeration.next();
                            if (isValidIPv6(address)) {
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
    
    public static TreeSet<String> getAddress4Set(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            TreeSet<String> ipSet = new TreeSet<>();
            Attributes attributesA = Server.getAttributesDNS(hostname, "A");
            if (attributesA != null) {
                Enumeration enumerationA = attributesA.getAll();
                while (enumerationA.hasMoreElements()) {
                    Attribute attributeA = (Attribute) enumerationA.nextElement();
                    NamingEnumeration enumeration = attributeA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv4(address)) {
                            address = SubnetIPv4.normalizeIPv4(address);
                            ipSet.add(address);
                        }
                    }
                }
            }
            return ipSet;
        }
    }
    
    public static String getAddress4Safe(String hostname) {
        try {
            return getAddress4(hostname);
        } catch (Exception ex) {
            return null;
        }
    }
    
    public static String getAddress4(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            Attributes attributesA = Server.getAttributesDNS(hostname, "A");
            if (attributesA != null) {
                Enumeration enumerationA = attributesA.getAll();
                while (enumerationA.hasMoreElements()) {
                    Attribute attributeA = (Attribute) enumerationA.nextElement();
                    NamingEnumeration enumeration = attributeA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv4(address)) {
                            return SubnetIPv4.normalizeIPv4(address);
                        }
                    }
                }
            }
            return null;
        }
    }
    
    public static TreeSet<String> getAddress6Set(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            TreeSet<String> ipSet = new TreeSet<>();
            Attributes attributesAAAA = Server.getAttributesDNS(hostname, "AAAA");
            if (attributesAAAA != null) {
                Enumeration enumerationAAAA = attributesAAAA.getAll();
                while (enumerationAAAA.hasMoreElements()) {
                    Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                    NamingEnumeration enumeration = attributeAAAA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv6(address)) {
                            address = SubnetIPv6.normalizeIPv6(address);
                            ipSet.add(address);
                        }
                    }
                }
            }
            return ipSet;
        }
    }
    
    public static String getAddress6Safe(String hostname) {
        try {
            return getAddress6(hostname);
        } catch (Exception ex) {
            return null;
        }
    }
    
    public static String getAddress6(
            String hostname
    ) throws NamingException {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return null;
        } else {
            Attributes attributesAAAA = Server.getAttributesDNS(hostname, "AAAA");
            if (attributesAAAA != null) {
                Enumeration enumerationAAAA = attributesAAAA.getAll();
                while (enumerationAAAA.hasMoreElements()) {
                    Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                    NamingEnumeration enumeration = attributeAAAA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv6(address)) {
                            return SubnetIPv6.normalizeIPv6(address);
                        }
                    }
                }
            }
            return null;
        }
    }
    
    public static TreeSet<String> getPointerSetSafe(String ip) {
        try {
            return getPointerSet(ip);
        } catch (NamingException ex) {
            return new TreeSet<>();
        }
    }
    
    public static TreeSet<String> getPointerSetSafe(String ip, boolean pontuation) {
        try {
            return getPointerSet(ip, pontuation);
        } catch (NamingException ex) {
            return new TreeSet<>();
        }
    }
    
    public static TreeSet<String> getPointerSet(String ip) throws NamingException {
        return getPointerSet(ip, true);
    }
    
    public static TreeSet<String> getPointerSet(String ip, boolean pontuation) throws NamingException {
        if (ip == null) {
            return null;
        } else {
            TreeSet<String> reverseSet = new TreeSet<>();
            if (isValidIP(ip)) {
                if (isValidIPv4(ip)) {
                    ip = getHostReverse(ip, "in-addr.arpa");
                } else if (isValidIPv6(ip)) {
                    ip = getHostReverse(ip, "ip6.arpa");
                }
            }
            Attributes atributes = Server.getAttributesDNS(ip, "PTR");
            if (atributes == null || atributes.size() == 0) {
                try {
                    atributes = Server.getAttributesDNS(ip, "CNAME");
                    if (atributes != null && atributes.size() == 1) {
                        Attribute attribute = atributes.get("CNAME");
                        if (attribute != null && attribute.size() == 1) {
                            String value = (String) attribute.get(0);
                            Attributes atributes2 = Server.getAttributesDNS(value, "PTR");
                            if (atributes2 != null && atributes2.size() > 0) {
                                atributes = atributes2;
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Do nothing.
                }
            }
            if (atributes != null) {
                NamingEnumeration enumeration = atributes.getAll();
                while (enumeration.hasMore()) {
                    Attribute attribute = (Attribute) enumeration.next();
                    for (int index = 0; index < attribute.size(); index++) {
                        String value = (String) attribute.get(index);
                        if (value != null && !(value = value.trim()).isEmpty()) {
                            if (isHostname(value)) {
                                value = Domain.normalizeHostname(value, pontuation);
                                reverseSet.add(value);
                            }
                        }
                    }
                }
            }
            return reverseSet;
        }
    }
    
    public static boolean hasMX(String address) {
        try {
            if (address == null) {
                return false;
            } else if (address.contains("@")) {
                int index = address.indexOf('@') + 1;
                address = address.substring(index);
            }
            ArrayList<String> mxSet = getMXSet(address);
            if (mxSet == null) {
                return false;
            } else if (mxSet.isEmpty()) {
                return false;
            } else {
                return true;
            }
        } catch (NamingException ex) {
            return false;
        }
    }
    
    public static ArrayList<String> getMXSetSafe(String host) {
        try {
            return getMXSet(host);
        } catch (NamingException ex) {
            return null;
        }
    }
    
    public static ArrayList<String> getMXSetSafe(String host, boolean pontuation) {
        try {
            return getMXSet(host, pontuation);
        } catch (NamingException ex) {
            return null;
        }
    }
    
    public static ArrayList<String> getMXSet(String host) throws NamingException {
        return getMXSet(host, true);
    }
    
    public static ArrayList<String> getMXSet(
            String host, boolean pontuation
    ) throws NamingException {
        return getMXSet(host, pontuation, 1);
    }
    
    private static ArrayList<String> getMXSet(
            String host, boolean pontuation, int level
    ) throws NamingException {
        if (host == null) {
            return null;
        } else if (level > 8) {
            // Avoid a possible infinite loop.
            Server.logError("too many loops to resolve MX for zone " + host);
            return null;
        } else {
            TreeMap<Integer,TreeSet<String>> mxMap = new TreeMap<>();
            Attributes atributes = Server.getAttributesDNS(host, "MX");
            if (atributes == null || atributes.size() == 0) {
                atributes = Server.getAttributesDNS(host, "CNAME");
                Attribute attribute = atributes.get("CNAME");
                if (attribute != null) {
                    String cname = (String) attribute.get(0);
                    return getMXSet(cname, pontuation, level+1);
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
                            if (isValidIP(mx.substring(0, last))) {
                                mxSet.add(Subnet.normalizeIP(mx.substring(0, last)));
                            } else if (isHostname(mx)) {
                                mxSet.add(Domain.normalizeHostname(mx, pontuation));
                            }
                        } catch (NumberFormatException ex) {
                        }
                    }
                }
            }
            ArrayList<String> mxList = new ArrayList<>();
            if (mxMap.isEmpty()) {
                // https://tools.ietf.org/html/rfc5321#section-5
                mxList.add(Domain.normalizeHostname(host, pontuation));
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
    }
    
    public static ArrayList<String> getNSSet(String host) throws NamingException {
        if (host == null) {
            return null;
        } else {
            ArrayList<String> nsList = new ArrayList<>();
            Attributes atributes = Server.getAttributesDNS(host, "NS");
            if (atributes == null) {
                return null;
            } else {
                Attribute attribute = atributes.get("NS");
                if (attribute == null) {
                    return null;
                } else {
                    for (int index = 0; index < attribute.size(); index++) {
                        String ns = (String) attribute.get(index);
                        if (!nsList.contains(ns)) {
                            nsList.add(ns);
                        }
                    }
                }
            }
            return nsList;
        }
    }
    
    public static ArrayList<String> getTXTSetSafe(String host) {
        try {
            return getTXTSet(host);
        } catch (NamingException ex) {
            return null;
        }
    }
    
    public static ArrayList<String> getTXTSet(String host) throws NamingException {
        if (host == null) {
            return null;
        } else {
            ArrayList<String> nsList = new ArrayList<>();
            Attributes atributes = Server.getAttributesDNS(host, "TXT");
            if (atributes == null) {
                return null;
            } else {
                Attribute attribute = atributes.get("TXT");
                if (attribute == null) {
                    return null;
                } else {
                    for (int index = 0; index < attribute.size(); index++) {
                        String ns = (String) attribute.get(index);
                        if (!nsList.contains(ns)) {
                            nsList.add(ns);
                        }
                    }
                }
            }
            return nsList;
        }
    }
    
    private static TreeSet<String> getIPv4Set(String host) throws NamingException {
        return getIPv4Set(null, host);
    }
    
    private static TreeSet<String> getIPv4Set(String server, String host) throws NamingException {
        TreeSet<String> ipSet = new TreeSet<>();
        Attributes atributes = Server.getAttributesDNS(
                server, host, new String[]{"A"}
        );
        if (atributes != null) {
            Attribute attribute = atributes.get("A");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    String ip = (String) attribute.get(index);
                    if (isValidIPv4(ip)) {
                        ip = SubnetIPv4.normalizeIPv4(ip);
                        ipSet.add(ip);
                    }
                }
            }
        }
        return ipSet;
    }
    
    private static TreeSet<String> getIPv6Set(String host) throws NamingException {
        return getIPv6Set(null, host);
    }
    
    private static TreeSet<String> getIPv6Set(String server, String host) throws NamingException {
        TreeSet<String> ipSet = new TreeSet<>();
        Attributes atributes = Server.getAttributesDNS(
                server, host, new String[]{"AAAA"}
        );
        if (atributes != null) {
            Attribute attribute = atributes.get("AAAA");
            if (attribute != null) {
                for (int index = 0; index < attribute.size(); index++) {
                    String ip = (String) attribute.get(index);
                    if (isValidIPv6(ip)) {
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
            TreeSet<String> ptrSet = getPointerSet(ip);
            this.addressSet = ptrSet;
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
            if (Reverse.getAddressSetSafe(hostname).contains(ip)) {
                return hostname;
            } else {
                return null;
            }
        }
    }
    
    public static String getValidHostname(String ip, TreeSet<String> ptrSet) {
        if (ip == null) {
            return null;
        } else if (ptrSet == null) {
            return null;
        } else {
            for (String ptr : ptrSet) {
                if (Reverse.getAddressSetSafe(ptr).contains(ip)) {
                    return ptr;
                }
            }
            return null;
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
    
    private static void dropExpired() {
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
        dropExpired();
        if (isChanged()) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/reverse.map");
                HashMap<String,Reverse> map = getMap();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    setStored();
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
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
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
