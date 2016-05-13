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
package net.spfbl.data;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.Peer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de liberação do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class White {
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    /**
     * Conjunto de remetentes liberados.
     */
    private static class SET {
        
        private static final HashSet<String> SET = new HashSet<String>();
        
        public static synchronized boolean isEmpty() {
            return SET.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = new TreeSet<String>();
            set.addAll(SET);
            SET.clear();
            return set;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<String>();
            set.addAll(SET);
            return set;
        }
        
        private static synchronized boolean addExact(String token) {
            return SET.add(token);
        }
        
        private static synchronized boolean dropExact(String token) {
            return SET.remove(token);
        }
        
        public static boolean contains(String token) {
            return SET.contains(token);
        }
    }
    
    private static void logTrace(long time, String message) {
        Server.log(time, Core.Level.TRACE, "WHITE", message, (String) null);
    }
    
    /**
     * Conjunto de critérios WHOIS para liberação.
     */
    private static class WHOIS {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<String,TreeSet<String>>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = getAll();
            MAP.clear();
            return set;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<String>();
            for (String client : MAP.keySet()) {
                for (String whois : MAP.get(client)) {
                    if (client == null) {
                        set.add("WHOIS=" + whois);
                    } else {
                        set.add(client + ":WHOIS=" + whois);
                    }
                }
        }
            return set;
        }
        
        private static synchronized boolean dropExact(String token) {
            int index = token.indexOf('=');
            String whois = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                return false;
            } else {
                boolean removed = set.remove(whois);
                if (set.isEmpty()) {
                    MAP.remove(client);
                }
                return removed;
            }
        }
        
        private static synchronized boolean addExact(String token) {
            int index = token.indexOf('=');
            String whois = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                set = new TreeSet<String>();
                MAP.put(client, set);
            }
            return set.add(whois);
        }
        
        public static boolean contains(String client, String dnsbl) {
            if (dnsbl == null) {
                return false;
            } else {
                TreeSet<String> dnsblSet = MAP.get(client);
                if (dnsblSet == null) {
                    return false;
                } else {
                    return dnsblSet.contains(dnsbl);
                }
            }
        }
        
        private static synchronized String[] getArray(Client client) {
            TreeSet<String> set = MAP.get(client == null || !client.hasEmail() ? null : client.getEmail());
            if (set == null) {
                return null;
            } else {
                int size = set.size();
                String[] array = new String[size];
                return set.toArray(array);
            }
        }
        
        private static String get(Client client, Set<String> tokenSet) {
            if (tokenSet.isEmpty()) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                TreeSet<String> subSet = new TreeSet<String>();
                String[] array = getArray(null);
                if (array != null) {
                    subSet.addAll(Arrays.asList(array));
                }
                if (client != null) {
                    array = getArray(client);
                    if (array != null) {
                        subSet.addAll(Arrays.asList(array));
                    }
                }
                if (subSet.isEmpty()) {
                    return null;
                } else {
                    for (String whois : subSet) {
                        int indexKey = whois.indexOf('/');
                        char signal = '=';
                        int indexValue = whois.indexOf(signal);
                        if (indexValue == -1) {
                            signal = '<';
                            indexValue = whois.indexOf(signal);
                            if (indexValue == -1) {
                                signal = '>';
                                indexValue = whois.indexOf(signal);
                            }
                        }
                        if (indexValue != -1) {
                            String key = whois.substring(indexKey + 1, indexValue);
                            String criterion = whois.substring(indexValue + 1);
                            for (String token : tokenSet) {
                                String value = null;
                                if (Subnet.isValidIP(token)) {
                                    value = Subnet.getValue(token, key);
                                } else if (!token.startsWith(".") && Domain.containsDomain(token)) {
                                    value = Domain.getValue(token, key);
                                } else if (!token.startsWith(".") && Domain.containsDomain(token.substring(1))) {
                                    value = Domain.getValue(token, key);
                                }
                                if (value != null) {
                                    if (signal == '=') {
                                        if (criterion.equals(value)) {
                                            logTrace(time, "WHOIS lookup for " + tokenSet + ".");
                                            return whois;
                                        }
                                    } else if (value.length() > 0) {
                                        int criterionInt = parseIntWHOIS(criterion);
                                        int valueInt = parseIntWHOIS(value);
                                        if (signal == '<' && valueInt < criterionInt) {
                                            logTrace(time, "WHOIS lookup for " + tokenSet + ".");
                                            return whois;
                                        } else if (signal == '>' && valueInt > criterionInt) {
                                            logTrace(time, "WHOIS lookup for " + tokenSet + ".");
                                            return whois;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    logTrace(time, "WHOIS lookup for " + tokenSet + ".");
                    return null;
                }

            }
        }
    }
    
//    /**
//     * Conjunto de DNSBL para bloqueio de IP.
//     */
//    private static class DNSBL {
//        
//        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<String,TreeSet<String>>();
//        
//        public static synchronized boolean isEmpty() {
//            return MAP.isEmpty();
//        }
//        
//        public static synchronized void clear() {
//            MAP.clear();
//        }
//        
//        public static synchronized TreeSet<String> getAll() {
//            TreeSet<String> set = new TreeSet<String>();
//            for (String client : MAP.keySet()) {
//                for (String dnsbl : MAP.get(client)) {
//                    if (client == null) {
//                        set.add("DNSBL=" + dnsbl);
//                    } else {
//                        set.add(client + ":DNSBL=" + dnsbl);
//                    }
//                }
//            }
//            return set;
//        }
//        
//        private static synchronized boolean dropExact(String token) {
//            int index = token.indexOf('=');
//            String dnsbl = token.substring(index+1);
//            index = token.lastIndexOf(':', index);
//            String client;
//            if (index == -1) {
//                client = null;
//            } else {
//                client = token.substring(0, index);
//            }
//            TreeSet<String> set = MAP.get(client);
//            if (set == null) {
//                return false;
//            } else {
//                boolean removed = set.remove(dnsbl);
//                if (set.isEmpty()) {
//                    MAP.remove(client);
//                }
//                return removed;
//            }
//        }
//        
//        private static synchronized boolean addExact(String token) {
//            int index = token.indexOf('=');
//            String dnsbl = token.substring(index+1);
//            index = token.lastIndexOf(':', index);
//            String client;
//            if (index == -1) {
//                client = null;
//            } else {
//                client = token.substring(0, index);
//            }
//            TreeSet<String> set = MAP.get(client);
//            if (set == null) {
//                set = new TreeSet<String>();
//                MAP.put(client, set);
//            }
//            return set.add(dnsbl);
//        }
//        
//        public static boolean contains(String client, String dnsbl) {
//            if (dnsbl == null) {
//                return false;
//            } else {
//                TreeSet<String> dnsblSet = MAP.get(client);
//                if (dnsblSet == null) {
//                    return false;
//                } else {
//                    return dnsblSet.contains(dnsbl);
//                }
//            }
//        }
//    
//        private static synchronized String[] getArray(String client) {
//            TreeSet<String> set = MAP.get(client);
//            if (set == null) {
//                return null;
//            } else {
//                int size = set.size();
//                String[] array = new String[size];
//                return set.toArray(array);
//            }
//        }
//        
//        private static String get(String client, String ip) {
//            if (ip == null) {
//                return null;
//            } else {
//                long time = System.currentTimeMillis();
//                TreeMap<String,TreeSet<String>> dnsblMap =
//                        new TreeMap<String,TreeSet<String>>();
//                String[] array = getArray(null);
//                if (array != null) {
//                    for (String dnsbl : array) {
//                        int index = dnsbl.indexOf(';');
//                        String server = dnsbl.substring(0, index);
//                        String value = dnsbl.substring(index + 1);
//                        TreeSet<String> dnsblSet = dnsblMap.get(server);
//                        if (dnsblSet == null) {
//                            dnsblSet = new TreeSet<String>();
//                            dnsblMap.put(server, dnsblSet);
//                        }
//                        dnsblSet.add(value);
//                    }
//                }
//                if (client != null) {
//                    array = getArray(client);
//                    if (array != null) {
//                        for (String dnsbl : array) {
//                            int index = dnsbl.indexOf(';');
//                            String server = dnsbl.substring(0, index);
//                            String value = dnsbl.substring(index + 1);
//                            TreeSet<String> dnsblSet = dnsblMap.get(server);
//                            if (dnsblSet == null) {
//                                dnsblSet = new TreeSet<String>();
//                                dnsblMap.put(server, dnsblSet);
//                            }
//                            dnsblSet.add(value);
//                        }
//                    }
//                }
//                String result = null;
//                for (String server : dnsblMap.keySet()) {
//                    TreeSet<String> valueSet = dnsblMap.get(server);
//                    String listed = Reverse.getListed(ip, server, valueSet);
//                    if (listed != null) {
//                        Server.logDebug("IP " + ip + " is listed in '" + server + ";" + listed + "'.");
//                        result = server + ";" + listed;
//                        break;
//                    }
//                }
//                logTrace(time, "DNSBL lookup for '" + ip + "'.");
//                return result;
//            }
//        }
//    }
    
    /**
     * Conjunto de REGEX para liberação.
     */
    private static class REGEX {
        
        private static final HashMap<String,ArrayList<Pattern>> MAP = new HashMap<String,ArrayList<Pattern>>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = getAll();
            MAP.clear();
            return set;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<String>();
            for (String client : MAP.keySet()) {
                for (Pattern pattern : MAP.get(client)) {
                    if (client == null) {
                        set.add("REGEX=" + pattern);
                    } else {
                        set.add(client + ":REGEX=" + pattern);
                    }
                }
            }
            return set;
        }
        
        private static synchronized boolean dropExact(String token) {
            int index = token.indexOf('=');
            String regex = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            ArrayList<Pattern> list = MAP.get(client);
            if (list == null) {
                return false;
            } else {
                for (index = 0; index < list.size(); index++) {
                    Pattern pattern = list.get(index);
                    if (regex.equals(pattern.pattern())) {
                        list.remove(index);
                        if (list.isEmpty()) {
                            MAP.remove(client);
                        }
                        return true;
                    }
                }
                return false;
            }
        }
        
        private static synchronized boolean addExact(String token) {
            int index = token.indexOf('=');
            String regex = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            ArrayList<Pattern> list = MAP.get(client);
            if (list == null) {
                list = new ArrayList<Pattern>();
                MAP.put(client, list);
            }
            for (index = 0; index < list.size(); index++) {
                Pattern pattern = list.get(index);
                if (regex.equals(pattern.pattern())) {
                    return false;
                }
            }
            Pattern pattern = Pattern.compile(regex);
            list.add(pattern);
            return true;
        }
        
        public static boolean contains(String client, String regex) {
            if (regex == null) {
                return false;
            } else {
                ArrayList<Pattern> patternList = MAP.get(client);
                if (patternList == null) {
                    return false;
                } else {
                    for (Pattern pattern : patternList) {
                        if (regex.equals(pattern.pattern())) {
                            return true;
                        }
                    }
                }
                return false;
            }
        }
        
        private static synchronized Pattern[] getArray(Client client) {
            ArrayList<Pattern> patternList = MAP.get(client == null || !client.hasEmail() ? null : client.getEmail());
            if (patternList == null) {
                return null;
            } else {
                int size = patternList.size();
                Pattern[] array = new Pattern[size];
                return patternList.toArray(array);
            }
        }
        
        private static String get(Client client, Set<String> tokenSet) {
            if (tokenSet.isEmpty()) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String result = null;
                Pattern[] patternArray = getArray(null);
                if (patternArray != null) {
                    for (Pattern pattern : patternArray) {
                        for (String token : tokenSet) {
                            Matcher matcher = pattern.matcher(token);
                            if (matcher.matches()) {
                                result = "REGEX=" + pattern.pattern();
                                break;
                            }
                        }
                    }
                }
                if (result == null && client != null) {
                    patternArray = getArray(client);
                    if (patternArray != null) {
                        for (Pattern pattern : patternArray) {
                            for (String token : tokenSet) {
                                Matcher matcher = pattern.matcher(token);
                                if (matcher.matches()) {
                                    result = client + ":REGEX=" + pattern.pattern();
                                    break;
                                }
                            }
                        }
                    }
                }
                logTrace(time, "REGEX lookup for " + tokenSet + ".");
                return result;
            }
        }
    }
    
    /**
     * Representa o conjunto de blocos IP liberados.
     */
    private static class CIDR {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<String,TreeSet<String>>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = getAll();
            MAP.clear();
            return set;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<String>();
            for (String client : MAP.keySet()) {
                for (String cidr : MAP.get(client)) {
                    if (cidr.contains(":")) {
                        cidr = SubnetIPv6.normalizeCIDRv6(cidr);
                    } else {
                        cidr = SubnetIPv4.normalizeCIDRv4(cidr);
                    }
                    if (client == null) {
                        set.add("CIDR=" + cidr);
                    } else {
                        set.add(client + ":CIDR=" + cidr);
                    }
                }
            }
            return set;
        }
        
        private static synchronized boolean dropExact(String token) {
            int index = token.indexOf('=');
            String cidr = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                return false;
            } else {
                String key = Subnet.expandCIDR(cidr);
                boolean removed = set.remove(key);
                if (set.isEmpty()) {
                    MAP.remove(client);
                }
                return removed;
            }
        }
        
        private static synchronized boolean addExact(String token) throws ProcessException {
            int index = token.indexOf('=');
            String cidr = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                set = new TreeSet<String>();
                MAP.put(client, set);
            }
            String key = Subnet.expandCIDR(cidr);
            String first = Subnet.getFirstIP(cidr);
            String last = Subnet.getLastIP(cidr);
            String floorLower = set.lower(key);
            String floorLast = set.floor(Subnet.expandIP(last) + "/9");
            if (floorLower == null) {
                floorLower = null;
            } else if (floorLower.contains(".")) {
                floorLower = SubnetIPv4.normalizeCIDRv4(floorLower);
            } else if (floorLower.contains(":")) {
                floorLower = SubnetIPv6.normalizeCIDRv6(floorLower);
            } else {
                floorLower = null;
            }
            if (floorLast == null) {
                floorLast = null;
            } else if (floorLast.contains(".")) {
                floorLast = SubnetIPv4.normalizeCIDRv4(floorLast);
            } else if (floorLast.contains(":")) {
                floorLast = SubnetIPv6.normalizeCIDRv6(floorLast);
            } else {
                floorLast = null;
            }
            if (cidr.equals(floorLast)) {
                return false;
            } else if (Subnet.containsIP(floorLast, first)) {
                throw new ProcessException("INTERSECTS " + floorLast);
            } else if (Subnet.containsIP(floorLast, last)) {
                throw new ProcessException("INTERSECTS " + floorLast);
            } else if (Subnet.containsIP(floorLower, first)) {
                throw new ProcessException("INTERSECTS " + floorLower);
            } else if (Subnet.containsIP(floorLower, last)) {
                throw new ProcessException("INTERSECTS " + floorLower);
            } else if (Subnet.containsIP(cidr, Subnet.getFirstIP(floorLast))) {
                throw new ProcessException("INTERSECTS " + floorLast);
            } else if (Subnet.containsIP(cidr, Subnet.getLastIP(floorLast))) {
                throw new ProcessException("INTERSECTS " + floorLast);
            } else {
                return set.add(key);
            }
        }
        
        public static boolean contains(String client, String cidr) {
            if (cidr == null) {
                return false;
            } else {
                String key = Subnet.expandCIDR(cidr);
                TreeSet<String> cidrSet = MAP.get(client);
                return cidrSet.contains(key);
            }
        }
        
        private static String getFloor(Client client, String ip) {
            TreeSet<String> cidrSet = MAP.get(client == null || !client.hasEmail() ? null : client.getEmail());
            if (cidrSet == null || cidrSet.isEmpty()) {
                return null;
            } else if (SubnetIPv4.isValidIPv4(ip)) {
                String key = SubnetIPv4.expandIPv4(ip);
                String cidr = cidrSet.floor(key + "/9");
                if (cidr == null) {
                    return null;
                } else if (cidr.contains(".")) {
                    return SubnetIPv4.normalizeCIDRv4(cidr);
                } else {
                    return null;
                }
            } else if (SubnetIPv6.isValidIPv6(ip)) {
                String key = SubnetIPv6.expandIPv6(ip);
                String cidr = cidrSet.floor(key + "/9");
                if (cidr == null) {
                    return null;
                } else if (cidr.contains(":")) {
                    return SubnetIPv6.normalizeCIDRv6(cidr);
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }

        public static String get(Client client, String ip) {
            long time = System.currentTimeMillis();
            String result;
            String cidr = getFloor(null, ip);
            if (Subnet.containsIP(cidr, ip)) {
                result = "CIDR=" + cidr;
            } else if (client == null) {
                result = null;
            } else if ((cidr = getFloor(client, ip)) == null) {
                result = null;
            } else if (Subnet.containsIP(cidr, ip)) {
                result = client + ":CIDR=" + cidr;
            } else {
                result = null;
            }
            logTrace(time, "CIDR lookup for '" + ip + "'.");
            return result;
        }
    }

    public static boolean dropExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS=")) {
            if (WHOIS.dropExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
//        } else if (token.contains("DNSBL=")) {
//            if (DNSBL.dropExact(token)) {
//                Peer.releaseAll(token);
//                CHANGED = true;
//                return true;
//            } else {
//                return false;
//            }
        } else if (token.contains("CIDR=")) {
            if (CIDR.dropExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.contains("REGEX=")) {
            if (REGEX.dropExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (SET.dropExact(token)) {
            Peer.releaseAll(token);
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    public static synchronized TreeSet<String> dropAll() {
        TreeSet<String> set = SET.clear();
        set.addAll(CIDR.clear());
        set.addAll(REGEX.clear());
//        set.addAll(DNSBL.clear());
        set.addAll(WHOIS.clear());
        CHANGED = true;
        return set;
    }

    public static boolean addExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS=")) {
            if (WHOIS.addExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
//        } else if (token.contains("DNSBL=")) {
//            if (DNSBL.addExact(token)) {
//                Peer.releaseAll(token);
//                CHANGED = true;
//                return true;
//            } else {
//                return false;
//            }
        } else if (token.contains("CIDR=")) {
            if (CIDR.addExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.contains("REGEX=")) {
            if (REGEX.addExact(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (SET.addExact(token)) {
            Peer.releaseAll(token);
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    public static synchronized TreeSet<String> getAll() throws ProcessException {
        TreeSet<String> whiteSet = SET.getAll();
        whiteSet.addAll(CIDR.getAll());
        whiteSet.addAll(REGEX.getAll());
//        whiteSet.addAll(DNSBL.getAll());
        whiteSet.addAll(WHOIS.getAll());
        return whiteSet;
    }

    public static boolean containsExact(String token) {
        if (token.contains("WHOIS=")) {
            int index = token.indexOf('=');
            String whois = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            return WHOIS.contains(client, whois);
//        } else if (token.contains("DNSBL=")) {
//            int index = token.indexOf('=');
//            String dnsbl = token.substring(index+1);
//            index = token.lastIndexOf(':', index);
//            String client;
//            if (index == -1) {
//                client = null;
//            } else {
//                client = token.substring(0, index);
//            }
//            return DNSBL.contains(client, dnsbl);
        } else if (token.contains("CIDR=")) {
            int index = token.indexOf('=');
            String cidr = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            return CIDR.contains(client, cidr);
        } else if (token.contains("REGEX=")) {
            int index = token.indexOf('=');
            String regex = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            return REGEX.contains(client, regex);
        } else {
            return SET.contains(token);
        }
    }

//    private static String addDomain(String user, String token) {
//        try {
//            if (token == null) {
//                return null;
//            } else if (token.startsWith("@") && (token = Domain.extractDomain(token.substring(1), true)) != null) {
//                if (user == null && addExact(token)) {
//                    return token;
//                } else if (user != null && addExact(user + ':' + token)) {
//                    return user + ':' + token;
//                } else {
//                    return null;
//                }
//            } else if (token.startsWith(".") && (token = Domain.extractDomain(token, true)) != null) {
//                if (user == null && addExact(token)) {
//                    return token;
//                } else if (user != null && addExact(user + ':' + token)) {
//                    return user + ':' + token;
//                } else {
//                    return null;
//                }
//            } else {
//                return null;
//            }
//        } catch (ProcessException ex) {
//            return null;
//        }
//    }
    
    private static boolean matches(String regex, String token) {
        try {
            return Pattern.matches(regex, token);
        } catch (Exception ex) {
            return false;
        }
    }
    
    private static boolean isWHOIS(String token) {
        return matches("^WHOIS(/[a-z-]+)+((=[a-zA-Z0-9@/.-]+)|((<|>)[0-9]+))$", token);
    }

    private static boolean isREGEX(String token) {
        return matches("^REGEX=[^ ]+$", token);
    }
    
    private static boolean isDNSBL(String token) {
        if (token.startsWith("DNSBL=") && token.contains(";")) {
            int index1 = token.indexOf('=');
            int index2 = token.indexOf(';');
            String server = token.substring(index1 + 1, index2);
            String value = token.substring(index2 + 1);
            return Domain.isHostname(server) && Subnet.isValidIP(value);
        } else {
            return false;
        }
    }

    private static boolean isCIDR(String token) {
        return matches("^CIDR=("
                + "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2})"
                + "|"
                + "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,7}:|"
                + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                + "::(ffff(:0{1,4}){0,1}:){0,1}"
                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
                + "([0-9a-fA-F]{1,4}:){1,4}:"
                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/[0-9]{1,3})"
                + ")$", token);
    }
    
    private static String normalizeTokenWhite(String token) throws ProcessException {
        token = SPF.normalizeToken(token, true, true, true, false, true);
        if (token == null) {
            return null;
        } else if (token.contains(";PASS")) {
            return token;
        } else if (token.contains(";FAIL")) {
            return token;
        } else if (token.contains(";SOFTFAIL")) {
            return token;
        } else if (token.contains(";NEUTRAL")) {
            return token;
        } else if (token.contains(";NONE")) {
            return token;
        } else if (isWHOIS(token)) {
            return token;
        } else if (isREGEX(token)) {
            return token;
        } else if (isDNSBL(token)) {
            return token;
        } else if (isCIDR(token)) {
            return token;
        } else if (token.startsWith("@>")) {
            return token;
        } else if (token.contains(">")) {
            int index = token.indexOf('>');
            return token.substring(0, index) + ";PASS" + token.substring(index);
        } else {
            return token + ";PASS";
        }
    }

    public static boolean add(
            String sender) throws ProcessException {
        if ((sender = normalizeTokenWhite(sender)) == null) {
            throw new ProcessException("ERROR: SENDER INVALID");
        } else if (addExact(sender)) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean add(String client, String token) throws ProcessException {
        if (client == null || !Domain.isEmail(client)) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("ERROR: TOKEN INVALID");
        } else {
            return addExact(client + ':' + token);
        }
    }
    
    public static boolean add(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("ERROR: TOKEN INVALID");
        } else {
            return addExact(client.getEmail() + ':' + token);
        }
    }

    public static boolean drop(String token) throws ProcessException {
        if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("ERROR: TOKEN INVALID");
        } else if (dropExact(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean drop(String client, String token) throws ProcessException {
        if (client == null || !Domain.isEmail(client)) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("ERROR: TOKEN INVALID");
        } else {
            return dropExact(client + ':' + token);
        }
    }

    public static boolean drop(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("ERROR: TOKEN INVALID");
        } else {
            return dropExact(client.getEmail() + ':' + token);
        }
    }

    public static TreeSet<String> get(Client client) throws ProcessException {
        TreeSet<String> whiteSet = new TreeSet<String>();
        if (client != null && client.hasEmail()) {
            for (String token : getAll()) {
                if (token.startsWith(client.getEmail() + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    whiteSet.add(token);
                }
            }
        }
        return whiteSet;
    }

    public static TreeSet<String> getAll(Client client) throws ProcessException {
        TreeSet<String> whiteSet = new TreeSet<String>();
        if (client != null && client.hasEmail()) {
            for (String token : getAll()) {
                if (!token.contains(":")) {
                    whiteSet.add(token);
                } else if (token.startsWith(client.getEmail() + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    whiteSet.add(token);
                }
            }
        }
        return whiteSet;
    }

    public static TreeSet<String> getAllTokens(String value) {
        TreeSet<String> whiteSet = new TreeSet<String>();
        if (Subnet.isValidIP(value)) {
            String ip = Subnet.normalizeIP(value);
            if (SET.contains(ip)) {
                whiteSet.add(ip);
            }
        } else if (Subnet.isValidCIDR(value)) {
            String cidr = Subnet.normalizeCIDR(value);
            if (CIDR.contains(null, cidr)) {
                whiteSet.add(cidr);
            }
            TreeSet<String> set = SET.getAll();
            for (String ip : set) {
                if (Subnet.containsIP(cidr, ip)) {
                    whiteSet.add(ip);
                }
            }
            for (String ip : set) {
                if (SubnetIPv6.containsIP(cidr, ip)) {
                    whiteSet.add(ip);
                }
            }
        } else if (value.startsWith(".")) {
            String hostname = value;
            TreeSet<String> set = SET.getAll();
            for (String key : set) {
                if (key.endsWith(hostname)) {
                    whiteSet.add(key);
                }
            }
            for (String mx : set) {
                String hostKey = '.' + mx.substring(1);
                if (hostKey.endsWith(hostname)) {
                    whiteSet.add(hostKey);
                }
            }
        } else if (SET.contains(value)) {
            whiteSet.add(value);
        }
        return whiteSet;
    }

    public static TreeSet<String> get() throws ProcessException {
        TreeSet<String> whiteSet = new TreeSet<String>();
        for (String token : getAll()) {
            if (!token.contains(":")) {
                whiteSet.add(token);
            }
        }
        return whiteSet;
    }
    
    public static boolean contains(Client client,
            String ip, String sender, String helo,
            String qualifier, String recipient) {
        return find(client, ip, sender, helo, qualifier, recipient) != null;
    }
    
    public static String find(Client client,
            String ip, String sender, String helo,
            String qualifier, String recipient) {
        TreeSet<String> whoisSet = new TreeSet<String>();
        TreeSet<String> regexSet = new TreeSet<String>();
        // Definição do destinatário.
        String recipientDomain;
        if (recipient != null && recipient.contains("@")) {
            int index = recipient.indexOf('@');
            recipient = recipient.toLowerCase();
            recipientDomain = recipient.substring(index);
        } else {
            recipient = null;
            recipientDomain = null;
        }
        // Verifica o remetente.
        if (sender != null && sender.contains("@")) {
            sender = sender.toLowerCase();
            int index1 = sender.indexOf('@');
            int index2 = sender.lastIndexOf('@');
            String part = sender.substring(0, index1 + 1);
            String senderDomain = sender.substring(index2);
            String found;
            if (senderDomain.equals("@spfbl.net") && qualifier.equals("PASS")) {
                return "@spfbl.net;PASS";
            } else if (sender.equals(Core.getAdminEmail()) && qualifier.equals("PASS")) {
                return sender + ";PASS";
            } else if (recipient != null && SET.contains(sender + ';' + qualifier + '>' + recipient)) {
                return sender + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(sender + ';' + qualifier + '>' + recipientDomain)) {
                return sender + ';' + qualifier + '>' + recipientDomain;
            } else if (SET.contains(sender + ';' + qualifier)) {
                return sender + ';' + qualifier;
            } else if (recipient != null && SET.contains(sender + ';' + qualifier + '>' + recipient)) {
                return sender + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(sender + ';' + qualifier + '>' + recipientDomain)) {
                return sender + ';' + qualifier + '>' + recipientDomain;
            } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + sender + ';' + qualifier)) {
                return client.getEmail() + ':' + sender + ';' + qualifier;
            } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + sender + ';' + qualifier + '>' + recipient)) {
                return client.getEmail() + ':' + sender + ';' + qualifier + '>' + recipient;
            } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + sender + ';' + qualifier + '>' + recipientDomain)) {
                return client.getEmail() + ':' + sender + ';' + qualifier + '>' + recipientDomain;
            } else if (SET.contains(part + ';' + qualifier)) {
                return part + ';' + qualifier;
            } else if (recipient != null && SET.contains(part + ';' + qualifier + '>' + recipient)) {
                return part + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(part + ';' + qualifier + '>' + recipientDomain)) {
                return part + ';' + qualifier + '>' + recipientDomain;
            } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + part + ';' + qualifier)) {
                return client.getEmail() + ':' + part + ';' + qualifier;
            } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + part + ';' + qualifier + '>' + recipient)) {
                return client.getEmail() + ':' + part + ';' + qualifier + '>' + recipient;
            } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + part + ';' + qualifier + '>' + recipientDomain)) {
                return client.getEmail() + ':' + part + ';' + qualifier + '>' + recipientDomain;
            } else if (SET.contains(senderDomain + ';' + qualifier)) {
                return senderDomain + ';' + qualifier;
            } else if (recipient != null && SET.contains(senderDomain + ';' + qualifier + '>' + recipient)) {
                return senderDomain + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                return senderDomain + ';' + qualifier + '>' + recipientDomain;
            } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + senderDomain + ';' + qualifier)) {
                return client.getEmail() + ':' + senderDomain + ';' + qualifier;
            } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + senderDomain + ';' + qualifier + '>' + recipient)) {
                return client.getEmail() + ':' + senderDomain + ';' + qualifier + '>' + recipient;
            } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                return client.getEmail() + ':' + senderDomain + ';' + qualifier + '>' + recipientDomain;
            } else if ((found = findHost(client, senderDomain.substring(1), qualifier, recipient, recipientDomain)) != null) {
                return found;
            } else if (recipient != null && SET.contains("@>" + recipient)) {
                return "@>" + recipient;
            } else if (recipientDomain != null && SET.contains("@>" + recipientDomain)) {
                return "@>" + recipientDomain;
            } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@>" + recipient)) {
                return client.getEmail() + ":@>" + recipient;
            } else if (recipientDomain != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@>" + recipientDomain)) {
                return client.getEmail() + ":@>" + recipientDomain;
            } else if (recipient != null && SET.contains("@;" + qualifier +  ">" + recipient)) {
                return "@;" + qualifier +  ">" + recipient;
            } else if (recipientDomain != null && SET.contains("@;" + qualifier +  ">" + recipientDomain)) {
                return "@;" + qualifier +  ">" + recipientDomain;
            } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + qualifier +  ">" + recipient)) {
                return client.getEmail() + ":@;" + qualifier +  ">" + recipient;
            } else if (recipientDomain != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + qualifier +  ">" + recipientDomain)) {
                return client.getEmail() + ":@;" + qualifier +  ">" + recipientDomain;
            } else {
                int index3 = senderDomain.length();
                while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = senderDomain.substring(0, index3 + 1);
                    if (SET.contains(subdomain + ';' + qualifier)) {
                        return subdomain + ';' + qualifier;
                    } else if (recipient != null && SET.contains(subdomain + ';' + qualifier + '>' + recipient)) {
                        return subdomain + ';' + qualifier + '>' + recipient;
                    } else if (recipientDomain != null && SET.contains(subdomain + ';' + qualifier + '>' + recipientDomain)) {
                        return subdomain + ';' + qualifier + '>' + recipientDomain;
                    } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + subdomain + ';' + qualifier)) {
                        return client.getEmail() + ':' + subdomain + ';' + qualifier;
                    } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + subdomain + ';' + qualifier + '>' + recipient)) {
                        return client.getEmail() + ':' + subdomain + ';' + qualifier + '>' + recipient;
                    } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + subdomain + ';' + qualifier + '>' + recipientDomain)) {
                        return client.getEmail() + ':' + subdomain + ';' + qualifier + '>' + recipientDomain;
                    }
                }
                int index4 = sender.length();
                while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                    String subsender = sender.substring(0, index4 + 1);
                    if (SET.contains(subsender + ';' + qualifier)) {
                        return subsender + ';' + qualifier;
                    } else if (recipient != null && SET.contains(subsender + ';' + qualifier + '>' + recipient)) {
                        return subsender + ';' + qualifier + '>' + recipient;
                    } else if (recipientDomain != null && SET.contains(subsender + ';' + qualifier + '>' + recipientDomain)) {
                        return subsender + ';' + qualifier + '>' + recipientDomain;
                    } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + subsender + ';' + qualifier)) {
                        return client.getEmail() + ':' + subsender + ';' + qualifier;
                    } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + subsender + ';' + qualifier + '>' + recipient)) {
                        return client.getEmail() + ':' + subsender + ';' + qualifier + '>' + recipient;
                    } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + subsender + ';' + qualifier + '>' + recipientDomain)) {
                        return client.getEmail() + ':' + subsender + ';' + qualifier + '>' + recipientDomain;
                    }
                }
            }
            if (senderDomain.endsWith(".br")) {
                whoisSet.add(senderDomain);
            }
            regexSet.add(sender);
        }
        // Verifica o HELO.
        if ((helo = Domain.extractHost(helo, true)) != null) {
            String found;
            if ((found = findHost(client, helo, qualifier, recipient, recipientDomain)) != null) {
                return found;
            }
            if (helo.endsWith(".br") && SPF.matchHELO(ip, helo)) {
                whoisSet.add(helo);
            }
            regexSet.add(helo);
        }
        // Verifica o IP.
        if (ip != null) {
            ip = Subnet.normalizeIP(ip);
            String cidr;
            if (SET.contains(ip + ';' + qualifier)) {
                return ip + ';' + qualifier;
            } else if (recipient != null && SET.contains(ip + ';' + qualifier + '>' + recipient)) {
                return ip + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(ip + ';' + qualifier + '>' + recipientDomain)) {
                return ip + ';' + qualifier + '>' + recipientDomain;
            } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + ip + ';' + qualifier)) {
                return client.getEmail() + ':' + ip + ';' + qualifier;
            } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + ip + ';' + qualifier + '>' + recipient)) {
                return client.getEmail() + ':' + ip + ';' + qualifier + '>' + recipient;
            } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + ip + ';' + qualifier + '>' + recipientDomain)) {
                return client.getEmail() + ':' + ip + ';' + qualifier + '>' + recipientDomain;
            } else if ((cidr = CIDR.get(client, ip)) != null) {
                return cidr;
            }
            whoisSet.add(ip);
            regexSet.add(ip);
        }
        // Verifica um critério do REGEX.
        String regex;
        if ((regex = REGEX.get(client, regexSet)) != null) {
            return regex;
        }
        // Verifica critérios do WHOIS.
        String whois;
        if ((whois = WHOIS.get(client, whoisSet)) != null) {
            return whois;
        }
        return null;
    }
    
    private static boolean containsHost(Client client,
            String host, String qualifier,
            String recipient, String recipientDomain) {
        return findHost(client, host, qualifier, recipient, recipientDomain) != null;
    }

    private static String findHost(Client client,
            String host, String qualifier,
            String recipient, String recipientDomain) {
        do {
            int index = host.indexOf('.') + 1;
            host = host.substring(index);
            String token = '.' + host;
            if (SET.contains(token + ';' + qualifier)) {
                return token + ';' + qualifier;
            } else if (recipient != null && SET.contains(token + ';' + qualifier + '>' + recipient)) {
                return token + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(token + ';' + qualifier + '>' + recipientDomain)) {
                return token + ';' + qualifier + '>' + recipientDomain;
            } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ':' + token + ';' + qualifier)) {
                return client.getEmail() + ':' + token + ';' + qualifier;
            } else if (client != null && client.hasEmail() && recipient != null && SET.contains(client.getEmail() + ':' + token + ';' + qualifier + '>' + recipient)) {
                return client.getEmail() + ':' + token + ';' + qualifier + '>' + recipient;
            } else if (client != null && client.hasEmail() && recipientDomain != null && SET.contains(client.getEmail() + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
                return client.getEmail() + ':' + token + ';' + qualifier + '>' + recipientDomain;
            }
        } while (host.contains("."));
        return null;
    }
    
    private static int parseIntWHOIS(String value) {
        try {
            if (value == null || value.length() == 0) {
                return 0;
            } else {
                Date date = Domain.DATE_FORMATTER.parse(value);
                long time = date.getTime() / (1000 * 60 * 60 * 24);
                long today = System.currentTimeMillis() / (1000 * 60 * 60 * 24);
                return (int) (today - time);
            }
        } catch (Exception ex) {
            try {
                return Integer.parseInt(value);
            } catch (Exception ex2) {
                return 0;
            }
        }
    }

//    private static String findHost(String client,
//            String host, String qualifier,
//            String recipient, String recipientDomain) {
//        host = Domain.extractHost(host, true);
//        if (host == null) {
//            return null;
//        } else {
//            do {
//                int index = host.indexOf('.') + 1;
//                host = host.substring(index);
//                String token = '.' + host;
//                if (SET.contains(token)) {
//                    return token;
//                } else if (SET.contains(token + '>' + recipient)) {
//                    return token + '>' + recipient;
//                } else if (SET.contains(token + '>' + recipientDomain)) {
//                    return token + '>' + recipientDomain;
//                } else if (SET.contains(token + ';' + qualifier)) {
//                    return token + ';' + qualifier;
//                } else if (SET.contains(token + ';' + qualifier + '>' + recipient)) {
//                    return token + ';' + qualifier + '>' + recipient;
//                } else if (SET.contains(token + ';' + qualifier + '>' + recipientDomain)) {
//                    return token + ';' + qualifier + '>' + recipientDomain;
//                } else if (client != null && SET.contains(client + ':' + token)) {
//                    return token;
//                } else if (client != null && SET.contains(client + ':' + token + '>' + recipient)) {
//                    return token + '>' + recipient;
//                } else if (client != null && SET.contains(client + ':' + token + '>' + recipientDomain)) {
//                    return token + '>' + recipientDomain;
//                } else if (client != null && SET.contains(client + ':' + token + ';' + qualifier)) {
//                    return token + ';' + qualifier;
//                } else if (client != null && SET.contains(client + ':' + token + ';' + qualifier + '>' + recipient)) {
//                    return token + ';' + qualifier + '>' + recipient;
//                } else if (client != null && SET.contains(client + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
//                    return token + ';' + qualifier + '>' + recipientDomain;
//                }
//            } while (host.contains("."));
//            return null;
//        }
//    }

    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/white.set");
                TreeSet<String> set = getAll();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(set, outputStream);
                    CHANGED = false;
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
        File file = new File("./data/white.set");
        if (file.exists()) {
            try {
                Set<String> set;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    set = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                // Processo temporário de transição.
                for (String token : set) {
                    String client;
                    String identifier;
                    if (token.contains(":")) {
                        int index = token.indexOf(':');
                        client = token.substring(0, index);
                        identifier = token.substring(index + 1);
                    } else {
                        client = null;
                        identifier = token;
                    }
                    if (Subnet.isValidCIDR(identifier)) {
                        identifier = "CIDR=" + Subnet.normalizeCIDR(identifier);
                    } else if (Owner.isOwnerID(identifier)) {
                        identifier = "WHOIS/ownerid=" + identifier;
                    } else {
                        identifier = normalizeTokenWhite(identifier);
                    }
                    if (identifier != null) {
                        try {
                            if (client == null) {
                                addExact(identifier);
                            } else if (Domain.isEmail(client)) {
                                addExact(client + ':' + identifier);
                            }
                        } catch (ProcessException ex) {
                            Server.logDebug("WHITE CIDR " + identifier + " " + ex.getErrorMessage());
                        }
                    }
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
