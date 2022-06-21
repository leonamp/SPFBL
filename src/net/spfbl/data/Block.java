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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.data;

import net.spfbl.core.Client;
import java.io.BufferedReader;
import net.spfbl.core.Reverse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import net.spfbl.core.Core;
import net.spfbl.core.Peer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isReverseIPv6;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Qualifier;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de bloqueio do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Block {
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    /**
     * Conjunto de remetentes bloqueados.
     */
    private static class SET {
        
        private static final TreeMap<String,Long> MAP = new TreeMap<>();
        
        public static boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
        }
        
        private static Long getTime(String token) {
            return MAP.get(token);
        }
        
        public static synchronized String firstKey() {
            if (MAP.isEmpty()) {
                return null;
            } else {
                return MAP.firstKey();
            }
        }
        
        public static synchronized String higherKey(String token) {
            return MAP.higherKey(token);
        }
        
        private static synchronized void putExact(String token, Long last) {
            MAP.put(token, last);
        }
        
        private static synchronized boolean addExact(String token) {
            return MAP.put(token, TIME) == null;
        }
        
        private static synchronized boolean dropExact(String token) {
            return MAP.remove(token) != null;
        }
        
        private static synchronized void update(String token) {
            MAP.put(token, TIME);
        }
        
        public static boolean contains(String token) {
            Long time = getTime(token);
            if (time == null) {
                return false;
            } else if (time.equals(TIME)) {
                return true;
            } else {
                update(token);
                return CHANGED = true;
            }
        }
        
        public static TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            String token = SET.firstKey();
            while (token != null) {
                set.add(token);
                token = SET.higherKey(token);
            }
            return set;
        }
        
        
        public static TreeSet<String> get(User user) {
            if (user == null) {
                return get((String) null);
            } else {
                return get(user.getEmail());
            }
        }
        
        public static TreeSet<String> get(String user) {
            TreeSet<String> resultSet = new TreeSet<>();
            String token = SET.firstKey();
            while (token != null) {
                if (user == null && !token.contains(":")) {
                    resultSet.add(token);
                } else if (user != null && token.startsWith(user + ':')) {
                    int index = token.indexOf(':');
                    resultSet.add(token.substring(index+1));
                }
                token = SET.higherKey(token);
            }
            return resultSet;
        }
        
        public static int getAll(OutputStream outputStream) throws Exception {
            int count = 0;
            String token = SET.firstKey();
            while (token != null) {
                outputStream.write(token.getBytes("UTF-8"));
                outputStream.write('\n');
                count++;
                token = SET.higherKey(token);
            }
            return count;
        }
        
        public static TreeMap<String,Long> getMap(
                HashSet<String> userSet
        ) {
            long min = TIME - 0x100000000L;
            TreeSet<String> removeSet = new TreeSet<>();
            TreeMap<String,Long> map = new TreeMap<>();
            String token = SET.firstKey();
            while (token != null) {
                Long time = getTime(token);
                if (time == null || time < min) {
                    removeSet.add(token);
                } else {
                    String client = null;
                    int index = token.indexOf(':');
                    if (index > 0) {
                        String clientTemp = token.substring(0, index);
                        if (isValidEmail(clientTemp)) {
                            client = clientTemp;
                        }
                    }
                    if (client != null && !userSet.contains(client)) {
                        removeSet.add(token);
                    } else {
                        map.put(token, time);
                    }
                }
                token = SET.higherKey(token);
            }
            for (String tokenDrop : removeSet) {
                dropExact(tokenDrop);
            }
            return map;
        }
                
        private static Long TIME = System.currentTimeMillis() & 0xFFFFFFFF00000000L;

        private static void refreshTime() {
            long time = System.currentTimeMillis() & 0xFFFFFFFF00000000L;
            if (TIME < time) {
                TIME = time;
            }
        }
        
        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/block.map");
            if (file.exists()) {
                try {
                    Map<String,Long> map;
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
                    }
                    TreeMap<Long,Long> timeMap = new TreeMap<>();
                    timeMap.put(TIME, TIME);
                    for (String token : map.keySet()) {
                        Long last = map.get(token);
                        if (last != null) {
                            last &= 0xFFFFFFFF00000000L;
                            if (timeMap.containsKey(last)) {
                                last = timeMap.get(last);
                            } else {
                                timeMap.put(last, last);
                            }
                            SET.putExact(token, last);
                        }
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        
        public static void store(HashSet<String> userSet) {
            long time = System.currentTimeMillis();
            File file = new File("./data/block.map");
            try {
                TreeMap<String,Long> tokenMap = SET.getMap(userSet);
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(tokenMap, outputStream);
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                refreshTime();
            }
        }
    }
    
    /**
     * Conjunto de critperios WHOIS para bloqueio.
     */
    private static class WHOIS {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
        }
        
        public static synchronized void drop(String client) {
            MAP.remove(client);
        }
        
        private static TreeSet<String> getClientSet(String client) {
            return MAP.get(client);
        }
        
        public static synchronized ArrayList<String> keySet() {
            ArrayList<String> keySet = new ArrayList<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        public static TreeSet<String> get(User user) {
            if (user == null) {
                return get((String) null);
            } else {
                return get(user.getEmail());
            }
        }
        
        public static TreeSet<String> get(String user) {
            TreeSet<String> resultSet = new TreeSet<>();
            TreeSet<String> whoisSet = getClientSet(user);
            if (whoisSet != null) {
                for (String whois : whoisSet) {
                    resultSet.add("WHOIS/" + whois);
                }
            }
            return resultSet;
        }
        
        public static int getAll(OutputStream outputStream) throws Exception {
            int count = 0;
            for (String client : keySet()) {
                TreeSet<String> clientSet = getClientSet(client);
                if (clientSet != null) {
                    for (String whois : clientSet) {
                        if (client != null) {
                            outputStream.write(client.getBytes("UTF-8"));
                            outputStream.write(':');
                        }
                        outputStream.write("WHOIS/".getBytes("UTF-8"));
                        outputStream.write(whois.getBytes("UTF-8"));
                        outputStream.write('\n');
                        count++;
                    }
                }
            }
            return count;
        }
        
        public static TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            for (String client : keySet()) {
                TreeSet<String> clientSet = getClientSet(client);
                if (clientSet != null) {
                    for (String whois : clientSet) {
                        if (client == null) {
                            set.add("WHOIS/" + whois);
                        } else {
                            set.add(client + ":WHOIS/" + whois);
                        }
                    }
                }
            }
            return set;
        }
        
        private static void writeAll(
                HashSet<String> userSet,
                FileWriter writer
        ) throws IOException {
            for (String client : keySet()) {
                if (client != null && !userSet.contains(client)) {
                    drop(client);
                } else {
                    TreeSet<String> clientSet = getClientSet(client);
                    if (clientSet != null) {
                        for (String whois : clientSet) {
                            if (client == null) {
                                writer.write("WHOIS/" + whois + "\n");
                            } else {
                                writer.write(client + ":WHOIS/" + whois + "\n");
                            }
                        }
                    }
                }
            }
        }
        
        private static boolean dropExact(String token) {
            int index = token.indexOf('/');
            String whois = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = getClientSet(client);
            if (set == null) {
                return false;
            } else {
                boolean removed = set.remove(whois);
                if (set.isEmpty()) {
                    drop(client);
                }
                return removed;
            }
        }
        
        private static synchronized boolean addExact(String client, String token) {
            int index = token.indexOf('/');
            String whois = token.substring(index+1);
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                set = new TreeSet<>();
                MAP.put(client, set);
            }
            return set.add(whois);
        }
        
        private static synchronized boolean addExact(String token) {
            int index = token.indexOf('/');
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
                set = new TreeSet<>();
                MAP.put(client, set);
            }
            return set.add(whois);
        }
        
        public static boolean contains(String client, String host) {
            if (host == null) {
                return false;
            } else {
                TreeSet<String> whoisSet = getClientSet(client);
                if (whoisSet == null) {
                    return false;
                } else {
                    return whoisSet.contains(host);
                }
            }
        }
        
        private static String get(
                String client,
                Set<String> tokenSet,
                boolean autoBlock,
                boolean superBlock
        ) {
            if (tokenSet.isEmpty()) {
                return null;
            } else {
                TreeSet<String> subSet = new TreeSet<>();
                if (superBlock) {
                    TreeSet<String> whoisSet = getClientSet(null);
                    if (whoisSet != null) {
                        subSet.addAll(whoisSet);
                    }
                }
                if (client != null) {
                    TreeSet<String> whoisSet = getClientSet(client);
                    if (whoisSet != null) {
                        for (String whois : whoisSet) {
                            subSet.add(client + ':' + whois);
                        }
                    }
                }
                if (subSet.isEmpty()) {
                    return null;
                } else {
                    for (String whois : subSet) {
                        try {
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
                                String userLocal = null;
                                int indexUser = whois.indexOf(':');
                                if (indexUser > 0 && indexUser < indexValue) {
                                    userLocal = whois.substring(0, indexUser);
                                }
                                String key = whois.substring(indexUser + 1, indexValue);
                                String criterion = whois.substring(indexValue + 1);
                                whois = indexUser == -1 ? whois : whois.substring(indexUser+1, whois.length());
                                for (String token : tokenSet) {
                                    String value = null;
                                    if (isValidIP(token)) {
                                        value = Subnet.getValue(token, key);
                                    } else if (token.startsWith(".") && isHostname(token)) {
                                        value = Domain.getValue(token, key);
                                    } else if (!token.startsWith(".") && isHostname(token.substring(1))) {
                                        value = Domain.getValue(token, key);
                                    }
                                    if (value != null) {
                                        if (signal == '=') {
                                            if (criterion.equals(value)) {
                                                if (autoBlock && (token = addDomain(userLocal, token)) != null) {
                                                    if (userLocal == null) {
                                                        Server.logDebug(null, "new BLOCK '" + token + "' added by 'WHOIS/" + whois + "'.");
                                                        Peer.sendBlockToAll(token);
                                                    } else {
                                                        Server.logDebug(null, "new BLOCK '" + userLocal + ":" + token + "' added by '" + userLocal + ":WHOIS/" + whois + "'.");
                                                    }
                                                }
                                                if (userLocal == null) {
                                                    return "WHOIS/" + whois;
                                                } else {
                                                    return userLocal + ":WHOIS/" + whois;
                                                }
                                            }
                                        } else if (value.length() > 0) {
                                            int criterionInt = parseIntWHOIS(criterion);
                                            int valueInt = parseIntWHOIS(value);
                                            if (signal == '<' && valueInt < criterionInt) {
                                                if (autoBlock && (token = addDomain(userLocal, token)) != null) {
                                                    if (userLocal == null) {
                                                        Server.logDebug(null, "new BLOCK '" + token + "' added by 'WHOIS/" + whois + "'.");
                                                        Peer.sendBlockToAll(token);
                                                    } else {
                                                        Server.logDebug(null, "new BLOCK '" + userLocal + ":" + token + "' added by '" + userLocal + ":WHOIS/" + whois + "'.");
                                                    }
                                                }
                                                if (userLocal == null) {
                                                    return "WHOIS/" + whois;
                                                } else {
                                                    return userLocal + ":WHOIS/" + whois;
                                                }
                                            } else if (signal == '>' && valueInt > criterionInt) {
                                                if (autoBlock && (token = addDomain(userLocal, token)) != null) {
                                                    if (userLocal == null) {
                                                        Server.logDebug(null, "new BLOCK '" + token + "' added by 'WHOIS/" + whois + "'.");
                                                        Peer.sendBlockToAll(token);
                                                    } else {
                                                        Server.logDebug(null, "new BLOCK '" + userLocal + ":" + token + "' added by '" + userLocal + ":WHOIS/" + whois + "'.");
                                                    }
                                                }
                                                if (userLocal == null) {
                                                    return "WHOIS/" + whois;
                                                } else {
                                                    return userLocal + ":WHOIS/" + whois;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    return null;
                }
            }
        }
    }
    
    /**
     * Conjunto de DNSBL para bloqueio de IP.
     */
    private static class DNSBL {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
        }
        
        public static synchronized void drop(String client) {
            MAP.remove(client);
        }
        
        public static TreeSet<String> get(User user) {
            if (user == null) {
                return get((String) null);
            } else {
                return get(user.getEmail());
            }
        }
        
        private static TreeSet<String> getClientSet(String client) {
            return MAP.get(client);
        }
        
        public static synchronized ArrayList<String> keySet() {
            ArrayList<String> keySet = new ArrayList<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        public static TreeSet<String> get(String user) {
            TreeSet<String> resultSet = new TreeSet<>();
            TreeSet<String> dnsblSet = getClientSet(user);
            if (dnsblSet != null) {
                for (String dnsbl : dnsblSet) {
                    resultSet.add("DNSBL=" + dnsbl);
                }
            }
            return resultSet;
        }
        
        public static int getAll(OutputStream outputStream) throws Exception {
            int count = 0;
            for (String client : keySet()) {
                TreeSet<String> set = getClientSet(client);
                if (set != null) {
                    for (String dnsbl : set) {
                        if (client != null) {
                            outputStream.write(client.getBytes("UTF-8"));
                            outputStream.write(':');
                        }
                        outputStream.write("DNSBL=".getBytes("UTF-8"));
                        outputStream.write(dnsbl.getBytes("UTF-8"));
                        outputStream.write('\n');
                        count++;
                    }
                }
            }
            return count;
        }
        
        public static TreeSet<String> getAll() {
            TreeSet<String> resultSet = new TreeSet<>();
            for (String client : keySet()) {
                TreeSet<String> clientSet = getClientSet(client);
                if (clientSet != null) {
                    for (String dnsbl : clientSet) {
                        if (client == null) {
                            resultSet.add("DNSBL=" + dnsbl);
                        } else {
                            resultSet.add(client + ":DNSBL=" + dnsbl);
                        }
                    }
                }
            }
            return resultSet;
        }
        
        public static void writeAll(
                HashSet<String> userSet,
                FileWriter writer
        ) throws IOException {
            for (String client : keySet()) {
                if (client != null && !userSet.contains(client)) {
                    drop(client);
                } else {
                    TreeSet<String> clientSet = getClientSet(client);
                    if (clientSet != null) {
                        for (String dnsbl : clientSet) {
                            if (client == null) {
                                writer.write("DNSBL=" + dnsbl + "\n");
                            } else {
                                writer.write(client + ":DNSBL=" + dnsbl + "\n");
                            }
                        }
                    }
                }
            }
        }
        
        private static boolean dropExact(String token) {
            int index = token.indexOf('=');
            String dnsbl = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = getClientSet(client);
            if (set == null) {
                return false;
            } else {
                boolean removed = set.remove(dnsbl);
                if (set.isEmpty()) {
                    drop(client);
                }
                return removed;
            }
        }
        
        private static synchronized boolean addExact(String client, String token) {
            int index = token.indexOf('=');
            String dnsbl = token.substring(index+1);
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                set = new TreeSet<>();
                MAP.put(client, set);
            }
            return set.add(dnsbl);
        }
        
        private static synchronized boolean addExact(String token) {
            int index = token.indexOf('=');
            String dnsbl = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            TreeSet<String> set = MAP.get(client);
            if (set == null) {
                set = new TreeSet<>();
                MAP.put(client, set);
            }
            return set.add(dnsbl);
        }
        
        public static boolean contains(String client, String dnsbl) {
            if (dnsbl == null) {
                return false;
            } else {
                TreeSet<String> dnsblSet = getClientSet(client);
                if (dnsblSet == null) {
                    return false;
                } else {
                    return dnsblSet.contains(dnsbl);
                }
            }
        }
        
        private static String get(String client, String ip) {
            if (ip == null) {
                return null;
            } else if (Provider.containsIPorFQDN(ip)) {
                return null;
            } else if (Ignore.containsIPorFQDN(ip)) {
                return null;
            } else if (White.containsIPorFQDN(ip)) {
                return null;
            } else {
                TreeMap<String,TreeSet<String>> dnsblMap = new TreeMap<>();
                TreeSet<String> registrySet = getClientSet(null);
                if (registrySet != null) {
                    for (String dnsbl : registrySet) {
                        int index = dnsbl.indexOf(';');
                        String server = dnsbl.substring(0, index);
                        String value = dnsbl.substring(index + 1);
                        TreeSet<String> dnsblSet = dnsblMap.get(server);
                        if (dnsblSet == null) {
                            dnsblSet = new TreeSet<>();
                            dnsblMap.put(server, dnsblSet);
                        }
                        dnsblSet.add(value);
                    }
                }
                if (client != null) {
                    registrySet = getClientSet(client);
                    if (registrySet != null) {
                        for (String dnsbl : registrySet) {
                            int index = dnsbl.indexOf(';');
                            String server = dnsbl.substring(0, index);
                            String value = dnsbl.substring(index + 1);
                            TreeSet<String> dnsblSet = dnsblMap.get(server);
                            if (dnsblSet == null) {
                                dnsblSet = new TreeSet<>();
                                dnsblMap.put(server, dnsblSet);
                            }
                            dnsblSet.add(value);
                        }
                    }
                }
                for (String server : dnsblMap.keySet()) {
                    TreeSet<String> valueSet = dnsblMap.get(server);
                    String listed = Reverse.getListedIP(ip, server, null, valueSet);
                    if (listed != null) {
                        Server.logInfo("The IP " + ip + " is listed in '" + server + ";" + listed + "'.");
                        if (client == null) {
                            return "DNSBL=" + server + ";" + listed;
                        } else if ((registrySet = getClientSet(null)) == null) {
                            return client + ":DNSBL=" + server + ";" + listed;
                        } else if (registrySet.contains(server + ";" + listed)) {
                            return "DNSBL=" + server + ";" + listed;
                        } else {
                            return client + ":DNSBL=" + server + ";" + listed;
                        }
                    }
                }
                return null;
            }
        }
    }
    
    /**
     * Conjunto de REGEX para bloqueio.
     */
    private static class REGEX {
        
        private static final HashMap<String,ArrayList<Regex>> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
        }
        
        public static synchronized void drop(String client) {
            MAP.remove(client);
        }
        
        public static TreeSet<String> get(User user) {
            if (user == null) {
                return get((String) null);
            } else {
                return get(user.getEmail());
            }
        }
        
        private static ArrayList<Regex> getClientList(String client) {
            return MAP.get(client);
        }
        
        public static TreeSet<String> get(String user) {
            TreeSet<String> resultSet = new TreeSet<>();
            ArrayList<Regex> patternList = getClientList(user);
            if (patternList != null) {
                for (Regex regex : patternList) {
                    resultSet.add("REGEX=" + regex.pattern());
                }
            }
            return resultSet;
        }
        
        private static synchronized ArrayList<String> getKeySet() {
            ArrayList<String> keySet = new ArrayList<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        public static int getAll(OutputStream outputStream) throws Exception {
            int count = 0;
            for (String client : getKeySet()) {
                ArrayList<Regex> patternList = getClientList(client);
                if (patternList != null) {
                    for (Regex regex : patternList) {
                        if (client != null) {
                            outputStream.write(client.getBytes("UTF-8"));
                            outputStream.write(':');
                        }
                        outputStream.write("REGEX=".getBytes("UTF-8"));
                        outputStream.write(regex.toString().getBytes("UTF-8"));
                        outputStream.write('\n');
                        count++;
                    }
                }
            }
            return count;
        }
        
        public static TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            for (String client : getKeySet()) {
                ArrayList<Regex> patternList = getClientList(client);
                if (patternList != null) {
                    for (Regex regex : patternList) {
                        if (client == null) {
                            set.add("REGEX=" + regex);
                        } else {
                            set.add(client + ":REGEX=" + regex);
                        }
                    }
                }
            }
            return set;
        }
        
        private static void writeAll(
                HashSet<String> userSet,
                FileWriter writer
        ) throws IOException {
            for (String client : getKeySet()) {
                if (client != null && !userSet.contains(client)) {
                    drop(client);
                } else {
                    ArrayList<Regex> patternList = getClientList(client);
                    if (patternList != null) {
                        for (Regex regex : patternList) {
                            if (client == null) {
                                writer.write("REGEX=" + regex + "\n");
                            } else {
                                writer.write(client + ":REGEX=" + regex + "\n");
                            }
                        }
                    }
                }
            }
        }
        
        private static boolean dropExact(String token) {
            if (token == null) {
                return false;
            } else {
                int index = token.indexOf('=');
                String regex = token.substring(index+1);
                index = token.indexOf(':');
                String client;
                if (index == -1) {
                    client = null;
                } else if (isValidEmail(token.substring(0, index))) {
                    client = token.substring(0, index);
                } else {
                    client = null;
                }
                ArrayList<Regex> list = getClientList(client);
                if (list == null) {
                    return false;
                } else {
                    for (index = 0; index < list.size(); index++) {
                        Regex pattern = list.get(index);
                        if (regex.equals(pattern.pattern())) {
                            list.remove(index);
                            if (list.isEmpty()) {
                                drop(client);
                            }
                            return true;
                        }
                    }
                    return false;
                }
            }
        }
        
        private static synchronized boolean addExact(String client, String token) {
            if (token == null) {
                return false;
            } else {
                int index = token.indexOf('=');
                String regex = token.substring(index+1);
                ArrayList<Regex> list = MAP.get(client);
                if (list == null) {
                    list = new ArrayList<>();
                    MAP.put(client, list);
                }
                Regex pattern = new Regex(regex);
                return list.add(pattern);
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
            ArrayList<Regex> list = MAP.get(client);
            if (list == null) {
                list = new ArrayList<>();
                MAP.put(client, list);
            }
            for (index = 0; index < list.size(); index++) {
                Regex pattern = list.get(index);
                if (regex.equals(pattern.pattern())) {
                    return false;
                }
            }
            Regex pattern = new Regex(regex);
            list.add(pattern);
            return true;
        }
        
        public static boolean contains(String client, String regex) {
            if (regex == null) {
                return false;
            } else {
                ArrayList<Regex> patternList = getClientList(client);
                if (patternList == null) {
                    return false;
                } else {
                    for (Regex pattern : patternList) {
                        if (regex.equals(pattern.pattern())) {
                            return true;
                        }
                    }
                }
                return false;
            }
        }
        
        public static String find(String token) {
            if (token == null) {
                return null;
            } else {
                ArrayList<Regex> patternList = getClientList(null);
                if (patternList == null) {
                    return null;
                } else {
                    for (Regex pattern : patternList) {
                        if (pattern.matches(token)) {
                            return "REGEX=" + pattern.pattern();
                        }
                    }
                }
                return null;
            }
        }
        
        private static String get(
                String client,
                Collection<String> tokenList,
                boolean autoBlock
                ) {
            if (tokenList.isEmpty()) {
                return null;
            } else {
                String result = null;
                ArrayList<Regex> patternList = getClientList(null);
                if (patternList != null) {
                    for (Object object : patternList.toArray()) {
                        Regex pattern = (Regex) object;
                        for (String token : tokenList) {
                            if (token.contains("@") == pattern.pattern().contains("@")) {
                                if (pattern.matches(token)) {
                                    String regex = "REGEX=" + pattern.pattern();
                                    if (autoBlock && Block.addExact(token)) {
                                        Server.logDebug(null, "new BLOCK '" + token + "' added by '" + regex + "'.");
                                        if (client == null) {
                                            Peer.sendBlockToAll(token);
                                        }
                                    }
                                    result = regex;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (result == null && client != null) {
                    patternList = getClientList(client);
                    if (patternList != null) {
                        for (Object object : patternList.toArray()) {
                            Regex pattern = (Regex) object;
                            for (String token : tokenList) {
                                if (token.contains("@") == pattern.pattern().contains("@")) {
                                    if (pattern.matches(token)) {
                                        String regex = "REGEX=" + pattern.pattern();
                                        token = client + ":" + token;
                                        if (autoBlock && addExact(token)) {
                                            Server.logDebug(null, "new BLOCK '" + token + "' added by '" + client + ":" + regex + "'.");
                                        }
                                        result = client + ":" + regex;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                return result;
            }
        }
    }
    
    public static boolean dropExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("DNSBL=")) {
            if (DNSBL.dropExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.contains("CIDR=")) {
            if (CIDR.remove(token.substring(5))) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.contains("REGEX=")) {
            if (REGEX.dropExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.contains("WHOIS/")) {
            if (WHOIS.dropExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (SET.dropExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }

    public static boolean dropAll() {
        SET.clear();
        REGEX.clear();
        DNSBL.clear();
        WHOIS.clear();
        CHANGED = true;
        return true;
    }
    
    public static boolean addExact(User user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.addExact(token);
        } else {
            return SET.addExact(user.getEmail() + ":" + token);
        }
    }
    
    public static boolean addExact(String user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.addExact(token);
        } else {
            return SET.addExact(user + ":" + token);
        }
    }
    
   public static boolean addExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS/")) {
            if (WHOIS.addExact(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.contains("DNSBL=")) {
            if (DNSBL.addExact(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.startsWith("CIDR=")) {
            if (CIDR.add(token.substring(5))) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.contains(":CIDR=")) {
            if (SET.addExact(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (token.contains("REGEX=")) {
            if (REGEX.addExact(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (SET.addExact(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> getAll() throws ProcessException {
        TreeSet<String> blockSet = SET.getAll();
        blockSet.addAll(REGEX.getAll());
        blockSet.addAll(DNSBL.getAll());
        blockSet.addAll(WHOIS.getAll());
        return blockSet;
    }
    
    private static void writeAll(
            HashSet<String> userSet,
            FileWriter writer
    ) throws IOException {
        REGEX.writeAll(userSet, writer);
        DNSBL.writeAll(userSet, writer);
        WHOIS.writeAll(userSet, writer);
    }
    
    public static TreeSet<String> get(String user) throws ProcessException {
        TreeSet<String> blockSet = SET.get(user);
        blockSet.addAll(REGEX.get(user));
        blockSet.addAll(DNSBL.get(user));
        blockSet.addAll(WHOIS.get(user));
        return blockSet;
    }
    
    public static boolean containsExact(User user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.contains(token);
        } else {
            return SET.contains(user.getEmail() + ":" + token);
        }
    }
    
    public static boolean containsExact(String user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.contains(token);
        } else {
            return SET.contains(user + ":" + token);
        }
    }
    
    public static boolean containsExactEmail(String email) {
        if (email == null) {
            return false;
        } else {
            return SET.contains(email);
        }
    }

    public static boolean containsExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS/")) {
            int index = token.indexOf('/');
            String whois = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            return WHOIS.contains(client, whois);
        } else if (token.contains("DNSBL=")) {
            int index = token.indexOf('=');
            String dnsbl = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            String client;
            if (index == -1) {
                client = null;
            } else {
                client = token.substring(0, index);
            }
            return DNSBL.contains(client, dnsbl);
        } else if (token.contains("CIDR=")) {
            int index = token.indexOf('=');
            String cidr = token.substring(index+1);
            index = token.lastIndexOf(':', index);
            if (index == -1) {
                return CIDR.contains(cidr);
            } else {
                return SET.contains(token);
            }
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

    private static String addDomain(String user, String token) {
        try {
            if (token == null) {
                return null;
            } else if (token.startsWith("@") && (token = Domain.extractDomain(token.substring(1), true)) != null) {
                if (user == null && addExact(token)) {
                    return token;
                } else if (user != null && addExact(user + ':' + token)) {
                    return user + ':' + token;
                } else {
                    return null;
                }
            } else if (token.startsWith(".") && (token = Domain.extractDomain(token, true)) != null) {
                if (user == null && addExact(token)) {
                    return token;
                } else if (user != null && addExact(user + ':' + token)) {
                    return user + ':' + token;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    private static String normalizeTokenBlock(String token) throws ProcessException {
        if (token == null) {
            return null;
        } else {
            int index = token.indexOf(':');
            if (index > 0 && isValidEmail(token.substring(0, index))) {
                String client = token.substring(0, index).toLowerCase();
                token = token.substring(index + 1);
                token = SPF.normalizeToken(
                        token, true, true, true, true,
                        true, true, true, true, true
                );
                if (token == null) {
                    return null;
                } else {
                    return client + ":" + token;
                }
            } else {
                return SPF.normalizeToken(
                        token, true, true, true, true,
                        true, true, true, true, true
                );
            }
        }
    }
    
    public static boolean tryAdd(String token) {
        try {
            return add(token) != null;
        } catch (ProcessException ex) {
            return false;
        }
    }
    
    public static String addSafe(String token) {
        try {
            if ((token = normalizeTokenBlock(token)) == null) {
                return null;
            } else if (addExact(token)) {
                return token;
            } else {
                return null;
            }
        } catch (ProcessException ex) {
            return null;
        }
    }

    public static String add(String token) throws ProcessException {
        if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addExact(token)) {
            return token;
        } else {
            return null;
        }
    }
    
    public static boolean add(String client, String token) throws ProcessException {
        if (client == null || !isValidEmail(client)) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(client + ':' + token);
        }
    }
    
    public static boolean addSafe(User user, String token) {
        try {
            return add(user, token);
        } catch (ProcessException ex) {
            return false;
        }
    }
    
    public static boolean add(User user, String token) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(user.getEmail() + ":" + token);
        }
    }
    
    public static String addIfNotNull(User user, String token) throws ProcessException {
        if (user == null) {
            return null;
        } else if ((token = normalizeTokenBlock(token)) == null) {
            return null;
        } else if (addExact(user.getEmail() + ":" + token)) {
            return user.getEmail() + ":" + token;
        } else {
            return null;
        }
    }

    public static boolean add(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(client.getEmail() + ':' + token);
        }
    }

    public static boolean drop(String token) throws ProcessException {
        if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (dropExact(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean drop(String client, String token) throws ProcessException {
        if (client == null || !isValidEmail(client)) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(client + ':' + token);
        }
    }
    
    public static boolean drop(User user, String token) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(user.getEmail() + ':' + token);
        }
    }

    public static boolean drop(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenBlock(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(client.getEmail() + ':' + token);
        }
    }

    public static TreeSet<String> get(Client client, User user) throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<>();
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail != null) {
            for (String token : get(userEmail)) {
                int index = token.indexOf(':') + 1;
                token = token.substring(index);
                blockSet.add(token);
            }
        }
        return blockSet;
    }
    
    public static TreeSet<String> getSet(User user) throws ProcessException {
        return SET.get(user);
    }

    public static TreeSet<String> getAll(Client client, User user) throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<>();
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        for (String token : getAll()) {
            if (!token.contains(":")) {
                blockSet.add(token);
            } else if (userEmail != null && token.startsWith(userEmail + ':')) {
                int index = token.indexOf(':') + 1;
                token = token.substring(index);
                blockSet.add(token);
            }
        }
        return blockSet;
    }

    public static TreeSet<String> getAllTokens(String value) {
        TreeSet<String> blockSet = new TreeSet<>();
        if (isValidIP(value)) {
            String ip = Subnet.normalizeIP(value);
            if (SET.contains(ip)) {
                blockSet.add(ip);
            }
        } else if (isValidCIDR(value)) {
            String cidr = Subnet.normalizeCIDR(value);
            if (CIDR.contains(cidr)) {
                blockSet.add(cidr);
            }
            TreeSet<String> set = SET.getAll();
            for (String ip : set) {
                if (Subnet.containsIP(cidr, ip)) {
                    blockSet.add(ip);
                }
            }
            for (String ip : set) {
                if (SubnetIPv6.containsIP(cidr, ip)) {
                    blockSet.add(ip);
                }
            }
        } else if (isHostname(value)) {
            LinkedList<String> regexList = new LinkedList<>();
            String host = Domain.normalizeHostname(value, true);
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                if (Block.dropExact('.' + host)) {
                    blockSet.add('.' + host);
                    regexList.addFirst('.' + host);
                }
            } while (host.contains("."));
        } else if (SET.contains(value)) {
            blockSet.add(value);
        }
        return blockSet;
    }
    
    public static int getAll(OutputStream outputStream) throws Exception {
        int count = SET.getAll(outputStream);
        count += REGEX.getAll(outputStream);
        count += DNSBL.getAll(outputStream);
        count += WHOIS.getAll(outputStream);
        outputStream.flush();
        return count;
    }
    
    public static int get(OutputStream outputStream) throws IOException {
        int count = 0;
        TreeSet<String> set;
        if ((set = SET.get((User) null)) != null) {
            for (String token : set) {
                outputStream.write(token.getBytes("UTF-8"));
                outputStream.write('\n');
                outputStream.flush();
                count++;
            }
        }
        if ((set = REGEX.get((User) null)) != null) {
            for (String token : set) {
                outputStream.write(token.getBytes("UTF-8"));
                outputStream.write('\n');
                outputStream.flush();
                count++;
            }
        }
        if ((set = DNSBL.get((User) null)) != null) {
            for (String token : set) {
                outputStream.write(token.getBytes("UTF-8"));
                outputStream.write('\n');
                outputStream.flush();
                count++;
            }
        }
        if ((set = WHOIS.get((User) null)) != null) {
            for (String token : set) {
                outputStream.write(token.getBytes("UTF-8"));
                outputStream.write('\n');
                outputStream.flush();
                count++;
            }
        }
        return count;
    }

    public static TreeSet<String> get() throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<>();
        for (String token : getAll()) {
            if (!token.contains(":")) {
                blockSet.add(token);
            }
        }
        return blockSet;
    }
    
    public static boolean addEmail(String email, String cause) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return false;
        } else if (SET.addExact(email)) {
            Server.logDebug(null, "new BLOCK '" + email + "' caused by '" + cause + "'.");
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean addFQDN(String host, String cause) {
        if ((host = Domain.extractHost(host, true)) == null) {
            return false;
        } else if (Ignore.containsFQDN(host)) {
            return false;
        } else if (Provider.containsFQDN(host)) {
            return false;
        } else if (SET.addExact(host)) {
            Server.logDebug(null, "new BLOCK '" + host + "' caused by '" + cause + "'.");
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean clearFQDN(Long timeKey, String host, String cause) {
        if ((host = Domain.extractHost(host, true)) == null) {
            return false;
        } else {
            boolean dropped = SET.dropExact(host);
            int index;
            while ((index = host.indexOf('.', 1)) > 0) {
                host = host.substring(index);
                if (SET.dropExact(host)) {
                    Server.logDebug(timeKey, "false positive FQDN '" + host + "' detected by '" + cause + "'.");
                    dropped = true;
                }
            }
            return dropped;
        }
    }
    
    public static void clear(long timeKey, String token, String cause) {
        try {
            if (isValidIPv4(token)) {
                String ip = SubnetIPv4.normalizeIPv4(token);
                if (Block.clearCIDR(ip, 32) != null) {
                    Server.logDebug(timeKey, "false positive BLOCK '" + ip + "/32' detected by '" + cause + "'.");
                }
                String block;
                for (String token2 : Reverse.getPointerSetSafe(ip)) {
                    while ((block = Block.find(null, null, token2, false, true, true, false)) != null) {
                        if (Block.dropExact(block)) {
                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + cause + "'.");
                        }
                    }
                }
            } else if (isValidIPv6(token)) {
                String ip = SubnetIPv6.normalizeIPv6(token);
                if (Block.clearCIDR(ip, 64) != null) {
                    Server.logDebug(timeKey, "false positive BLOCK '" + ip + "/64' detected by '" + cause + "'.");
                }
                String block;
                for (String token2 : Reverse.getPointerSetSafe(ip)) {
                    while ((block = Block.find(null, null, token2, false, true, true, false)) != null) {
                        if (Block.dropExact(block)) {
                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + cause + "'.");
                        }
                    }
                }
            }
            TreeSet<String> blockSet = new TreeSet<>();
            String block;
            while ((block = Block.find(null, null, token, false, true, true, false)) != null) {
                if (blockSet.contains(block)) {
                    throw new ProcessException("FATAL BLOCK ERROR " + block);
                } else if (Block.dropExact(block)) {
                    Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + cause + "'.");
                }
                blockSet.add(block);
            }
        } catch (ProcessException ex) {
            Server.logError(ex);
        }
    }
    
    public static void clearHREF(long timeKey, User user, String token, String name) {
        try {
            TreeSet<String> blockSet = new TreeSet<>();
            String block;
            while ((block = findHREF(timeKey, null, user, token, true, false)) != null) {
                if (blockSet.contains(block)) {
                    throw new ProcessException("FATAL BLOCK ERROR " + block);
                } else if (dropExact(block)) {
                    Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + name + "'.");
                }
                blockSet.add(block);
            }
        } catch (ProcessException ex) {
            Server.logError(ex);
        }
    }
    
    public static String clearCIDR(String ip, int mask) {
        if (isValidIP(ip)) {
            String cidr = Subnet.normalizeCIDR(ip + "/" + mask);
            if (CIDR.remove(cidr)) {
                return "CIDR=" + cidr;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    public static boolean clearCIDR(Long timeKey, String ip, String cause) {
        if (ip == null) {
            return false;
        } else {
            String block;
            int mask = isValidIPv4(ip) ? 32 : 128;
            if ((block = Block.clearCIDR(ip, mask)) != null) {
                Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + cause + "'.");
                for (String token : Reverse.getPointerSetSafe(ip)) {
                    while ((block = Block.find(null, null, token, false, true, true, false)) != null) {
                        if (Block.dropExact(block)) {
                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + cause + "'.");
                        }
                    }
                }
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static String find(
            User user,
            String token,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS
            )  {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        }
        return find(userEmail, token, findDNSBL, findREGEX, findWHOIS, false);
    }
    
    public static String findHREF(
            Long timeKey,
            User user,
            String token,
            boolean findIP
            )  {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        }
        return findHREF(timeKey, userEmail, token, findIP, true);
    }
    
    public static String findHREF(
            Long timeKey,
            String userEmail,
            String token,
            boolean findIP
            )  {
        return findHREF(timeKey, userEmail, token, findIP, true);
    }
    
    public static String find(
            User user,
            String token,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS,
            boolean autoBlock
            ) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        }
        return find(userEmail, token, findDNSBL, findREGEX, findWHOIS, autoBlock);
    }
    
    public static String find(
            Client client,
            User user,
            String token,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS,
            boolean autoBlock
            ) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return find(userEmail, token, findDNSBL, findREGEX, findWHOIS, autoBlock);
    }
    
    public static String findHREF(
            Long timeKey,
            Client client,
            User user,
            String token,
            boolean findIP,
            boolean autoBlock
            ) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return findHREF(timeKey, userEmail, token, findIP, autoBlock);
    }
    
    public static String find(
            String userEmail,
            String token,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS,
            boolean autoBlock
            ) {
        TreeSet<String> whoisSet = new TreeSet<>();
        LinkedList<String> regexList = new LinkedList<>();
        if (token == null) {
            return null;
        } else if (Domain.isMailFrom(token)) {
            String sender = Domain.normalizeEmail(token);
            if (sender != null) {
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (SET.contains(sender)) {
                    return sender;
                } else if (userEmail != null && SET.contains(userEmail + ':' + sender)) {
                    return userEmail + ':' + sender;
                } else if (SET.contains(part)) {
                    return part;
                } else if (userEmail != null && SET.contains(userEmail + ':' + part)) {
                    return userEmail + ':' + part;
                } else if (SET.contains(senderDomain)) {
                    return senderDomain;
                } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain)) {
                    return userEmail + ':' + senderDomain;
                } else {
                    int index3 = senderDomain.length();
                    while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = senderDomain.substring(0, index3 + 1);
                        if (SET.contains(subdomain)) {
                            return subdomain;
                        } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain)) {
                            return userEmail + ':' + subdomain;
                        }
                    }
                    String host = '.' + senderDomain.substring(1);
                    do {
                        int index = host.indexOf('.') + 1;
                        host = host.substring(index);
                        String token2 = '.' + host;
                        if (SET.contains(token2)) {
                            return token2;
                        } else if (userEmail != null && SET.contains(userEmail + ':' + token2)) {
                            return userEmail + ':' + token2;
                        }
                        regexList.addFirst(token2);
                    } while (host.contains("."));
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (SET.contains(subsender)) {
                            return subsender;
                        } else if (userEmail != null && SET.contains(userEmail + ':' + subsender)) {
                            return userEmail + ':' + subsender;
                        }
                    }
                }
                if (senderDomain.endsWith(".br")) {
                    whoisSet.add(senderDomain);
                }
                regexList.add(sender);
            }
        } else if (isValidIP(token)) {
            token = Subnet.normalizeIP(token);
            String cidr;
            String dnsbl;
            if (SET.contains(token)) {
                return token;
            } else if (userEmail != null && SET.contains(userEmail + ':' + token)) {
                return userEmail + ':' + token;
            } else if (userEmail == null && (cidr = CIDR.get(token)) != null) {
                return "CIDR=" + cidr;
            } else if (findDNSBL && (dnsbl = DNSBL.get(userEmail, token)) != null) {
                return dnsbl;
            }
            regexList.add(token);
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (SET.contains(token2)) {
                    return token2;
                } else if (userEmail != null && SET.contains(userEmail + ':' + token2)) {
                    return userEmail + ':' + token2;
                }
                regexList.addFirst(token2);
            } while (host.contains("."));
            if (token.endsWith(".br")) {
                whoisSet.add(token);
            }
        } else {
            regexList.add(token);
        }
        if (findREGEX) {
            try {
                // Verifica um critério do REGEX.
                String regex;
                if ((regex = REGEX.get(userEmail, regexList, autoBlock)) != null) {
                    return regex;
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (findWHOIS) {
            try {
                // Verifica critérios do WHOIS.
                String whois;
                if ((whois = WHOIS.get(userEmail, whoisSet, autoBlock, true)) != null) {
                    return whois;
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        return null;
    }
    
    public static String findHREF(
            Long timeKey,
            String userEmail,
            String token,
            boolean findIP,
            boolean autoBlock
            ) {
        if (token == null) {
            return null;
        } else if (Domain.isMailFrom(token)) {
            String sender = Domain.normalizeEmail(token);
            if (sender != null) {
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (SET.contains("HREF=" + sender)) {
                    return "HREF=" + sender;
                } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + sender)) {
                    return userEmail + ":HREF=" + sender;
                } else if (SET.contains("HREF=" + part)) {
                    return "HREF=" + part;
                } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + part)) {
                    return userEmail + ":HREF=" + part;
                } else if (SET.contains("HREF=" + senderDomain)) {
                    return "HREF=" + senderDomain;
                } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + senderDomain)) {
                    return userEmail + ":HREF=" + senderDomain;
                } else {
                    int index3 = senderDomain.length();
                    while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = senderDomain.substring(0, index3 + 1);
                        if (SET.contains("HREF=" + subdomain)) {
                            return "HREF=" + subdomain;
                        } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + subdomain)) {
                            return userEmail + ":HREF=" + subdomain;
                        }
                    }
                    String host = '.' + senderDomain.substring(1);
                    do {
                        int index = host.indexOf('.') + 1;
                        host = host.substring(index);
                        String token2 = '.' + host;
                        if (SET.contains("HREF=" + token2)) {
                            return "HREF=" + token2;
                        } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + token2)) {
                            return userEmail + ":HREF=" + token2;
                        }
                    } while (host.contains("."));
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (SET.contains("HREF=" + subsender)) {
                            return "HREF=" + subsender;
                        } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + subsender)) {
                            return userEmail + ":HREF=" + subsender;
                        }
                    }
                }
                String ownerID = Domain.getOwnerID(senderDomain);
                if (ownerID != null) {
                    if (SET.contains("HREF=" + ownerID)) {
                        if (autoBlock && SET.addExact("HREF=" + sender)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + sender + "' added by 'HREF=" + ownerID + "'.");
                        }
                        return "HREF=" + ownerID;
                    } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + ownerID)) {
                        if (autoBlock && SET.addExact(userEmail + ":HREF=" + sender)) {
                            Server.logDebug(timeKey, "new BLOCK '" + userEmail + ":HREF=" + sender + "' added by '" + userEmail + ":HREF=" + ownerID + "'.");
                        }
                        return userEmail + ":HREF=" + ownerID;
                    }
                }
            }
        } else if (isValidIP(token)) {
            token = Subnet.normalizeIP(token);
            if (SET.contains("HREF=" + token)) {
                return "HREF=" + token;
            } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + token)) {
                return userEmail + ":HREF=" + token;
            }
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (SET.contains("HREF=" + token2)) {
                    return "HREF=" + token2;
                } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + token2)) {
                    return userEmail + ":HREF=" + token2;
                }
            } while (host.contains("."));
            String ownerID = Domain.getOwnerID(token);
            if (ownerID != null) {
                if (SET.contains("HREF=" + ownerID)) {
                    if (autoBlock && SET.addExact("HREF=" + token)) {
                        Server.logDebug(timeKey, "new BLOCK 'HREF=" + token + "' added by 'HREF=" + ownerID + "'.");
                    }
                    return "HREF=" + ownerID;
                } else if (userEmail != null && SET.contains(userEmail + ":HREF=" + ownerID)) {
                    if (autoBlock && SET.addExact(userEmail + ":HREF=" + token)) {
                        Server.logDebug(timeKey, "new BLOCK '" + userEmail + ":HREF=" + token + "' added by '" + userEmail + ":HREF=" + ownerID + "'.");
                    }
                    return userEmail + ":HREF=" + ownerID;
                }
            }
            if (findIP) {
                for (String ip : Reverse.getAddressSetSafe(token)) {
                    if (SET.contains("HREF=" + ip)) {
                        if (autoBlock && SET.addExact("HREF=" + token)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + token + "' added by 'HREF=" + ip + "'.");
                        }
                        return "HREF=" + ip;
                    }
                }
            }
        }
        return null;
    }
    
    
    public static void clearSafe(
            Long timeKey,
            Client client,
            User user,
            String ip,
            String helo,
            String sender,
            String hostname,
            Qualifier qualifier,
            String recipient,
            String cause
            ) {
        try {
            if (qualifier == null) {
                clear(timeKey, client, user, ip, helo, sender, hostname, "NONE", recipient, cause);
            } else {
                clear(timeKey, client, user, ip, helo, sender, hostname, qualifier.getResult(), recipient, cause);
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    public static void clear(
            Long timeKey,
            Client client,
            User user,
            String ip,
            String helo,
            String sender,
            String hostname,
            String qualifier,
            String recipient,
            String cause
            ) throws ProcessException {
        String userEmail = null;
        boolean canClear = true;
        if (user != null) {
            userEmail = user.getEmail();
            canClear = user.canClearBLOCK();
        } else if (client != null) {
            userEmail = client.getEmail();
            canClear = !NoReply.contains(userEmail, false);
        }
        if (canClear) {
            clear(timeKey, userEmail, ip, sender, hostname, qualifier, recipient);
        }
        if (Core.hasAdminEmail()) {
            String banKey = Block.getBannedKey(
                    (User) null, ip, helo, hostname,
                    sender, qualifier, null
            );
            if (SET.dropExact(banKey)) {
                Server.logDebug(timeKey, "false positive BLOCK '" + banKey + "' detected by '" + cause + "'.");
            }
            banKey = Block.getBannedKey(
                    (User) null, ip, helo, hostname,
                    sender, qualifier, recipient
            );
            if (SET.dropExact(banKey)) {
                Server.logDebug(timeKey, "false positive BLOCK '" + banKey + "' detected by '" + cause + "'.");
            }
        }
        if (client != null && client.hasEmail()) {
            String banKey = Block.getBannedKey(
                    client, ip, helo, hostname,
                    sender, qualifier, recipient
            );
            if (SET.dropExact(banKey)) {
                Server.logDebug(timeKey, "false positive BLOCK '" + banKey + "' detected by '" + cause + "'.");
            }
        }
    }
    
    public static void clear(
            Long timeKey,
            String userEmail,
            String ip,
            String sender,
            String hostname,
            String qualifier,
            String recipient
            ) throws ProcessException {
        String block = Block.getBlockKey(
                userEmail, ip, hostname, recipient
        );
        if (Block.dropExact(block)) {
            if (userEmail == null) {
                Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected.");
            } else {
                Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
            }
        }
        int mask = isValidIPv4(ip) ? 32 : 64;
        if ((block = Block.clearCIDR(ip, mask)) != null) {
            if (userEmail == null) {
                Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected.");
            } else {
                Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
            }
            TreeSet<String> tokenSet = Reverse.getPointerSetSafe(ip);
            if (hostname != null) {
                tokenSet.add(hostname);
            }
            for (String token : tokenSet) {
                while ((block = Block.find(null, null, token, false, true, true, false)) != null) {
                    if (Block.dropExact(block)) {
                        if (userEmail == null) {
                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected.");
                        } else {
                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
                        }
                    }
                }
            }
        }
        TreeSet<String> blockSet = new TreeSet<>();
        while ((block = find(userEmail, ip, sender, hostname, qualifier, recipient, true, false, false, true, true, false)) != null) {
            if (blockSet.contains(block)) {
                throw new ProcessException("FATAL BLOCK ERROR " + block);
            } else if (dropExact(block)) {
                if (userEmail == null) {
                    Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected.");
                } else {
                    Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
                }
            }
            blockSet.add(block);
        }
    }
    
    public static boolean contains(String token) {
        if (token == null) {
            return false;
        } else if (isHostname(token)) {
            String hostname = Domain.normalizeHostname(token, true);
            return Block.containsDomain(hostname, false);
        } else if (isValidEmail(token)) {
            token = Domain.normalizeEmail(token);
            if (Block.containsExact(token)) {
                return true;
            } else {
                int index = token.indexOf('@') + 1;
                String hostname = '.' + token.substring(index);
                return Block.containsDomain(hostname, false);
            }
        } else {
            return false;
        }
    }
    
    public static boolean contains(User user, String token) {
        if (token == null) {
            return false;
        } else if (isHostname(token)) {
            String hostname = Domain.normalizeHostname(token, true);
            return Block.containsDomain(user, hostname, false);
        } else if (isValidEmail(token)) {
            token = Domain.normalizeEmail(token);
            if (Block.containsExact(user, token)) {
                return true;
            } else {
                int index = token.indexOf('@') + 1;
                String hostname = '.' + token.substring(index);
                return Block.containsDomain(user, hostname, false);
            }
        } else {
            return false;
        }
    }

    public static boolean contains(
            Client client, User user,
            String ip, String sender, String helo,
            String qualifier, String recipient,
            boolean findReverse, boolean findCIDR, boolean findDNSBL,
            boolean findREGEX, boolean findWHOIS, boolean autoblock
            ) throws ProcessException {
        return find(
                client, user, ip, sender, helo, qualifier, recipient,
                findReverse, findCIDR, findDNSBL, findREGEX, findWHOIS, autoblock
        ) != null;
    }
    
    public static String getBlockKey(
            String userEmail,
            String ip,
            String hostname,
            String recipient
            ) {
        if (userEmail == null) {
            userEmail = "";
        } else {
            userEmail += ":";
        }
        if (recipient == null) {
            recipient = "";
        } else {
            recipient = ">" + recipient;
        }
        if (hostname == null) {
            return userEmail + "@;" + ip + recipient;
        } else {
            return userEmail + "@;" + hostname + recipient;
        }
    }
    
    public static boolean isBannedIP(String ip) {
        if (ip == null) {
            return false;
        } else {
            String key;
            String admin = Core.getAdminEmail();
            if (admin == null) {
                key = "@;" + ip + ">@";
            } else {
                key = admin + ":@;" + ip + ">@";
            }
            return SET.contains(key);
        }
    }
    
    public static boolean isBannedFQDN(String fqdn) {
        if (fqdn == null) {
            return false;
        } else {
            String key;
            String admin = Core.getAdminEmail();
            if (admin == null) {
                key = "@;" + fqdn + ">@";
            } else {
                key = admin + ":@;" + fqdn + ">@";
            }
            return SET.contains(key);
        }
    }
    
    public static boolean isBanned(
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            SPF.Qualifier qualifier,
            String recipient
    ) {
        if (Core.hasAdminEmail()) {
            String result;
            if (qualifier == null) {
                result = "NONE";
            } else {
                result = qualifier.name();
            }
            String key = keyBlockKey(
                    Core.getAdminEmail(),
                    ip, helo, sender,
                    fqdn, result, "@"
            );
            if (SET.contains(key)) {
                return true;
            }
        }
        if (recipient == null) {
            return false;
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
            String key = keyBlockKey(
                    user, ip, helo, fqdn, sender,
                    qualifier, recipient
            );
            return SET.contains(key);
        }
    }
    
    public static boolean isBanned(
            Client client,
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (Core.hasAdminEmail()) {
            String key = keyBlockKey(
                    Core.getAdminEmail(),
                    ip, helo, sender,
                    fqdn, result, "@"
            );
            if (SET.contains(key)) {
                return true;
            }
        }
        if (client != null && client.hasEmail()) {
            String key = keyBlockKey(
                    client.getEmail(),
                    ip, helo, sender,
                    fqdn, result, "@"
            );
            if (SET.contains(key)) {
                return true;
            } else if (client.isBanActive()) {
                for (String cidr : Subnet.getRangeArray(ip)) {
                    if (Block.containsExact(client.getEmail() + ":CIDR=" + cidr)) {
                        return true;
                    }
                }
            }
        }
        if (recipient == null) {
            return false;
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
            String key = keyBlockedKey(
                    user, ip, helo, fqdn, sender,
                    result, recipient
            );
            return SET.contains(key);
        }
    }
    
    public static boolean isBanned(
            String userEmail,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (Core.hasAdminEmail()) {
            String key = keyBlockKey(
                    Core.getAdminEmail(),
                    ip, helo, sender,
                    fqdn, result, "@"
            );
            if (SET.contains(key)) {
                return true;
            }
        }
        if (recipient == null) {
            return false;
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
            String key = keyBlockedKey(
                    userEmail, ip, helo, fqdn, sender,
                    result, recipient
            );
            return SET.contains(key);
        }
    }
    
    public static String findBannedKey(
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        String key = Block.getBannedKey(
                user, ip, helo, fqdn, sender, result, recipient
        );
        if (SET.contains(key)) {
            return key;
        } else {
            return null;
        }
    }
    
    public static String getBannedKey(
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (recipient == null) {
            recipient = "@";
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
        }
        String key = keyBlockedKey(
                user, ip, helo, fqdn, sender,
                result, recipient
        );
        return key;
    }
    
    public static String getBannedKey(
            Client client,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (recipient == null) {
            recipient = "@";
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
        }
        String key = keyBlockedKey(
                client, ip, helo, fqdn, sender,
                result, recipient
        );
        return key;
    }
    
    public static String keyBlockKey(
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            SPF.Qualifier qualifier,
            String recipient
    ) {
        if (qualifier == null) {
            return keyBlockKey(
                    null, user, ip, helo, sender,
                    fqdn, "NONE", recipient
            );
        } else {
            return keyBlockKey(
                    null, user, ip, helo, sender,
                    fqdn, qualifier.name(), recipient
            );
        }
    }
    
    public static String keyBlockedKey(
            User user,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (result == null) {
            return keyBlockKey(
                    null, user, ip, helo, sender,
                    fqdn, "NONE", recipient
            );
        } else {
            return keyBlockKey(
                    null, user, ip, helo, sender,
                    fqdn, result, recipient
            );
        }
    }
    
    public static String keyBlockedKey(
            Client client,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (result == null) {
            return keyBlockKey(
                    client, null, ip, helo, sender,
                    fqdn, "NONE", recipient
            );
        } else {
            return keyBlockKey(
                    client, null, ip, helo, sender,
                    fqdn, result, recipient
            );
        }
    }
    
    public static String keyBlockedKey(
            String userEmail,
            String ip,
            String helo,
            String fqdn,
            String sender,
            String result,
            String recipient
    ) {
        if (result == null) {
            return keyBlockKey(
                    userEmail, ip, helo, sender,
                    fqdn, "NONE", recipient
            );
        } else {
            return keyBlockKey(
                    userEmail, ip, helo, sender,
                    fqdn, result, recipient
            );
        }
    }
    
    public static boolean ban(
            Client client,
            User user,
            String ip,
            String helo,
            String sender,
            String hostname,
            String result,
            String recipient
    ) {
        if (recipient == null) {
            return false;
        } else if (sender == null && Provider.containsFQDN(hostname)) {
            return false;
        } else if (sender != null && Provider.containsDomain(sender)) {
            return false;
        } else {
            int index = recipient.indexOf('@');
            recipient = recipient.substring(index);
            String key = keyBlockKey(
                    client,
                    user,
                    ip,
                    helo,
                    sender,
                    hostname,
                    result,
                    recipient
            );
            return SET.addExact(key);
        }
    }
    
    public static boolean addBlockKey(
            Long timeKey,
            Client client,
            User user,
            String ip,
            String helo,
            String sender,
            String fqdn,
            String result,
            String recipient,
            String cause
    ) {
        if (result == null) {
            result = "NONE";
        }
        if (Provider.containsFQDN(fqdn)) {
            return false;
        } else if (result.equals("PASS") && Provider.containsDomain(sender) && !Provider.isFreeMail(sender)) {
            return false;
        } else {
            String key = keyBlockKey(
                    client, user, ip, helo,
                    sender, fqdn, result, recipient
            );
            if (Block.addExact(key)) {
                Server.logDebug(timeKey, "new BLOCK '" + key + "' added by '" + cause + "'.");
                return true;
            } else {
                return false;
            }
        }
    }

     public static String keyBlockKey(
            Client client,
            User user,
            String ip,
            String helo,
            String sender,
            String fqdn,
            String result,
            String recipient
    ) {
        String userEmail;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        } else {
            userEmail = Core.getAdminEmail();
        }
        return keyBlockKey(
                userEmail, ip, helo, sender,
                fqdn, result, recipient
        );
    }
     
    public static String keyBlockKey(
            String userEmail,
            String ip,
            String helo,
            String sender,
            String fqdn,
            Qualifier qualifier,
            String recipient
    ) {
        return keyBlockKey(
                userEmail,
                ip,
                helo,
                sender,
                fqdn,
                qualifier == null ? "NONE" : qualifier.name(),
                recipient
        );
    }
    
    public static String keyBlockKey(
            String userEmail,
            String ip,
            String helo,
            String sender,
            String fqdn,
            String result,
            String recipient
    ) {
        if (userEmail == null) {
            userEmail = "";
        } else {
            userEmail += ":";
        }
        if (recipient == null) {
            recipient = "";
        } else {
            recipient = ">" + recipient;
        }
        if (result == null) {
            result = "NONE";
        }
        if (sender == null || sender.length() == 0) {
            String mask;
            String domain = Domain.extractDomainSafe(fqdn, false);
            if (domain != null) {
                return userEmail + "mailer-daemon@" + domain + recipient;
            } else if (Generic.containsMask(mask = Generic.convertHostToMask(helo))) {
                mask = mask.replace('#', '0');
                mask = mask.substring(1);
                return userEmail + "mailer-daemon@" + mask + recipient;
            } else {
                return userEmail + "mailer-daemon@;" + ip + recipient;
            }
        } else {
            sender = sender.toLowerCase();
            if (sender.endsWith("@gmail.com") && sender.contains("+caf_=")) {
                sender = Domain.normalizeEmail(sender);
            } else if (sender.startsWith("srs0=") || sender.startsWith("srs0+")) {
                int index1 = sender.lastIndexOf('@');
                int index2 = sender.lastIndexOf('=', index1);
                if (index2 > 0) {
                    int index3 = sender.lastIndexOf('=', index2-1);
                    if (index3 > 0) {
                        String part = sender.substring(index2+1, index1);
                        String domain = sender.substring(index3+1, index2);
                        sender = part + '@' + domain;
                        result = "NOTPASS";
                    }
                }
            }
            int index = sender.lastIndexOf('@') + 1;
            String senderDomain = '@' + sender.substring(index);
            if (Provider.containsExact(senderDomain)) {
                if (result.equals("PASS")) {
                    sender = Domain.normalizeEmail(sender);
                    if (sender == null) {
                        return userEmail + senderDomain + recipient;
                    } else {
                        return userEmail + sender + recipient;
                    }
                } else {
                    String domain = Domain.extractDomainSafe(fqdn, false);
                    if (domain != null) {
                        if (Provider.containsFQDN(fqdn)) {
                            sender = Domain.normalizeEmail(sender);
                            if (sender == null) {
                                return userEmail + senderDomain + ";" + domain + recipient;
                            } else {
                                return userEmail + sender + ";" + domain + recipient;
                            }
                        } else if (NoReply.containsFQDN(domain)) {
                            return userEmail + "@;" + domain + recipient;
                        } else {
                            return userEmail + senderDomain + ";" + domain + recipient;
                        }
                    } else if (NoReply.containsFQDN(helo)) {
                        return userEmail + senderDomain + ";NONE" + recipient;
                    } else {
                        return userEmail + senderDomain + ";NOTPASS" + recipient;
                    }
                }
            } else if (Provider.containsFQDN(fqdn)) {
                String domain1 = Domain.extractDomainSafe(fqdn, false);
                String validation;
                if (result.equals("PASS")) {
                    validation = "";
                } else if (senderDomain.substring(1).equals(domain1)) {
                    validation = "";
                } else if (domain1 != null) {
                    validation = ";" + domain1;
                } else {
                    validation = ";BULK";
                }
                String domain2 = Domain.extractDomainSafe(
                        senderDomain.substring(1), true
                );
                if (domain2 == null || Provider.containsExact(domain2)) {
                    return userEmail + senderDomain + validation + recipient;
                } else {
                    return userEmail + domain2 + validation + recipient;
                }
            } else {
                String domain1 = Domain.extractDomainSafe(fqdn, false);
                if (!result.equals("PASS")) {
                    String domain2 = domain1;
                    if (domain2 == null) {
                        domain2 = Domain.extractDomainSafe(helo, false);
                        if (domain2 == null || net.spfbl.data.Domain.isInexistent(domain2)) {
                            domain2 = Domain.extractDomainSafe(Reverse.getHostname(ip), false);
                        }
                    }
                    if (NoReply.containsFQDN(domain2)) {
                        return userEmail + "@;" + domain2 + recipient;
                    }
                }
                String validation;
                if (result.equals("NONE")) {
                    validation = ";NONE";
                } else if (result.equals("PASS")) {
                    validation = "";
                } else if (senderDomain.substring(1).equals(domain1)) {
                    validation = "";
                } else if (result.equals("FAIL") && Ignore.containsExact(senderDomain)) {
                    validation = ";FAIL";
                } else if (NoReply.containsExact('.' + senderDomain.substring(1))) {
                    validation = "";
                } else if (domain1 != null) {
                    validation = ";" + domain1;
                } else if (result.equals("FAIL")) {
                    validation = ";FAIL";
                } else if (recipient.endsWith(senderDomain)) {
                    // Forged sender.
                    validation = ";NONE";
                } else if (!isHostname(helo)) {
                    validation = ";NONE";
                } else if (NoReply.containsFQDN(helo)) {
                    validation = ";NONE";
                } else if (SubnetIPv6.isSLAAC(ip)) {
                    validation = ";NONE";
                } else {
                    validation = ";NOTPASS";
                }
                String domain3 = Domain.extractDomainSafe(
                        senderDomain.substring(1), true
                );
                if (domain3 == null || Provider.containsExact(domain3)) {
                    return userEmail + senderDomain + validation + recipient;
                } else if (validation.equals(";" + domain3.substring(1))) {
                    return userEmail + domain3 + recipient;
                } else {
                    return userEmail + domain3 + validation + recipient;
                }
            }
        }
    }
    
    public static String find(
            Client client,
            User user,
            String ip,
            String sender,
            String hostname,
            String qualifier,
            String recipient,
            boolean findReverse,
            boolean findCIDR,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS,
            boolean autoblock
            ) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return find(
                userEmail, ip, sender, hostname, qualifier, recipient,
                findReverse, findCIDR, findDNSBL, findREGEX, findWHOIS, autoblock
        );
    }

    public static String find(
            String userEmail,
            String ip,
            String sender,
            String hostname,
            String qualifier,
            String recipient,
            boolean findReverse,
            boolean findCIDR,
            boolean findDNSBL,
            boolean findREGEX,
            boolean findWHOIS,
            boolean autoblock
            ) {
        if (sender == null && hostname != null) {
            try {
                String domain = Domain.extractDomain(hostname, false);
                sender = "mailer-daemon@" + domain;
            } catch (Exception ex) {
                sender = null;
            }
        }
        TreeSet<String> whoisSet = new TreeSet<>();
        TreeSet<String> regexSet = new TreeSet<>();
        // Definição do destinatário.
        String recipientDomain;
        if (recipient != null && recipient.contains("@")) {
            int index = recipient.indexOf('@');
            recipient = recipient.toLowerCase();
            if (Core.isAbuseEmail(recipient) || (recipient.startsWith("postmaster@") && !recipient.equals(userEmail))) {
                // Não pode haver bloqueio para o postmaster, admin e abuse,
                // exceto se o bloqueio for especifico destes.
                String mx = Domain.extractHost(sender, true);
                String token = (Provider.containsExact(mx) ? sender : mx) + ">" + recipient;
                if (Block.containsExact(userEmail, token)) {
                    return userEmail == null ? token : userEmail + ":" + token;
                } else {
                    return null;
                }
            } else {
                recipientDomain = recipient.substring(index);
            }
        } else {
            recipient = null;
            recipientDomain = null;
        }
        String found;
        if (findCIDR && (found = Block.findCIDR(ip)) != null) {
            return found;
        } else if ((found = findSender(userEmail, sender, qualifier,
                recipient, recipientDomain, whoisSet, regexSet)) != null) {
            return found;
        } else if (!qualifier.equals("NONE") && !qualifier.equals("PASS")
                && (found = findSender(userEmail, sender, "NOTPASS",
                recipient, recipientDomain, whoisSet, regexSet)) != null) {
            return found;
        } else if ((found = findSender(userEmail, sender, ip,
                recipient, recipientDomain, whoisSet, regexSet)) != null) {
            return found;
        }
        // Verifica o HELO.
        if ((hostname = Domain.extractHost(hostname, true)) != null) {
            if ((found = findHost(userEmail, sender, hostname, qualifier,
                    recipient, recipientDomain, whoisSet, regexSet,
                    FQDN.isFQDN(ip, hostname)
            )) != null) {
                return found;
            }
            if (hostname.endsWith(".br")) {
                whoisSet.add(hostname);
            }
            regexSet.add(hostname);
        }
        // Verifica o IP.
        if (ip != null) {
            ip = Subnet.normalizeIP(ip);
            String cidr;
            String dnsbl;
            if (SET.contains(ip)) {
                return ip;
            } else if (recipient != null && SET.contains(ip + '>' + recipient)) {
                return ip + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(ip + '>' + recipientDomain)) {
                return ip + '>' + recipientDomain;
            } else if (SET.contains(ip + ';' + qualifier)) {
                return ip + ';' + qualifier;
            } else if (recipient != null && SET.contains(ip + ';' + qualifier + '>' + recipient)) {
                return ip + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(ip + ';' + qualifier + '>' + recipientDomain)) {
                return ip + ';' + qualifier + '>' + recipientDomain;
            } else if (userEmail == null && sender == null & SET.contains("mailer-daemon@;" + ip)) {
                return "mailer-daemon@;" + ip;
            } else if (userEmail != null && sender == null & SET.contains(userEmail + ":mailer-daemon@;" + ip)) {
                return userEmail + ":mailer-daemon@;" + ip;
            } else if (userEmail != null && SET.contains(userEmail + ":@;" + ip)) {
                return userEmail + ":@;" + ip;
            } else if (userEmail != null && SET.contains(userEmail + ':' + ip)) {
                return userEmail + ':' + ip;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + ip + '>' + recipient)) {
                return userEmail + ':' + ip + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + ip + '>' + recipientDomain)) {
                return userEmail + ':' + ip + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + ip + ';' + qualifier)) {
                return userEmail + ':' + ip + ';' + qualifier;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + ip + ';' + qualifier + '>' + recipient)) {
                return userEmail + ':' + ip + ';' + qualifier + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + ip + ';' + qualifier + '>' + recipientDomain)) {
                return userEmail + ':' + ip + ';' + qualifier + '>' + recipientDomain;
            } else if (userEmail == null && (cidr = CIDR.get(ip)) != null) {
                return "CIDR=" + cidr;
            } else if (findDNSBL && !Provider.contains(hostname) && !Ignore.contains(hostname) && (dnsbl = DNSBL.get(userEmail, ip)) != null) {
                return dnsbl;
            }
            regexSet.add(ip);
        }
        if (findREGEX) {
            try {
                // Verifica um critério do REGEX.
                String regex;
                if ((regex = REGEX.get(userEmail, regexSet, autoblock)) != null) {
                    return regex;
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (findWHOIS) {
            try {
                // Verifica critérios do WHOIS.
                String whois;
                if ((whois = WHOIS.get(userEmail, whoisSet, autoblock,  true)) != null) {
                    return whois;
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        return null;
    }
    
    public static String findSender(
            String userEmail,
            String sender,
            String validation,
            String recipient,
            String recipientDomain,
            TreeSet<String> whoisSet,
            TreeSet<String> regexSet
    ) {
        // Verifica o remetente.
        if (sender != null && sender.contains("@")) {
            sender = sender.toLowerCase();
            if (sender.startsWith("srs0=") || sender.startsWith("srs0+")) {
                int index = sender.lastIndexOf('@');
                String senderOriginal = sender.substring(0, index);
                if (senderOriginal.startsWith("srs0+")) {
                    senderOriginal = senderOriginal.replaceFirst("^srs0\\+", "srs0=");
                }
                StringTokenizer tokenizer = new StringTokenizer(senderOriginal, "=");
                if (tokenizer.countTokens() == 5) {
                    tokenizer.nextToken();
                    tokenizer.nextToken();
                    tokenizer.nextToken();
                    String senderDomain = tokenizer.nextToken();
                    String part = tokenizer.nextToken();
                    senderOriginal = part + '@' + senderDomain;
                    String block = Block.find(userEmail, senderOriginal, false, true, true, false);
                    if (block != null) {
                        return block;
                    }
                }
            }
            if (sender.endsWith("@gmail.com") && sender.contains("+caf_=")) {
                // Gmail forward pattern.
                int index0 = sender.indexOf('+');
                int index1 = sender.lastIndexOf('@');
                String part = sender.substring(0, index0);
                String domain = sender.substring(index1 + 1);
                String senderOriginal = part + '@' + domain;
                String block = Block.find(userEmail, senderOriginal, false, true, true, false);
                if (block == null) {
                    int index2 = sender.lastIndexOf('=', index1);
                    if (index2 > 0) {
                        int index3 = sender.lastIndexOf('=', index2-1);
                        if (index3 > 0) {
                            domain = sender.substring(index2+1, index1);
                            part = sender.substring(index3+1, index2);
                            senderOriginal = part + '@' + domain;
                            block = Block.find(userEmail, senderOriginal, false, true, true, false);
                        }
                    }
                }
                if (block != null) {
                    return block;
                }
            }
            String normalized = Domain.normalizeEmail(sender);
            sender = normalized == null ? sender : normalized;
            int index1 = sender.indexOf('@');
            int index2 = sender.lastIndexOf('@');
            String part = sender.substring(0, index1 + 1);
            String senderDomain = sender.substring(index2);
            String host;
            if (SET.contains(sender)) {
                return sender;
            } else if (SET.contains(sender + '>' + recipient)) {
                return sender + '>' + recipient;
            } else if (SET.contains(sender + '>' + recipientDomain)) {
                return sender + '>' + recipientDomain;
            } else if (SET.contains(sender + ';' + validation + '>' + recipient)) {
                return sender + ';' + validation + '>' + recipient;
            } else if (SET.contains(sender + ';' + validation + '>' + recipientDomain)) {
                return sender + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(sender + ';' + validation)) {
                return sender + ';' + validation;
            } else if (SET.contains(sender + ';' + validation + '>' + recipient)) {
                return sender + ';' + validation + '>' + recipient;
            } else if (SET.contains(sender + ';' + validation + '>' + recipientDomain)) {
                return sender + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender)) {
                return userEmail + ':' + sender;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + '>' + recipient)) {
                return userEmail + ':' + sender + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + '>' + recipientDomain)) {
                return userEmail + ':' + sender + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + ';' + validation)) {
                return userEmail + ':' + sender + ';' + validation;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + sender + ';' + validation + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + sender + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(part)) {
                return part;
            } else if (SET.contains(part + '>' + recipient)) {
                return part + '>' + recipient;
            } else if (SET.contains(part + '>' + recipientDomain)) {
                return part + '>' + recipientDomain;
            } else if (SET.contains(part + ';' + validation)) {
                return part + ';' + validation;
            } else if (SET.contains(part + ';' + validation + '>' + recipient)) {
                return part + ';' + validation + '>' + recipient;
            } else if (SET.contains(part + ';' + validation + '>' + recipientDomain)) {
                return part + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part)) {
                return userEmail + ':' + part;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + '>' + recipient)) {
                return userEmail + ':' + part + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + '>' + recipientDomain)) {
                return userEmail + ':' + part + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + ';' + validation)) {
                return userEmail + ':' + part + ';' + validation;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + part + ';' + validation + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + part + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(senderDomain)) {
                return senderDomain;
            } else if (SET.contains(senderDomain + '>' + recipient)) {
                return senderDomain + '>' + recipient;
            } else if (SET.contains(senderDomain + '>' + recipientDomain)) {
                return senderDomain + '>' + recipientDomain;
            } else if (SET.contains(senderDomain + ';' + validation)) {
                return senderDomain + ';' + validation;
            } else if (SET.contains(senderDomain + ';' + validation + '>' + recipient)) {
                return senderDomain + ';' + validation + '>' + recipient;
            } else if (SET.contains(senderDomain + ';' + validation + '>' + recipientDomain)) {
                return senderDomain + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain)) {
                return userEmail + ':' + senderDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + '>' + recipient)) {
                return userEmail + ':' + senderDomain + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + '>' + recipientDomain)) {
                return userEmail + ':' + senderDomain + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation)) {
                return userEmail + ':' + senderDomain + ';' + validation;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + senderDomain + ';' + validation + '>' + recipient;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + senderDomain + ';' + validation + '>' + recipientDomain;
            } else if ((host = findHost(userEmail, sender, "." + senderDomain.substring(1), validation, recipient, recipientDomain, whoisSet, regexSet, false)) != null) {
                return host;
            } else if (recipient != null && SET.contains("@>" + recipient)) {
                return "@>" + recipient;
            } else if (recipientDomain != null && SET.contains("@>" + recipientDomain)) {
                return "@>" + recipientDomain;
            } else if (recipient != null && userEmail != null && SET.contains(userEmail + ":@>" + recipient)) {
                return userEmail + ":@>" + recipient;
            } else if (recipientDomain != null && userEmail != null && SET.contains(userEmail + ":@>" + recipientDomain)) {
                return userEmail + ":@>" + recipientDomain;
            } else if (recipient != null && SET.contains("@;" + validation)) {
                return "@;" + validation;
            } else if (recipient != null && SET.contains("@;" + validation + ">" + recipient)) {
                return "@;" + validation + ">" + recipient;
            } else if (recipientDomain != null && SET.contains("@;" + validation + ">" + recipientDomain)) {
                return "@;" + validation + ">" + recipientDomain;
            } else if (recipient != null && userEmail != null && SET.contains(userEmail + ":@;" + validation)) {
                return userEmail + ":@;" + validation;
            } else if (recipient != null && userEmail != null && SET.contains(userEmail + ":@;" + validation + ">" + recipient)) {
                return userEmail + ":@;" + validation +  ">" + recipient;
            } else if (recipientDomain != null && userEmail != null && SET.contains(userEmail + ":@;" + validation + ">" + recipientDomain)) {
                return userEmail + ":@;" + validation +  ">" + recipientDomain;
            } else {
                int index3 = senderDomain.length();
                while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = senderDomain.substring(0, index3 + 1);
                    if (SET.contains(subdomain)) {
                        return subdomain;
                    } else if (SET.contains(subdomain + '>' + recipient)) {
                        return subdomain + '>' + recipient;
                    } else if (SET.contains(subdomain + '>' + recipientDomain)) {
                        return subdomain + '>' + recipientDomain;
                    } else if (SET.contains(subdomain + ';' + validation)) {
                        return subdomain + ';' + validation;
                    } else if (SET.contains(subdomain + ';' + validation + '>' + recipient)) {
                        return subdomain + ';' + validation + '>' + recipient;
                    } else if (SET.contains(subdomain + ';' + validation + '>' + recipientDomain)) {
                        return subdomain + ';' + validation + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain)) {
                        return userEmail + ':' + subdomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + '>' + recipient)) {
                        return userEmail + ':' + subdomain + '>' + recipient;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + '>' + recipientDomain)) {
                        return userEmail + ':' + subdomain + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + ';' + validation)) {
                        return userEmail + ':' + subdomain + ';' + validation;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + ';' + validation + '>' + recipient)) {
                        return userEmail + ':' + subdomain + ';' + validation + '>' + recipient;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + ';' + validation + '>' + recipientDomain)) {
                        return userEmail + ':' + subdomain + ';' + validation + '>' + recipientDomain;
                    }
                }
                int index4 = sender.length();
                while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                    String subsender = sender.substring(0, index4 + 1);
                    if (SET.contains(subsender)) {
                        return subsender;
                    } else if (SET.contains(subsender + '>' + recipient)) {
                        return subsender + '>' + recipient;
                    } else if (SET.contains(subsender + '>' + recipientDomain)) {
                        return subsender + '>' + recipientDomain;
                    } else if (SET.contains(subsender + ';' + validation)) {
                        return subsender + ';' + validation;
                    } else if (SET.contains(subsender + ';' + validation + '>' + recipient)) {
                        return subsender + ';' + validation + '>' + recipient;
                    } else if (SET.contains(subsender + ';' + validation + '>' + recipientDomain)) {
                        return subsender + ';' + validation + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender)) {
                        return userEmail + ':' + subsender;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + '>' + recipient)) {
                        return userEmail + ':' + subsender + '>' + recipient;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + '>' + recipientDomain)) {
                        return userEmail + ':' + subsender + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + ';' + validation)) {
                        return userEmail + ':' + subsender + ';' + validation;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipient)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipient;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain;
                    }
                }
            }
            if (senderDomain.endsWith(".br")) {
                whoisSet.add(senderDomain);
            }
            regexSet.add(sender);
            regexSet.add(senderDomain);
        }
        return null;
    }
    
    public static boolean containsSignatureBlockURL(String token) {
        return getSignatureBlockURL(token) != null;
    }
    
    public static String getSignatureBlockURL(String token) {
        if (token == null) {
            return null;
        } else {
            Matcher matcher = Core.URL_SIGNATURE_PATTERN.createMatcher(token);
            if (matcher.find()) {
                String signature = matcher.group(1);
                if (containsExact(signature)) {
                    return signature;
                } else {
                    String host = matcher.group(2).substring(1);
                    Core.URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                    if (isValidIPv4(host)) {
                        host = SubnetIPv4.reverseToIPv4(host);
                    } else if (isReverseIPv6(host)) {
                        host = SubnetIPv6.reverseToIPv6(host);
                        host = SubnetIPv6.tryTransformToIPv4(host);
                    }
                    if (containsHREF(host)) {
                        return host;
                    } else {
                        return null;
                    }
                }
            } else {
                Core.URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                return null;
            }
        }
    }
    
    public static boolean containsHREF(String token) {
        if (isValidIP(token)) {
            String ip = Subnet.normalizeIP(token);
            return SET.contains("HREF=" + ip);
        } else if (isHostname(token)) {
            String host = Domain.normalizeHostname(token, true);
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (SET.contains("HREF=" + token2)) {
                    return true;
                }
            } while (host.contains("."));
            String ownerID = Domain.getOwnerID(token);
            if (ownerID != null) {
                if (SET.contains("HREF=" + ownerID)) {
                    if (SET.addExact("HREF=" + token)) {
                        Server.logDebug(null, "new BLOCK 'HREF=" + token + "' added by 'HREF=" + ownerID + "'.");
                    }
                    return true;
                }
            }
        } else if (isValidEmail(token)) {
            if ((token = Domain.normalizeEmail(token)) == null) {
                return false;
            } else if (SET.contains("HREF=" + token)) {
                return true;
            } else {
                int index = token.indexOf('@');
                if (SET.contains("HREF=" + token.substring(index))) {
                    return true;
                } else {
                    return containsHREF(token.substring(index + 1));
                }
            }
        }
        return false;
    }
    
    public static boolean containsHostnameHREF(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return false;
        } else {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (SET.contains("HREF=" + token)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }
    }
    
    public static boolean containsFastHREF(String token) {
        if (isValidIP(token)) {
            String ip = Subnet.normalizeIP(token);
            return SET.contains("HREF=" + ip);
        } else if (isHostname(token)) {
            String host = Domain.normalizeHostname(token, true);
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (SET.contains("HREF=" + token2)) {
                    return true;
                }
            } while (host.contains("."));
        } else if (isValidEmail(token)) {
            token = Domain.normalizeEmail(token);
            if (SET.contains("HREF=" + token)) {
                return true;
            } else {
                int index = token.indexOf('@');
                if (SET.contains("HREF=" + token.substring(index))) {
                    return true;
                } else {
                    return containsFastHREF(token.substring(index + 1));
                }
            }
        }
        return false;
    }
    
    public static boolean containsFQDNFromIP(String ip) {
        String fqdn = FQDN.getFQDN(ip);
        if (fqdn == null) {
            return false;
        } else if (SET.contains(fqdn)) {
            return true;
        } else {
            int index;
            while ((index = fqdn.indexOf('.', 1)) > 0) {
                fqdn = fqdn.substring(index);
                if (SET.contains(fqdn)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean containsIPorFQDN(String ip) {
        if (ip == null) {
            return false;
        } else if (CIDR.get(ip) == null) {
            String fqdn = FQDN.getFQDN(ip, false);
            if (fqdn == null) {
                return false;
            } else if (SET.contains(fqdn)) {
                return true;
            } else {
                int index;
                while ((index = fqdn.indexOf('.', 1)) > 0) {
                    fqdn = fqdn.substring(index);
                    if (SET.contains(fqdn)) {
                        return true;
                    }
                }
                return false;
            }
        } else {
            return true;
        }
    }
    
    public static boolean containsCIDR(InetAddress address) {
        if (address instanceof Inet4Address) {
            String ip = SubnetIPv4.normalizeIPv4(address.getHostAddress());
            return CIDR.contains(ip);
        } else if (address instanceof Inet6Address) {
            String ip = SubnetIPv6.normalizeIPv6(address.getHostAddress());
            return CIDR.contains(ip);
        } else {
            return false;
        }
    }
    
    public static boolean containsCIDR(String ip) {
        return CIDR.contains(ip);
    }
    
    public static boolean containsIP(String ip) {
        return CIDR.containsIP(ip);
    }
    
    public static String findCIDR(String ip) {
        String cidr = CIDR.get(ip);
        if (cidr == null) {
            return null;
        } else {
            return "CIDR=" + cidr;
        }
    }
    
    public static boolean containsDNSBL(String ip) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return false;
        } else {
            return DNSBL.get(null, ip) != null;
        }
    }
    
    public static String findDNSBL(String ip) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            return DNSBL.get(null, ip);
        }
    }

    private static int parseIntWHOIS(String value) {
        try {
            if (value == null || value.length() == 0) {
                return 0;
            } else {
                Date date = new SimpleDateFormat("yyyyMMdd").parse(value);
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
    
    public static boolean containsDomain(String host, boolean href) {
        return containsDomain((String) null, host, href);
    }
    
    public static boolean containsDomain(User user, String host, boolean href) {
        if (user == null) {
            return containsDomain((String) null, host, href);
        } else {
            return containsDomain(user.getEmail(), host, href);
        }
    }
    
    public static boolean containsDomain(String client, String host, boolean href) {
        host = Domain.extractHost(host, true);
        if (host == null) {
            return false;
        } else {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (SET.contains(token)) {
                    return true;
                } else if (client != null && SET.contains(client + ':' + token)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }
    }
    
    public static String returnBlockedPTR(Set<String> tokenSet) {
        if (tokenSet == null) {
            return null;
        } else {
            for (String token : tokenSet) {
                if (containsFQDN(token)) {
                    return token;
                }
            }
            return null;
        }
    }
    
    public static boolean containsFQDN(String fqdn) {
        if ((fqdn = Domain.extractHost(fqdn, true)) == null) {
            return false;
        } else if (SET.contains(fqdn)) {
            return true;
        } else {
            int index;
            while ((index = fqdn.indexOf('.', 1)) > 0) {
                fqdn = fqdn.substring(index);
                if (SET.contains(fqdn)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean matchesWithText(User user, String text)  {
        if (text == null) {
            return false;
        } else if (user == null) {
            return false;
        } else {
            LinkedList<String> textList = new LinkedList<>();
            textList.add(Core.removerAcentuacao(text));
            return REGEX.get(user.getEmail(), textList, false) != null;
        }
    }
    
    public static String getREGEX(User user, String text)  {
        if (text == null) {
            return null;
        } else if (user == null) {
            return null;
        } else {
            LinkedList<String> textList = new LinkedList<>();
            textList.add(Core.removerAcentuacao(text));
            return REGEX.get(user.getEmail(), textList, false);
        }
    }
    
    public static boolean containsWHOIS(String host) {
        host = Domain.extractHost(host, true);
        if (host == null) {
            return false;
        } else if (host.endsWith(".br")) {
            try {
                TreeSet<String> tokenSet = new TreeSet<>();
                tokenSet.add(host);
                return WHOIS.get(null, tokenSet, true, true) != null;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    public static boolean containsWHOIS(User user, String host) {
        return getWHOIS(user, host) != null;
    }
    
    public static String getWHOIS(User user, String host) {
        String userEmail = user == null ? null : user.getEmail();
        return getWHOIS(userEmail, host);
    }
    
    public static String getWHOIS(String userEmail, String host) {
        if ((host = Domain.extractHost(host, true)) == null) {
            return null;
        } else if (host.endsWith(".br")) {
            try {
                TreeSet<String> tokenSet = new TreeSet<>();
                tokenSet.add(host);
                return WHOIS.get(userEmail, tokenSet, true, false);
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        } else {
            return null;
        }
    }

    private static String findHost(
            String userEmail, String sender,
            String hostname, String qualifier, String recipient,
            String recipientDomain, TreeSet<String> whoisSet,
            TreeSet<String> regexSet, boolean full
    ) {
        hostname = Domain.extractHost(hostname, true);
        if (hostname == null) {
            return null;
        } else {
            do {
                int index = hostname.indexOf('.') + 1;
                hostname = hostname.substring(index);
                String token = '.' + hostname;
                if (SET.contains(token)) {
                    return token;
                } else if (SET.contains(token + '>' + recipient)) {
                    return token + '>' + recipient;
                } else if (SET.contains(token + '>' + recipientDomain)) {
                    return token + '>' + recipientDomain;
                } else if (SET.contains(token + ';' + qualifier)) {
                    return token + ';' + qualifier;
                } else if (SET.contains(token + ';' + qualifier + '>' + recipient)) {
                    return token + ';' + qualifier + '>' + recipient;
                } else if (SET.contains(token + ';' + qualifier + '>' + recipientDomain)) {
                    return token + ';' + qualifier + '>' + recipientDomain;
                } else if (userEmail != null && SET.contains(userEmail + ":@;" + token)) {
                    return userEmail + ":@;" + token;
                } else if (userEmail != null && SET.contains(userEmail + ':' + token)) {
                    return userEmail + ':' + token;
                } else if (userEmail != null  && SET.contains(userEmail + ':' + token + '>' + recipient)) {
                    return userEmail + ':' + token + '>' + recipient;
                } else if (userEmail != null  && SET.contains(userEmail + ':' + token + '>' + recipientDomain)) {
                    return userEmail + ':' + token + '>' + recipientDomain;
                } else if (userEmail != null  && SET.contains(userEmail + ':' + token + ';' + qualifier)) {
                    return userEmail + ':' + token + ';' + qualifier;
                } else if (userEmail != null  && SET.contains(userEmail + ':' + token + ';' + qualifier + '>' + recipient)) {
                    return userEmail + ':' + token + ';' + qualifier + '>' + recipient;
                } else if (userEmail != null  && SET.contains(userEmail + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
                    return userEmail + ':' + token + ';' + qualifier + '>' + recipientDomain;
                } else if (full && (token = findSender(userEmail, sender, hostname, recipient,
                        recipientDomain, whoisSet, regexSet)) != null) {
                    return token;
                }
            } while (hostname.contains("."));
            return null;
        }
    }

    public static void store() {
        if (!Core.isRunning()) {
            CHANGED = true;
        }
        if (CHANGED) {
            HashSet<String> userSet = Core.getUserClientSet();
            SET.store(userSet);
            long time = System.currentTimeMillis();
            File file = new File("./data/block.txt");
            try (FileWriter writer = new FileWriter(file)) {
                writeAll(userSet, writer);
                THREAD.store(writer);
                Server.logStore(time, file);
                file = new File("./data/block.set");
                file.delete();
            } catch (Exception ex) {
                Server.logError(ex);
            }
            CHANGED = false;
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file1 = new File("./data/block.txt");
        File file2 = new File("./data/block.set");
        if (file1.exists()) {
            String token;
            try (BufferedReader reader = new BufferedReader(new FileReader(file1))) {
                while ((token = reader.readLine()) != null) {
                    try {
                        if (token.startsWith("QUEUE=")) {
                            addOperation(token.substring(6), null);
                        } else {
                            String client;
                            String identifier;
                            if (token.contains(":")) {
                                int index = token.indexOf(':');
                                client = token.substring(0, index);
                                if (isValidEmail(client)) {
                                    identifier = token.substring(index + 1);
                                } else {
                                    client = null;
                                    identifier = token;
                                }
                            } else {
                                client = null;
                                identifier = token;
                            }
                            if (identifier.startsWith("CIDR=")) {
                                CIDR.add(client == null ? identifier.substring(5) : null);
                            } else if (identifier.startsWith("WHOIS/")) {
                                WHOIS.addExact(client, identifier);
                            } else if (identifier.startsWith("DNSBL=")) {
                                DNSBL.addExact(client, identifier);
                            } else if (identifier.startsWith("REGEX=")) {
                                REGEX.addExact(client, normalizeTokenBlock(identifier));
                            } else if (identifier.contains("+") || identifier.contains("@gmail.com")) {
                                SET.addExact(normalizeTokenBlock(identifier));
                            } else {
                                SET.addExact(token);
                            }
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                CHANGED = false;
                Server.logLoad(time, file1);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        } else if (file2.exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file2)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                for (String token : set) {
                    try {
                        String client;
                        String identifier;
                        if (token.contains(":")) {
                            int index = token.indexOf(':');
                            client = token.substring(0, index);
                            if (isValidEmail(client)) {
                                identifier = token.substring(index + 1);
                            } else {
                                client = null;
                                identifier = token;
                            }
                        } else {
                            client = null;
                            identifier = token;
                        }
                        if (identifier.startsWith("CIDR=")) {
                            CIDR.add(client == null ? identifier.substring(5) : null);
                        } else if (identifier.startsWith("WHOIS/")) {
                            WHOIS.addExact(client, identifier);
                        } else if (identifier.startsWith("DNSBL=")) {
                            DNSBL.addExact(client, identifier);
                        } else if (identifier.startsWith("REGEX=")) {
                            REGEX.addExact(client, identifier);
                        } else if (identifier.contains("+") || identifier.contains("@gmail.com")) {
                            SET.addExact(normalizeTokenBlock(identifier));
                        } else {
                            SET.addExact(token);
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                CHANGED = false;
                Server.logLoad(time, file2);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        SET.load();
    }
    
    public static boolean tryToDominoBlockIP(String ip, String cause) {
        if (ip == null) {
            return false;
        } else if (Abuse.containsSubscribedIP(ip)) {
            return false;
        } else if (Ignore.containsIPorFQDN(ip)) {
            return false;
        } else if (Provider.containsIPorFQDN(ip)) {
            return false;
        } else if (White.containsIPorFQDN(ip)) {
            return false;
        } else if (ip.contains(":")) {
            String cidr = ip + "/64";
            if (!CIDR.containsCIDRv6(cidr)) {
                if (SubnetIPv6.isSLAAC(ip)) {
                    cidr = ip + "/48";
                } else {
                    cidr = ip + "/52";
                }
                if (CIDR.addCIDRv6(cidr)) {
                    Server.logDebug(null, "new BLOCK '" + cidr + "' added by '" + cause + "'.");
                    return true;
                }
            }
            return false;
        } else if (CIDR.addIPv4(ip)) {
            Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + cause + "'.");
            addOperation(ip, null);
            return true;
        } else {
            return false;
        }
    }
    
    private static boolean tryToBlockIP(String ip) {
        if (Abuse.containsSubscribedIP(ip)) {
            return false;
        } else {
            String fqdn = FQDN.getFQDN(ip, true);
            if (fqdn == null) {
                TreeSet<String> ptrSet = Reverse.getPointerSetSafe(ip);
                if (ptrSet.isEmpty()) {
                    if (CIDR.addIP(ip)) {
                        Server.logDebug(null, "new BLOCK '" + ip + "' added by 'NONE'.");
                        return true;
                    }
                } else {
                    for (String ptr : ptrSet) {
                        if (Ignore.containsFQDN(ptr) && FQDN.addFQDN(ip, ptr, true)) {
                            return false;
                        } else if (Generic.isDynamicPattern(ptr)) {
                            if (CIDR.addIP(ip)) {
                                Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + ptr + ";DYNAMIC'.");
                                return true;
                            }
                        } else if (Generic.containsGenericFQDN(ptr)) {
                            if (CIDR.addIP(ip)) {
                                Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + ptr + ";GENERIC'.");
                                return true;
                            }
                        } else if (Provider.containsFQDN(ptr) && FQDN.addFQDN(ip, ptr, true)) {
                            return false;
                        } else if (Block.containsFQDN(ptr)) {
                            if (CIDR.addIP(ip)) {
                                Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + ptr + ";BLOCK'.");
                                return true;
                            }
                        } else if (NoReply.containsFQDN(ptr)) {
                            if (CIDR.addIP(ip)) {
                                Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + ptr + ";COMPLIANCE'.");
                                return true;
                            }
                        } else if (Reputation.isHarmful(ip, ptr)) {
                            if (CIDR.addIP(ip)) {
                                Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + ptr + ";HARMFUL'.");
                                return true;
                            }
                        }
                    }
                    for (String ptr : ptrSet) {
                        if (FQDN.addFQDN(ip, ptr, true)) {
                            return false;
                        }
                    }
                    if (CIDR.addIP(ip)) {
                        Server.logDebug(null, "new BLOCK '" + ip + "' added by 'INVALID'.");
                        return true;
                    }
                }
            } else if (Block.containsFQDN(fqdn)) {
                if (CIDR.addIP(ip)) {
                    Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + fqdn + ";BLOCK'.");
                    return true;
                }
            } else if (NoReply.containsFQDN(fqdn)) {
                if (CIDR.addIP(ip)) {
                    Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + fqdn + ";COMPLIANCE'.");
                    return true;
                }
            } else if (Reputation.isHarmful(ip, fqdn)) {
                if (CIDR.addIP(ip)) {
                    Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + fqdn + ";HARMFUL'.");
                    return true;
                }
            } else if (Abuse.isHarmful(ip, fqdn)) {
                if (CIDR.addIP(ip)) {
                    String abuse = Abuse.getEmail(ip, fqdn);
                    Server.logDebug(null, "new BLOCK '" + ip + "' added by '" + abuse + ";HARMFUL'.");
                    return true;
                }
            }
            return false;
        }
    }
    
    private static boolean addOperation(String ip, Byte value) {
        if (ip == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(ip, value));
            return true;
        }
    }
    
    private static final ProcessThread THREAD = new ProcessThread();
    
    public static void startThread() {
        THREAD.start();
    }
    
    public static void terminateThread() {
        THREAD.terminate();
    }
    
    public static boolean offer(long time, User.Query query) {
        if (query == null) {
            return false;
        } else if (System.currentTimeMillis() - time > Server.WEEK_TIME) {
            return false;
        } else if (query.isSenderAdvised()) {
            return false;
        } else if (!query.isResult("BLOCK")) {
            return false;
        } else {
            THREAD.put(time, query);
            return true;
        }
    }
    
    private static class ProcessThread extends Thread {
        
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private final TreeMap<Long,Query> MAP = new TreeMap<>();
        private boolean run = true;
        
        private synchronized void put(long time, Query query) {
            MAP.put(time, query);
            notify();
        }
        
        private synchronized Entry<Long,Query> pollQuery() {
            return MAP.pollFirstEntry();
        }
        
        private synchronized boolean isEmptyQuery() {
            return MAP.isEmpty();
        }
        
        private ProcessThread() {
            super("BLOKTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private synchronized void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notify();
        }
        
        private synchronized SimpleImmutableEntry poll() {
            return QUEUE.poll();
        }
        
        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        private synchronized boolean continueRun() {
            return run;
        }
        
        public synchronized void terminate() {
            run = false;
            notify();
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String ip = entry.getKey();
                    writer.write("QUEUE=");
                    writer.write(ip);
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
        
        @Override
        public void run() {
            try {
                while (Core.isRunning() && continueRun()) {
                    SimpleImmutableEntry<String,Byte> entry;
                    while (Core.isRunning() && isEmptyQuery() && (entry = poll()) != null) {
                        String ip = entry.getKey();
                        if (CIDR.isPublicIP(ip)) {
                            Byte value = entry.getValue();
                            if (value == null) {
                                long beginTime = System.currentTimeMillis();
                                String previous = ip;
                                while ((previous = SubnetIPv4.getPreviousIPv4(previous)) != null) {
                                    if (!Block.tryToBlockIP(previous)) {
                                        break;
                                    } else if (!Core.isRunning()) {
                                        addOperation(previous, null);
                                        break;
                                    } else if (System.currentTimeMillis() - beginTime > Server.MINUTE_TIME) {
                                        addOperation(previous, null);
                                        break;
                                    }
                                }
                                beginTime = System.currentTimeMillis();
                                String next = ip;
                                while ((next = SubnetIPv4.getNextIPv4(next)) != null) {
                                    if (!Block.tryToBlockIP(next)) {
                                        break;
                                    } else if (!Core.isRunning()) {
                                        addOperation(previous, null);
                                        break;
                                    } else if (System.currentTimeMillis() - beginTime > Server.MINUTE_TIME) {
                                        addOperation(next, null);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Entry<Long,Query> entryQuery;
                    while (Core.isRunning() && (entryQuery = pollQuery()) != null) {
                        long time = entryQuery.getKey();
                        Query query = entryQuery.getValue();
                        query.adviseSenderBLOCK(time);
                    }
                    Server.logTrace("queue finished.");
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }
    }
}
