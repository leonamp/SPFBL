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

import net.spfbl.core.Client;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import net.spfbl.core.Core;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
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
        
        private static final HashSet<String> SET = new HashSet<>();
        
        public static synchronized boolean isEmpty() {
            return SET.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = new TreeSet<>();
            set.addAll(SET);
            SET.clear();
            return set;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            set.addAll(SET);
            return set;
        }
        
        public static TreeSet<String> getAll(
                HashSet<String> userSet
        ) {
            TreeSet<String> set = new TreeSet<>();
            for (String token : getAll()) {
                String client = null;
                int index = token.indexOf(':');
                if (index > 0) {
                    String clientTemp = token.substring(0, index);
                    if (isValidEmail(clientTemp)) {
                        client = clientTemp;
                    }
                }
                if (client != null && !userSet.contains(client)) {
                    if (dropExact(token)) {
                        CHANGED = true;
                    }
                } else {
                    set.add(token);
                }
            }
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
    
    /**
     * Conjunto de critérios WHOIS para liberação.
     */
    private static class WHOIS {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<>();
        
        public static boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = getAll();
            MAP.clear();
            return set;
        }
        
        public static synchronized void drop(String client) {
            MAP.remove(client);
        }
        
        public static synchronized ArrayList<String> keySet() {
            ArrayList<String> keySet = new ArrayList<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static TreeSet<String> getClientSet(String client) {
            return MAP.get(client);
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
        
        public static TreeSet<String> getAll(HashSet<String> userSet) {
            TreeSet<String> set = new TreeSet<>();
            for (String client : keySet()) {
                if (client != null && !userSet.contains(client)) {
                    drop(client);
                } else {
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
            }
            return set;
        }
        
        private static synchronized boolean dropExact(String token) {
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
        
        private static String[] getArray(String client) {
            TreeSet<String> set = getClientSet(client);
            if (set == null) {
                return null;
            } else {
                int size = set.size();
                String[] array = new String[size];
                return set.toArray(array);
            }
        }
        
        private static String get(String client, Set<String> tokenSet) {
            if (tokenSet.isEmpty()) {
                return null;
            } else {
                TreeSet<String> subSet = new TreeSet<>();
                String[] array = getArray(null);
                if (array != null) {
                    subSet.addAll(Arrays.asList(array));
                }
                if (client != null) {
                    array = getArray(client);
                    if (array != null) {
                        for (String whois : array) {
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
                                int indexUser = whois.indexOf(':');
                                String key = whois.substring(indexUser + 1, indexValue);
                                String criterion = whois.substring(indexValue + 1);
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
                                                return whois;
                                            }
                                        } else if (value.length() > 0) {
                                            int criterionInt = parseIntWHOIS(criterion);
                                            int valueInt = parseIntWHOIS(value);
                                            if (signal == '<' && valueInt < criterionInt) {
                                                return whois;
                                            } else if (signal == '>' && valueInt > criterionInt) {
                                                return whois;
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
     * Conjunto de REGEX para liberação.
     */
    private static class REGEX {
        
        private static final HashMap<String,ArrayList<Regex>> MAP = new HashMap<>();
        
        public static boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized TreeSet<String> clear() {
            TreeSet<String> set = getAll();
            MAP.clear();
            return set;
        }
        
        public static synchronized void drop(String client) {
            MAP.remove(client);
        }
        
        private static synchronized ArrayList<String> getKeySet() {
            ArrayList<String> keySet = new ArrayList<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static ArrayList<Regex> getClientList(String client) {
            return MAP.get(client);
        }
        
        public static TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            for (String client : getKeySet()) {
                ArrayList<Regex> patternList = getClientList(client);
                if (patternList != null) {
                    for (Regex pattern : patternList) {
                        if (client == null) {
                            set.add("REGEX=" + pattern);
                        } else {
                            set.add(client + ":REGEX=" + pattern);
                        }
                    }
                }
            }
            return set;
        }
        
        public static TreeSet<String> getAll(HashSet<String> userSet) {
            TreeSet<String> set = new TreeSet<>();
            for (String client : getKeySet()) {
                if (client != null && !userSet.contains(client)) {
                    drop(client);
                } else {
                    ArrayList<Regex> patternList = getClientList(client);
                    if (patternList != null) {
                        for (Regex pattern : patternList) {
                            if (client == null) {
                                set.add("REGEX=" + pattern);
                            } else {
                                set.add(client + ":REGEX=" + pattern);
                            }
                        }
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
            ArrayList<Regex> list = MAP.get(client);
            if (list == null) {
                return false;
            } else {
                for (index = 0; index < list.size(); index++) {
                    Regex pattern = list.get(index);
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
        
        private static Regex[] getArray(String client) {
            ArrayList<Regex> patternList = getClientList(client);
            if (patternList == null) {
                return null;
            } else {
                int size = patternList.size();
                Regex[] array = new Regex[size];
                return patternList.toArray(array);
            }
        }
        
        private static String get(String client, Set<String> tokenSet) {
            if (tokenSet.isEmpty()) {
                return null;
            } else {
                String result = null;
                Regex[] patternArray = getArray(null);
                if (patternArray != null) {
                    for (Regex pattern : patternArray) {
                        for (String token : tokenSet) {
                            if (token.contains("@") == pattern.pattern().contains("@")) {
                                if (pattern.matches(token)) {
                                    result = "REGEX=" + pattern.pattern();
                                    break;
                                }
                            }
                        }
                    }
                }
                if (result == null && client != null) {
                    patternArray = getArray(client);
                    if (patternArray != null) {
                        for (Regex pattern : patternArray) {
                            for (String token : tokenSet) {
                                if (token.contains("@") == pattern.pattern().contains("@")) {
                                    if (pattern.matches(token)) {
                                        result = client + ":REGEX=" + pattern.pattern();
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
    
    /**
     * Representa o conjunto de blocos IP liberados.
     */
    private static class CIDR {
        
        private static final AddressSet SET = new AddressSet(7);
        
        public static void load() {
            try {
                File file = new File("./data/white.cidr.txt");
                if (file.exists()) {
                    SET.start(file);
                }
            } catch (IOException ex) {
                Server.logError(ex);
            }
        }
        
        public static boolean store() {
            return SET.store();
        }
        
        private static boolean addExact(String token) {
            if (token == null) {
                return false;
            } else if (token.startsWith("CIDR=")) {
                return SET.add(token.substring(5));
            } else if (isValidCIDR(token)) {
                return SET.add(token);
            } else {
                return false;
            }
        }
        
        private static boolean addExact(String token, boolean overlap) {
            if (token == null) {
                return false;
            } else if (token.startsWith("CIDR=")) {
                return SET.add(token.substring(5));
            } else {
                return SET.add(token);
            }
        }
        
        private static boolean dropExact(String token) {
            if (token == null) {
                return false;
            } else if (token.startsWith("CIDR=")) {
                return SET.remove(token.substring(5));
            } else {
                return SET.remove(token);
            }
        }
        
        public static void clear() {
            SET.clear();
        }
        
        public static boolean split(String user) {
            return false;
        }
        
        public static TreeSet<String> get(String user) {
            if (user == null) {
                return SET.getAllLegacy();
            } else {
                return new TreeSet<>();
            }
        }
        
        public static void writeAll(FileWriter writer) throws IOException {
            if (!SET.store()) {
                SET.writeLegacy(writer);
            }
        }
        
        public static TreeSet<String> getAll() {
            return SET.getAllLegacy();
        }
        
        public static boolean contains(String client, String cidr) {
            if (client == null) {
                return SET.contains(cidr);
            } else {
                return false;
            }
        }
        
        public static String get(String client, String ip) {
            if (client == null) {
                return SET.getLegacy(ip);
            } else {
                return null;
            }
        }
    }
    
    public static boolean dropExactSafe(String token) {
        try {
            return dropExact(token);
        } catch (ProcessException ex) {
            return false;
        }
    }
    
    public static boolean dropExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS/")) {
            if (WHOIS.dropExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.contains("CIDR=")) {
            if (CIDR.dropExact(token)) {
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
        } else if (SET.dropExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }

    public static boolean dropAll() {
        CIDR.clear();
        REGEX.clear();
        WHOIS.clear();
        CHANGED = true;
        return true;
    }

    public static String byTicket(
            String ticket,
            LinkedList<User> userResult
    ) {
        byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
        if (byteArray == null) {
            return null;
        } else if (byteArray.length > 8) {
            long date = byteArray[7] & 0xFF;
            date <<= 8;
            date += byteArray[6] & 0xFF;
            date <<= 8;
            date += byteArray[5] & 0xFF;
            date <<= 8;
            date += byteArray[4] & 0xFF;
            date <<= 8;
            date += byteArray[3] & 0xFF;
            date <<= 8;
            date += byteArray[2] & 0xFF;
            date <<= 8;
            date += byteArray[1] & 0xFF;
            date <<= 8;
            date += byteArray[0] & 0xFF;
            if (System.currentTimeMillis() - date > 432000000) {
                return "EXPIRED TICKET\n";
            } else {
                String query = Core.decodeHuffman(byteArray, 8);
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String command = tokenizer.nextToken();
                if (command.equals("spam")) {
                    String userEmail = null;
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        if (token.endsWith(":")) {
                            userEmail = token.substring(0, token.length()-1);
                        }
                    }
                    User user = User.get(userEmail);
                    if (user == null) {
                        return "QUERY NOT FOUND\n";
                    } else {
                        userResult.add(user);
                        User.Query userQuery = user.getQuerySafe(date);
                        if (userQuery == null) {
                            return "QUERY NOT FOUND\n";
                        } else if (userQuery.whiteKey(date)) {
                            userQuery.setFilter("CUSTOM_WHITELIST");
                            return "ADDED\n";
                        } else {
                            return "ALREADY EXISTS\n";
                        }
                    }
                } else {
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static boolean addExact(User user, String token) {
        if (token == null) {
            return false;
        } else if (user == null && SET.addExact(token)) {
            return CHANGED = true;
        } else if (user != null && SET.addExact(user.getEmail() + ":" + token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static boolean addExact(String user, String token) {
        if (token == null) {
            return false;
        } else if (user == null && SET.addExact(token)) {
            return CHANGED = true;
        } else if (user != null && SET.addExact(user + ":" + token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static boolean addFQDN(String fqdn) {
        if ((fqdn = Domain.normalizeHostname(fqdn, false)) == null) {
            return false;
        } else if (SET.addExact(fqdn)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static boolean dropFQDN(String fqdn) {
        if ((fqdn = Domain.normalizeHostname(fqdn, false)) == null) {
            return false;
        } else if (SET.dropExact(fqdn)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static boolean addExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("WHOIS/")) {
            if (WHOIS.addExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.startsWith("CIDR=")) {
            if (CIDR.addExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (token.contains("REGEX=")) {
            if (REGEX.addExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (SET.addExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }

    public static synchronized TreeSet<String> getAll() throws ProcessException {
        HashSet<String> userSet = Core.getUserClientSet();
        TreeSet<String> whiteSet = SET.getAll(userSet);
        whiteSet.addAll(REGEX.getAll(userSet));
        whiteSet.addAll(WHOIS.getAll(userSet));
        whiteSet.addAll(CIDR.getAll());
        return whiteSet;
    }
    
    public static boolean containsIPorFQDN(String ip) {
        if (ip == null) {
            return false;
        } else if (CIDR.get(null, ip) == null) {
            String fqdn = FQDN.getFQDN(ip, false);
            if (fqdn == null) {
                return false;
            } else {
                return SET.contains(fqdn);
            }
        } else {
            return true;
        }
    }
    
    public static boolean contains(String token) {
        if (token == null) {
            return false;
        } else if (isHostname(token)) {
            String hostname = Domain.normalizeHostname(token, true);
            return White.containsHostname(hostname);
        } else if (isValidEmail(token)) {
            token = Domain.normalizeEmail(token);
            if (White.containsExact(token = token.toLowerCase())) {
                return true;
            } else {
                int index = token.indexOf('@') + 1;
                String hostname = '.' + token.substring(index);
                return White.containsDomain(hostname);
            }
        } else {
            return false;
        }
    }
    
    public static boolean containsDomain(String host) {
        if ((host = Domain.extractHost(host, true)) == null) {
            return false;
        } else if (SET.contains(host + ";PASS")) {
            return true;
        } else {
            int index;
            while ((index = host.indexOf('.', 1)) > 0) {
                host = host.substring(index);
                if (SET.contains(host + ";PASS")) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean containsHostname(String host) {
        if ((host = Domain.extractHost(host, true)) == null) {
            return false;
        } else if (SET.contains(host.substring(1))) { // check FQDN.
            return true;
        } else if (SET.contains(host + ";PASS")) {
            return true;
        } else {
            int index;
            while ((index = host.indexOf('.', 1)) > 0) {
                host = host.substring(index);
                if (SET.contains(host + ";PASS")) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static String returnWhitePTR(Set<String> tokenSet) {
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
    
    public static boolean containsFQDN(String host) {
        if ((host = Domain.extractHost(host, false)) == null) {
            return false;
        } else {
            return SET.contains(host);
        }
    }

    public static boolean containsExact(String token) {
        if (token.contains("WHOIS/")) {
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
    
    private static final Regex WHOIS_PATTERN = new Regex("^"
            + "WHOIS(/[a-z-]+)+((=[a-zA-Z0-9@/.-]+)|((<|>)[0-9]+))"
            + "$"
    );
    
    private static boolean isWHOIS(String token) {
        return WHOIS_PATTERN.matches(token);
    }
    
    private static final Regex REGEX_PATTERN = new Regex("^"
            + "REGEX=[^ ]+"
            + "$"
    );

    private static boolean isREGEX(String token) {
        return REGEX_PATTERN.matches(token);
    }
    
    private static boolean isDNSBL(String token) {
        if (token.startsWith("DNSBL=") && token.contains(";")) {
            int index1 = token.indexOf('=');
            int index2 = token.indexOf(';');
            String server = token.substring(index1 + 1, index2);
            String value = token.substring(index2 + 1);
            return isHostname(server) && isValidIP(value);
        } else {
            return false;
        }
    }
    
    private static final Regex CIDR_PATTERN = new Regex("^"
            + "CIDR=("
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
            + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})"
            + "/[0-9]{1,3})"
            + "$"
    );

    private static boolean isCIDR(String token) {
        return CIDR_PATTERN.matches(token);
    }
    
    public static String normalizeTokenWhite(String token) throws ProcessException {
        if (isHostname(token)) {
            return Domain.normalizeHostname(token, false);
        } else {
            token = SPF.normalizeToken(
                    token, true, true, true, false,
                    false, false, false, false, false
            );
        }
        if (token == null) {
            return null;
        } else if (token.contains(";PASS")) {
            return token;
        } else if (token.contains(";NONE")) {
            return token;
        } else if (token.contains(";BULK")) {
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
        } else if (token.contains(";")) {
            return token;
        } else if (token.contains(">")) {
            int index = token.indexOf('>');
            return token.substring(0, index) + ";PASS" + token.substring(index);
        } else {
            return token + ";PASS";
        }
    }

    public static boolean add(
            String token
    ) throws ProcessException {
        if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addExact(token)) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean add(String client, String token) throws ProcessException {
        if (client == null || !isValidEmail(client)) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(client.toLowerCase() + ':' + token);
        }
    }
    
    public static boolean add(User user, String token) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(user.getEmail() + ':' + token);
        }
    }
    
    public static boolean add(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return addExact(client.getEmail() + ':' + token);
        }
    }

    public static boolean drop(String token) throws ProcessException {
        if ((token = normalizeTokenWhite(token)) == null) {
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
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(client + ':' + token);
        }
    }
    
    public static boolean drop(User user, String token) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(user.getEmail() + ':' + token);
        }
    }

    public static boolean drop(Client client, String token) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if ((token = normalizeTokenWhite(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else {
            return dropExact(client.getEmail() + ':' + token);
        }
    }
    
    public static boolean containsExtact(User user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.contains(token);
        } else {
            return SET.contains(user.getEmail() + ":" + token);
        }
    }
    
    public static boolean containsExtact(String user, String token) {
        if (token == null) {
            return false;
        } else if (user == null) {
            return SET.contains(token);
        } else {
            return SET.contains(user + ":" + token);
        }
    }

    public static TreeSet<String> get(Client client, User user) throws ProcessException {
        TreeSet<String> whiteSet = new TreeSet<>();
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail != null) {
            for (String token : getAll()) {
                if (token.startsWith(userEmail + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    whiteSet.add(token);
                }
            }
        }
        return whiteSet;
    }

    public static TreeSet<String> getAll(Client client, User user) throws ProcessException {
        TreeSet<String> whiteSet = new TreeSet<>();
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail != null) {
            for (String token : getAll()) {
                if (!token.contains(":")) {
                    whiteSet.add(token);
                } else if (token.startsWith(userEmail + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    whiteSet.add(token);
                }
            }
        }
        return whiteSet;
    }

    public static TreeSet<String> getAllTokens(String value) {
        TreeSet<String> whiteSet = new TreeSet<>();
        if (isValidIP(value)) {
            String ip = Subnet.normalizeIP(value);
            if (SET.contains(ip)) {
                whiteSet.add(ip);
            }
        } else if (isValidCIDR(value)) {
            String cidr = Subnet.normalizeCIDR(value);
            if (CIDR.contains((String) null, cidr)) {
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
        TreeSet<String> whiteSet = new TreeSet<>();
        for (String token : getAll()) {
            int index = Math.max(0, token.indexOf(':'));
            String email = token.substring(0, index);
            if (!isValidEmail(email)) {
                whiteSet.add(token);
            }
        }
        return whiteSet;
    }
    
    public static String clearCIDR(String ip, int mask) {
        if (isValidIP(ip)) {
            String cidr;
            while ((cidr = CIDR.get(null, ip)) != null) {
                if (!CIDR.split(cidr)) {
                    return cidr;
                }
            }
            return null;
        } else {
            return null;
        }
    }
    
    public static void clear(
            Long timeKey,
            Client client,
            User user,
            String ip,
            String sender,
            String hostname,
            String qualifier,
            String recipient
            ) throws ProcessException {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        clear(timeKey, userEmail, ip, sender, hostname, qualifier, recipient);
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
        String white;
        int mask = isValidIPv4(ip) ? 32 : 64;
        if ((white = White.clearCIDR(ip, mask)) != null) {
            if (userEmail == null) {
                Server.logDebug(timeKey, "false negative WHITE '" + white + "' detected.");
            } else {
                Server.logDebug(timeKey, "false negative WHITE '" + white + "' detected by '" + userEmail + "'.");
            }
        }
        TreeSet<String> whiteSet = new TreeSet<>();
        while ((white = find(userEmail, ip, sender, hostname, qualifier, recipient)) != null) {
            if (whiteSet.contains(white)) {
                throw new ProcessException("FATAL WHITE ERROR " + white);
            } else if (dropExact(white)) {
                if (userEmail == null) {
                    Server.logDebug(timeKey, "false negative WHITE '" + white + "' detected.");
                } else {
                    Server.logDebug(timeKey, "false negative WHITE '" + white + "' detected by '" + userEmail + "'.");
                }
            }
            whiteSet.add(white);
        }
    }
    
    public static boolean contains(
            Client client, User user,
            String ip, String sender, String hostname,
            String qualifier, String recipient, String subaddress
    ) {
        if (user != null && user.isInvitation(recipient, subaddress)) {
            return true;
        } else {
            return find(client, user, ip, sender, hostname, qualifier, recipient) != null;
        }
    }
    
    
    public static boolean contains(
            Client client, User user,
            String ip, String sender, String hostname,
            String qualifier, String recipient
    ) {
        return find(client, user, ip, sender, hostname, qualifier, recipient) != null;
    }
    
    public static boolean containsKey(
            User user,
            String ip,
            String fqdn,
            String sender,
            SPF.Qualifier qualifier
    ) {
        String key = White.key(
                user, ip, fqdn, sender, qualifier
        );
        return SET.contains(key);
    }
    
    public static String key(
            User user,
            String ip,
            String fqdn,
            String sender,
            SPF.Qualifier qualifier
    ) {
        if (qualifier == null) {
            return key(null, user, ip, sender, fqdn, "NONE");
        } else {
            return key(null, user, ip, sender, fqdn, qualifier.name());
        }
    }
    
    public static boolean containsKey(
            User user,
            String ip,
            String fqdn,
            String sender,
            String qualifier
    ) {
        String key = White.key(
                user, ip, fqdn, sender, qualifier
        );
        return SET.contains(key);
    }
    
    public static String key(
            User user,
            String ip,
            String fqdn,
            String sender,
            String qualifier
    ) {
        if (qualifier == null) {
            return key(null, user, ip, sender, fqdn, "NONE");
        } else {
            return key(null, user, ip, sender, fqdn, qualifier);
        }
    }
    
    public static String key(
            Client client,
            User user,
            String ip,
            String sender,
            String hostname,
            String qualifier
    ) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return key(userEmail, ip, sender, hostname, qualifier);
    }
    
    public static String key(
            String userEmail,
            String ip,
            String sender,
            String hostname,
            String qualifier
    ) {
        if (userEmail == null) {
            userEmail = "";
        } else {
            userEmail += ":";
        }
        if (sender == null || sender.isEmpty() || !sender.contains("@")) {
            try {
                if (hostname == null) {
                    return userEmail + "mailer-daemon@;" + ip;
                } else {
                    String domain = Domain.extractDomain(hostname, false);
                    return userEmail + "mailer-daemon@" + domain;
                }
            } catch (Exception ex) {
                return userEmail + ip;
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
                        qualifier = "NOTPASS";
                    }
                }
            }
            int index = sender.indexOf('@');
            String senderDomain = sender.substring(index);
            String validator;
            if ("PASS".equals(qualifier)) {
                validator = "PASS";
            } else if (!"FAIL".equals(qualifier) && Provider.containsCIDR(ip)) {
                validator = "BULK";
            } else if (hostname == null) {
                validator = ip;
            } else if (!"FAIL".equals(qualifier) && Provider.containsFQDN(hostname)) {
                validator = "BULK";
            } else {
                try {
                    validator = Domain.extractDomain(hostname, false);
                } catch (ProcessException ex) {
                    validator = ip;
                }
            }
            if (Provider.containsExact(senderDomain)) {
                sender = Domain.normalizeEmail(sender);
            } else {
                sender = null;
            }
            if (sender == null) {
                return userEmail + senderDomain + ";" + validator;
            } else {
                return userEmail + sender + ";" + validator;
            }
        }
    }
    
    public static String find(
            Client client, User user,
            String ip, String sender, String hostname,
            String qualifier, String recipient
    ) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return find(userEmail, ip, sender, hostname, qualifier, recipient);
    }
    
    public static String find(
            String userEmail,
            String ip, String sender, String hostname,
            String qualifier, String recipient
    ) {
        String key = key(userEmail, ip, sender, hostname, qualifier);
        if (SET.contains(key)) {
            return key;
        } else if (containsFQDN(hostname)) {
            return hostname;
        } else {
            TreeSet<String> whoisSet = new TreeSet<>();
            TreeSet<String> regexSet = new TreeSet<>();
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
            if (sender == null && hostname != null) {
                try {
                    String domain = Domain.extractDomain(hostname, false);
                    sender = "mailer-daemon@" + domain;
                    if (containsExact(sender + ";PASS")) {
                        return sender + ";PASS";
                    } else if (containsExact(userEmail + ":" + sender + ";PASS")) {
                        return userEmail + ":" + sender + ";PASS";
                    }
                } catch (Exception ex) {
                    sender = null;
                }
            }
            String found;
            if ((found = findSender(userEmail, sender, qualifier,
                    recipient, recipientDomain, whoisSet, regexSet)) != null) {
                return found;
            } else if ((found = findSender(userEmail, sender, ip,
                    recipient, recipientDomain, whoisSet, regexSet)) != null) {
                return found;
            }
            // Verifica o hostname.
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
                if (userEmail != null && ip.contains(":") && SET.contains(userEmail + ":CIDR=" + ip + "/32")) {
                    return ip;
                } else if (userEmail != null && !ip.contains(":") && SET.contains(userEmail + ":CIDR=" + ip + "/128")) {
                    return ip;
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
                } else if (userEmail != null && SET.contains(userEmail + ':' + ip + ';' + qualifier)) {
                    return userEmail + ':' + ip + ';' + qualifier;
                } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + ip + ';' + qualifier + '>' + recipient)) {
                    return userEmail + ':' + ip + ';' + qualifier + '>' + recipient;
                } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + ip + ';' + qualifier + '>' + recipientDomain)) {
                    return userEmail + ':' + ip + ';' + qualifier + '>' + recipientDomain;
                } else if ((cidr = CIDR.get(null, ip)) != null) {
                    return cidr;
                }
                regexSet.add(ip);
            }
            // Verifica um critério do REGEX.
            String regex;
            if ((regex = REGEX.get(userEmail, regexSet)) != null) {
                return regex;
            }
            // Verifica critérios do WHOIS.
            String whois;
            if ((whois = WHOIS.get(userEmail, whoisSet)) != null) {
                return whois;
            }
            return null;
        }
    }
    
    private static String findSender(
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
            int index1 = sender.indexOf('@');
            int index2 = sender.lastIndexOf('@');
            String part = sender.substring(0, index1 + 1);
            String senderDomain = sender.substring(index2);
            String found;
            if (sender.equals(Core.getAdminEmail()) && validation.equals("PASS")) {
                return Core.getAdminEmail() + ";PASS";
            } else if (recipient != null && SET.contains(sender + ';' + validation + '>' + recipient)) {
                return sender + ';' + validation + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(sender + ';' + validation + '>' + recipientDomain)) {
                return sender + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(sender + ';' + validation)) {
                return sender + ';' + validation;
            } else if (recipient != null && SET.contains(sender + ';' + validation + '>' + recipient)) {
                return sender + ';' + validation + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(sender + ';' + validation + '>' + recipientDomain)) {
                return sender + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + sender + ';' + validation)) {
                return userEmail + ':' + sender + ';' + validation;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + sender + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + sender + ';' + validation + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + sender + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + sender + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(part + ';' + validation)) {
                return part + ';' + validation;
            } else if (recipient != null && SET.contains(part + ';' + validation + '>' + recipient)) {
                return part + ';' + validation + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(part + ';' + validation + '>' + recipientDomain)) {
                return part + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + part + ';' + validation)) {
                return userEmail + ':' + part + ';' + validation;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + part + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + part + ';' + validation + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + part + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + part + ';' + validation + '>' + recipientDomain;
            } else if (SET.contains(senderDomain + ';' + validation)) {
                return senderDomain + ';' + validation;
            } else if (recipient != null && SET.contains(senderDomain + ';' + validation + '>' + recipient)) {
                return senderDomain + ';' + validation + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(senderDomain + ';' + validation + '>' + recipientDomain)) {
                return senderDomain + ';' + validation + '>' + recipientDomain;
            } else if (userEmail != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation)) {
                return userEmail + ':' + senderDomain + ';' + validation;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation + '>' + recipient)) {
                return userEmail + ':' + senderDomain + ';' + validation + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + senderDomain + ';' + validation + '>' + recipientDomain)) {
                return userEmail + ':' + senderDomain + ';' + validation + '>' + recipientDomain;
            } else if ((found = findHost(userEmail, sender, "." + senderDomain.substring(1), validation, recipient, recipientDomain, whoisSet, regexSet, false)) != null) {
                return found;
            } else {
                int index3 = senderDomain.length();
                while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = senderDomain.substring(0, index3 + 1);
                    if (SET.contains(subdomain + ';' + validation)) {
                        return subdomain + ';' + validation;
                    } else if (recipient != null && SET.contains(subdomain + ';' + validation + '>' + recipient)) {
                        return subdomain + ';' + validation + '>' + recipient;
                    } else if (recipientDomain != null && SET.contains(subdomain + ';' + validation + '>' + recipientDomain)) {
                        return subdomain + ';' + validation + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subdomain + ';' + validation)) {
                        return userEmail + ':' + subdomain + ';' + validation;
                    } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + subdomain + ';' + validation + '>' + recipient)) {
                        return userEmail + ':' + subdomain + ';' + validation + '>' + recipient;
                    } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + subdomain + ';' + validation + '>' + recipientDomain)) {
                        return userEmail + ':' + subdomain + ';' + validation + '>' + recipientDomain;
                    }
                }
                int index4 = sender.length();
                while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                    String subsender = sender.substring(0, index4 + 1);
                    if (SET.contains(subsender + ';' + validation)) {
                        return subsender + ';' + validation;
                    } else if (recipient != null && SET.contains(subsender + ';' + validation + '>' + recipient)) {
                        return subsender + ';' + validation + '>' + recipient;
                    } else if (recipientDomain != null && SET.contains(subsender + ';' + validation + '>' + recipientDomain)) {
                        return subsender + ';' + validation + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + ';' + validation)) {
                        return userEmail + ':' + subsender + ';' + validation;
                    } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipient)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipient;
                    } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain;
                    }
                }
                index4 = index2;
                while ((index4 = sender.lastIndexOf('.', index4 - 1)) > 0) {
                    String subsender = sender.substring(index4);
                    if (SET.contains(subsender + ';' + validation)) {
                        return subsender + ';' + validation;
                    } else if (recipient != null && SET.contains(subsender + ';' + validation + '>' + recipient)) {
                        return subsender + ';' + validation + '>' + recipient;
                    } else if (recipientDomain != null && SET.contains(subsender + ';' + validation + '>' + recipientDomain)) {
                        return subsender + ';' + validation + '>' + recipientDomain;
                    } else if (userEmail != null && SET.contains(userEmail + ':' + subsender + ';' + validation)) {
                        return userEmail + ':' + subsender + ';' + validation;
                    } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipient)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipient;
                    } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain)) {
                        return userEmail + ':' + subsender + ';' + validation + '>' + recipientDomain;
                    }
                }
            }
            if (senderDomain.endsWith(".br")) {
                whoisSet.add(senderDomain);
            }
            regexSet.add(sender);
        }
        return null;
    }

    public static boolean isDesactive(
            Client client,
            User user,
            String ip,
            String hostname,
            String recipient
    ) {
        String recipientDomain;
        if (recipient != null && recipient.contains("@")) {
            int index = recipient.indexOf('@');
            recipient = recipient.toLowerCase();
            recipientDomain = recipient.substring(index);
        } else {
            recipient = null;
            recipientDomain = null;
        }
        if (recipient != null && SET.contains("@>" + recipient)) {
            return true;
        } else if (recipientDomain != null && SET.contains("@>" + recipientDomain)) {
            return true;
        } else if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + ip)) {
            return true;
        } else if (user != null && SET.contains(user.getEmail() + ":@;" + ip)) {
            return true;
        } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@>" + recipient)) {
            return true;
        } else if (recipient != null && user != null && SET.contains(user.getEmail() + ":@>" + recipient)) {
            return true;
        } else if (recipientDomain != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@>" + recipientDomain)) {
            return true;
        } else if (recipientDomain != null && user != null && SET.contains(user.getEmail() + ":@>" + recipientDomain)) {
            return true;
        } else if (recipient != null && SET.contains("@;" + ip)) {
            return true;
        } else if (recipient != null && SET.contains("@;" + ip +  ">" + recipient)) {
            return true;
        } else if (recipientDomain != null && SET.contains("@;" + ip +  ">" + recipientDomain)) {
            return true;
        } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + ip)) {
            return true;
        } else if (recipient != null && user != null && SET.contains(user.getEmail() + ":@;" + ip)) {
            return true;
        } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + ip +  ">" + recipient)) {
            return true;
        } else if (recipient != null && user != null && SET.contains(user.getEmail() + ":@;" + ip +  ">" + recipient)) {
            return true;
        } else if (recipientDomain != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + ip +  ">" + recipientDomain)) {
            return true;
        } else if (recipientDomain != null && user != null && SET.contains(user.getEmail() + ":@;" + ip +  ">" + recipientDomain)) {
            return true;
        } else if (hostname == null) {
            return false;
        } else {
            do {
                int index = hostname.indexOf('.') + 1;
                hostname = hostname.substring(index);
                if (client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + hostname)) {
                    return true;
                } else if (user != null && SET.contains(user.getEmail() + ":@;" + hostname)) {
                    return true;
                } else if (recipient != null && SET.contains("@;" + hostname)) {
                    return true;
                } else if (recipient != null && SET.contains("@;" + hostname +  ">" + recipient)) {
                    return true;
                } else if (recipientDomain != null && SET.contains("@;" + hostname +  ">" + recipientDomain)) {
                    return true;
                } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + hostname)) {
                    return true;
                } else if (recipient != null && user != null && SET.contains(user.getEmail() + ":@;" + hostname)) {
                    return true;
                } else if (recipient != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + hostname +  ">" + recipient)) {
                    return true;
                } else if (recipient != null && user != null && SET.contains(user.getEmail() + ":@;" + hostname +  ">" + recipient)) {
                    return true;
                } else if (recipientDomain != null && client != null && client.hasEmail() && SET.contains(client.getEmail() + ":@;" + hostname +  ">" + recipientDomain)) {
                    return true;
                } else if (recipientDomain != null && user != null && SET.contains(user.getEmail() + ":@;" + hostname +  ">" + recipientDomain)) {
                    return true;
                }
            } while (hostname.contains("."));
            return false;
        }
    }

    private static String findHost(String userEmail,
            String sender, String hostname, String qualifier,
            String recipient, String recipientDomain,
            TreeSet<String> whoisSet, TreeSet<String> regexSet, boolean full
    ) {
        do {
            int index = hostname.indexOf('.') + 1;
            hostname = hostname.substring(index);
            String token = '.' + hostname;
            if (SET.contains(token + ';' + qualifier)) {
                return token + ';' + qualifier;
            } else if (recipient != null && SET.contains(token + ';' + qualifier + '>' + recipient)) {
                return token + ';' + qualifier + '>' + recipient;
            } else if (recipientDomain != null && SET.contains(token + ';' + qualifier + '>' + recipientDomain)) {
                return token + ';' + qualifier + '>' + recipientDomain;
//            } else if (userEmail != null && SET.contains(userEmail + ":@;" + hostname)) {
//                return userEmail + ":@;" + hostname;
            } else if (userEmail != null && SET.contains(userEmail + ':' + token)) {
                return userEmail + ':' + token;
            } else if (userEmail != null && SET.contains(userEmail + ':' + token + ';' + qualifier)) {
                return userEmail + ':' + token + ';' + qualifier;
            } else if (userEmail != null && recipient != null && SET.contains(userEmail + ':' + token + ';' + qualifier + '>' + recipient)) {
                return userEmail + ':' + token + ';' + qualifier + '>' + recipient;
            } else if (userEmail != null && recipientDomain != null && SET.contains(userEmail + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
                return userEmail + ':' + token + ';' + qualifier + '>' + recipientDomain;
            } else if (full && (token = findSender(userEmail, sender, hostname, recipient,
                    recipientDomain, whoisSet, regexSet)) != null) {
                return token;
            }
        } while (hostname.contains("."));
        return null;
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

    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/white.set");
                TreeSet<String> set = getAll();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(set, outputStream);
                    CHANGED = false;
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        CIDR.store();
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/white.set");
        if (file.exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                for (String token : set) {
                    addExact(token);
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        CIDR.load();
    }
}
