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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de reversos genáricos do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Generic {
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    /**
     * Conjunto de zonas de reversos genericos.
     */
    private static class SET {
        
        private static final HashSet<String> SET = new HashSet<String>();
        
        public static synchronized boolean isEmpty() {
            return SET.isEmpty();
        }
        
        public static synchronized void clear() {
            SET.clear();
            CHANGED = true;
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<String>();
            set.addAll(SET);
            return set;
        }
        
        private static synchronized boolean addExact(String token) {
            return CHANGED = SET.add(token);
        }
        
        private static synchronized boolean dropExact(String token) {
            return CHANGED = SET.remove(token);
        }
        
        public static synchronized boolean contains(String token) {
            return SET.contains(token);
        }
    }
    
//    private static void logTrace(long time, String message) {
//        Server.log(time, Core.Level.TRACE, "GRDNS", message, (String) null);
//    }
    
    /**
     * Conjunto de REGEX para bloqueio.
     */
    private static class REGEX {
        
        private static final HashMap<String,ArrayList<Pattern>> MAP = new HashMap<String,ArrayList<Pattern>>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
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
                        return CHANGED = true;
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
            return CHANGED = true;
        }
        
        private static synchronized ArrayList<Pattern> getClientList(String client) {
            return MAP.get(client);
        }
        
        public static boolean contains(String client, String regex) {
            if (regex == null) {
                return false;
            } else {
                ArrayList<Pattern> patternList = getClientList(client);
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
        
        private static String get(
                Collection<String> tokenList
                ) throws ProcessException {
            if (tokenList.isEmpty()) {
                return null;
            } else {
                ArrayList<Pattern> patternList = getClientList(null);
                if (patternList != null) {
                    for (Object object : patternList.toArray()) {
                        Pattern pattern = (Pattern) object;
                        for (String token : tokenList) {
                            if (token.contains("@") == pattern.pattern().contains("@")) {
                                Matcher matcher = pattern.matcher(token);
                                if (matcher.matches()) {
                                    return "REGEX=" + pattern.pattern();
                                }
                            }
                        }
                    }
                }
                return null;
            }
        }
    }
    
    public static boolean dropExact(String token) {
        if (token == null) {
            return false;
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
        SET.clear();
        REGEX.clear();
        return CHANGED = true;
    }

    public static boolean addExact(String token) throws ProcessException {
        if (token == null) {
            return false;
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
    
    public static TreeSet<String> getAll() throws ProcessException {
        TreeSet<String> blockSet = SET.getAll();
        blockSet.addAll(REGEX.getAll());
        return blockSet;
    }
    
    public static boolean containsDomain(String address) {
        if (address == null) {
            return false;
        } else {
            try {
                int index = address.indexOf('@') + 1;
                address = address.substring(index);
                String hostname = Domain.normalizeHostname(address, true);
                if (hostname == null) {
                    return false;
                } else {
                    LinkedList<String> regexList = new LinkedList<String>();
                    do {
                        index = hostname.indexOf('.') + 1;
                        hostname = hostname.substring(index);
                        if (SET.contains('.' + hostname)) {
                            return true;
                        } else {
                            regexList.addFirst('.' + hostname);
                        }
                    } while (hostname.contains("."));
                    return REGEX.get(regexList) != null;
                }
            } catch (ProcessException ex) {
                Server.logError(ex);
                return false;
            }
        }
    }

    public static boolean containsExact(String token) {
        if (token.contains("REGEX=")) {
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

    private static String normalizeTokenGeneric(String token) {
        if (token == null) {
            return null;
        } else if (Subnet.isValidIP(token)) {
            return null;
        } else if (Domain.isEmail(token)) {
            return null;
        } else if (SPF.isREGEX(token)) {
            return token;
        } else if (Domain.isHostname(token)) {
            return Domain.normalizeHostname(token, true);
        } else if (token.contains("#") || token.contains(".H.")) {
            while (token.contains("##")) {
                token = token.replace("##", "#");
            }
            String normal = token.replace('#', '0');
            normal = normal.replace(".H.", ".a0.");
            if (Domain.isHostname(normal)) {
                try {
                    String domain = Domain.extractDomain(normal, true);
                    if (normal.equals(domain)) {
                        // Domínio genérico.
                        return Domain.normalizeHostname(token, true);
                    } else if (token.endsWith(domain)) {
                        // Hostname genérico.
                        return Domain.normalizeHostname(token, true);
                    }
                } catch (ProcessException ex) {
                }
            }
            return null;
        } else {
            return null;
        }
    }
    
    public static boolean tryAdd(String token) {
        try {
            return add(token) != null;
        } catch (ProcessException ex) {
            return false;
        }
    }

    public static String add(String token) throws ProcessException {
        if ((token = normalizeTokenGeneric(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addExact(token)) {
            return token;
        } else {
            return null;
        }
    }
    
    public static boolean drop(String token) throws ProcessException {
        if ((token = normalizeTokenGeneric(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (dropExact(token)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> get() throws ProcessException {
        TreeSet<String> genericSet = new TreeSet<String>();
        for (String token : getAll()) {
            genericSet.add(token);
        }
        return genericSet;
    }
    
    public static boolean contains(String token) {
        return find(token) != null;
    }
    
    public static String convertDomainToMask(String host) {
        if (host == null) {
            return null;
        } else if (Domain.isHostname(host)) {
            try {
                String domain = Domain.extractDomain(host, true);
                String mask = domain.replace('0', '#');
                mask = mask.replace('1', '#');
                mask = mask.replace('2', '#');
                mask = mask.replace('3', '#');
                mask = mask.replace('4', '#');
                mask = mask.replace('5', '#');
                mask = mask.replace('6', '#');
                mask = mask.replace('7', '#');
                mask = mask.replace('8', '#');
                mask = mask.replace('9', '#');
                while (mask.contains("##")) {
                    mask = mask.replace("##", "#");
                }
                if (mask.equals(domain)) {
                    return null;
                } else {
                    return mask;
                }
            } catch (ProcessException ex) {
                return null;
            }
        } else {
            return null;
        }
    }
    
//    public static String getHostMask(String host) {
//        if (host == null) {
//            return null;
//        } else if (Domain.isHostname(host)) {
//            host = Domain.normalizeHostname(host, true);
//            do {
//                int index = host.indexOf('.') + 1;
//                host = host.substring(index);
//                String token2 = '.' + host;
//                if (SET.contains(token2)) {
//                    return null;
//                }
//            } while (host.contains("."));
//            return convertHostToMask(host);
//        } else {
//            return null;
//        }
//    }
    
    public static String convertHostToMask(String host) {
        if (host == null) {
            return null;
        } else if (Domain.isHostname(host)) {
            try {
                String domain = Domain.extractDomain(host, true);
                int index = host.length() - domain.length();
                if (index > 0) {
                    String mask = host.substring(0, index);
                    mask = mask.replace('0', '#');
                    mask = mask.replace('1', '#');
                    mask = mask.replace('2', '#');
                    mask = mask.replace('3', '#');
                    mask = mask.replace('4', '#');
                    mask = mask.replace('5', '#');
                    mask = mask.replace('6', '#');
                    mask = mask.replace('7', '#');
                    mask = mask.replace('8', '#');
                    mask = mask.replace('9', '#');
                    while (mask.contains("##")) {
                        mask = mask.replace("##", "#");
                    }
                    StringTokenizer tokenizer = new StringTokenizer(mask, ".");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        String subMask = token.replace('a', 'H');
                        subMask = subMask.replace('b', 'H');
                        subMask = subMask.replace('c', 'H');
                        subMask = subMask.replace('d', 'H');
                        subMask = subMask.replace('e', 'H');
                        subMask = subMask.replace('f', 'H');
                        if (subMask.contains("H")) {
                            subMask = subMask.replace('#', 'H');
                            while (subMask.contains("HH")) {
                                subMask = subMask.replace("HH", "H");
                            }
                            if (subMask.equals("H")) {
                                mask = mask.replace('.' + token + '.', ".H.");
                                if (mask.endsWith('.' + token)) {
                                    mask = mask.replace('.' + token, ".H");
                                }
                            }
                        }
                    }
                    mask += domain;
                    if (mask.equals(host)) {
                        return null;
                    } else {
                        return mask;
                    }
                } else {
                    return null;
                }
            } catch (ProcessException ex) {
                return null;
            }
        } else {
            return null;
        }
    }
    
    public static String find(
            String token
            ) {
        String mask = null;
        LinkedList<String> regexList = new LinkedList<String>();
        if (token == null) {
            return null;
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (SET.contains(token2)) {
                    return token2;
                }
                regexList.addFirst(token2);
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (SET.contains(host)) {
                    return host;
                }
            }
            if ((host = convertHostToMask(token)) != null) {
                mask = host;
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    String token2 = '.' + host;
                    if (SET.contains(token2)) {
                        return token2;
                    }
                    regexList.addFirst(token2);
                } while (host.contains("."));
            }
        } else if (token.contains("@")) {
            int index = token.lastIndexOf('@') + 1;
            token = token.substring(index);
            token = Domain.normalizeHostname(token, true);
            if (token != null) {
                String host = token;
                do {
                    index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    String token2 = '.' + host;
                    if (SET.contains(token2)) {
                        return token2;
                    }
                    regexList.addFirst(token2);
                } while (host.contains("."));
            }
        } else {
            regexList.add(token);
        }
        try {
            // Verifica um critério do REGEX.
            String regex;
            if ((regex = REGEX.get(regexList)) != null) {
                if (mask != null) {
                    int index = regex.indexOf('=') + 1;
                    if (!regex.contains("[0-9a-f]+") && !regex.contains("[0-9a-z]+") && !regex.contains("[a-z]+")) {
                        Pattern pattern = Pattern.compile(regex.substring(index));
                        index = mask.length();
                        while ((index = mask.lastIndexOf('.', index-1)) >= 0) {
                            String subMask = mask.substring(index);
                            if (Domain.isReserved(subMask)) {
                                // Do nothing.
                            } else if (Domain.isDomain(subMask)) {
                                if ((subMask = Generic.convertDomainToMask(subMask)) != null) {
                                    Matcher matcher = pattern.matcher(subMask.replace('#', '0'));
                                    if (matcher.matches()) {
                                        if (addExact(subMask)) {
                                            Block.clear(subMask.replace('#', '0'), "GENERIC");
                                            Server.logDebug("new GENERIC '" + subMask + "' added by '" + regex + "'.");
                                            return subMask;
                                        }
                                    }
                                }
                            } else {
                                Matcher matcher = pattern.matcher(subMask.replace('#', '0').replace(".H.", ".0a."));
                                if (matcher.matches()) {
                                    if (addExact(subMask)) {
                                        Block.clear(subMask.replace('#', '0').replace(".H.", ".0a."), "GENERIC");
                                        Server.logDebug("new GENERIC '" + subMask + "' added by '" + regex + "'.");
                                        return subMask;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                return regex;
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
        return null;
    }

    public static void store() {
        if (CHANGED) {
            try {
                Server.logTrace("storing generic.set");
                long time = System.currentTimeMillis();
                File file = new File("./data/generic.set");
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
        File file = new File("./data/generic.set");
        if (file.exists()) {
            try {
                Set<String> set;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    set = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String token : set) {
                    if (token.startsWith("REGEX=")) {
                        REGEX.addExact(token);
                    } else {
                        SET.addExact(token);
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
