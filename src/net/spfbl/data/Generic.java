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
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
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
    private static class MAP {
        
        private static final HashMap<String,Boolean> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clearGeneric() {
            MAP.clear();
            CHANGED = true;
        }
        
        public static synchronized void clearDynamic() {
            for (String key : MAP.keySet()) {
                MAP.put(key, false);
            }
        }
        
        public static synchronized TreeSet<String> getGenericAll() {
            TreeSet<String> set = new TreeSet<>();
            set.addAll(MAP.keySet());
            return set;
        }
        
        public static synchronized TreeSet<String> getDynamicAll() {
            TreeSet<String> set = new TreeSet<>();
            for (String key : MAP.keySet()) {
                if (MAP.get(key)) {
                    set.add(key);
                }
            }
            return set;
        }
        
        public static synchronized TreeMap<String,Boolean> getMapAll() {
            TreeMap<String,Boolean> map = new TreeMap<>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized boolean addGenericExact(String token) {
            if (MAP.containsKey(token)) {
                return false;
            } else {
                Boolean old = MAP.put(token, false);
                boolean changed = old == null || old.equals(true);
                CHANGED |= changed;
                return changed;
            }
        }
        
        private static synchronized boolean addDynamicExact(String token) {
            Boolean old = MAP.put(token, true);
            boolean changed = old == null || old.equals(false);
            CHANGED |= changed;
            return changed;
        }
        
        private static synchronized boolean putExact(String token, boolean dyn) {
            Boolean old = MAP.put(token, dyn);
            boolean changed = old == null || !old.equals(dyn);
            CHANGED |= changed;
            return changed;
        }
        
        private static synchronized boolean dropGenericExact(String token) {
            boolean changed = MAP.remove(token) != null;
            CHANGED |= changed;
            return changed;
        }
        
        private static synchronized boolean dropDynamicExact(String token) {
            Boolean dyn = MAP.get(token);
            if (dyn == null) {
                return false;
            } else if (dyn) {
                MAP.put(token, false);
                return CHANGED = true;
            } else {
                return false;
            }
        }
        
        public static synchronized boolean containsGeneric(String token) {
            return MAP.containsKey(token);
        }
        
        public static synchronized boolean containsDynamic(String token) {
            Boolean dyn = MAP.get(token);
            if (dyn == null) {
                return false;
            } else {
                return dyn;
            }
        }
    }
    
    /**
     * Conjunto de REGEX para bloqueio.
     */
    private static class REGEX {
        
        private static final HashMap<String,ArrayList<Pattern>> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
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
                list = new ArrayList<>();
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
    
    public static boolean dropGenericExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("REGEX=")) {
            if (REGEX.dropExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (MAP.dropGenericExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static boolean dropDynamicExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("REGEX=")) {
            return false;
        } else if (MAP.dropDynamicExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }

    public static boolean dropGenericAll() {
        MAP.clearGeneric();
        REGEX.clear();
        return CHANGED = true;
    }
    
    public static boolean dropDynamicAll() {
        MAP.clearDynamic();
        return CHANGED = true;
    }

    private static boolean addGenericExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("REGEX=")) {
            if (REGEX.addExact(token)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else if (MAP.addGenericExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    private static boolean addDynamicExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("REGEX=")) {
            return false;
        } else if (MAP.addDynamicExact(token)) {
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public static TreeSet<String> getGenericAll() throws ProcessException {
        TreeSet<String> set = MAP.getGenericAll();
        set.addAll(REGEX.getAll());
        return set;
    }
    
    public static TreeSet<String> getDynamicAll() throws ProcessException {
        TreeSet<String> set = MAP.getDynamicAll();
        return set;
    }
    
    public static TreeMap<String,Boolean> getMapAll() throws ProcessException {
        TreeMap<String,Boolean> map = MAP.getMapAll();
        for (String key : REGEX.getAll()) {
            map.put(key, false);
        }
        return map;
    }
    
    public static boolean containsGenericExact(String address) {
        if (address == null) {
            return false;
        } else {
            return MAP.containsGeneric(address);
        }
    }
    
    public static boolean containsGenericDomain(String address) {
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
                    LinkedList<String> regexList = new LinkedList<>();
                    do {
                        index = hostname.indexOf('.') + 1;
                        hostname = hostname.substring(index);
                        if (MAP.containsGeneric('.' + hostname)) {
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

    public static boolean containsDynamicDomain(String address) {
        if (address == null) {
            return false;
        } else {
            int index = address.indexOf('@') + 1;
            address = address.substring(index);
            String hostname = Domain.normalizeHostname(address, true);
            if (hostname == null) {
                return false;
            } else {
                do {
                    index = hostname.indexOf('.') + 1;
                    hostname = hostname.substring(index);
                    if (MAP.containsDynamic('.' + hostname)) {
                        return true;
                    }
                } while (hostname.contains("."));
                return false;
            }
        }
    }

    private static String normalizeToken(String token, boolean regex) {
        if (token == null) {
            return null;
        } else if (Subnet.isValidIP(token)) {
            return null;
        } else if (Domain.isMailFrom(token)) {
            return null;
        } else if (SPF.isREGEX(token)) {
            if (regex) {
                return token;
            } else {
                return null;
            }
        } else if (token.contains("#") || token.contains(".H.")) {
            while (token.contains(".H.")) {
                token = token.replace(".H.", ".$.");
            }
            while (token.contains("##")) {
                token = token.replace("##", "#");
            }
            String normal = token.replace('#', '0');
            normal = normal.replace(".$.", ".a0.");
            if (Domain.isHostname(normal)) {
                try {
                    String domain = Domain.extractDomain(normal, true);
                    if (normal.equals(domain)) {
                        // Domínio genérico.
                        token = Domain.normalizeHostname(token, true);
                        while (token.contains(".$.")) {
                            token = token.replace(".$.", ".H.");
                        }
                        return token;
                    } else if (token.endsWith(domain)) {
                        // Hostname genérico.
                        token = Domain.normalizeHostname(token, true);
                        while (token.contains(".$.")) {
                            token = token.replace(".$.", ".H.");
                        }
                        return token;
                    }
                } catch (ProcessException ex) {
                }
            }
            return null;
        } else if (Domain.isHostname(token)) {
            return Domain.normalizeHostname(token, true);
        } else {
            return null;
        }
    }
    
    public static boolean tryAdd(String token) {
        try {
            return addGeneric(token) != null;
        } catch (ProcessException ex) {
            return false;
        }
    }

    public static String addGeneric(String token) throws ProcessException {
        if ((token = normalizeToken(token, true)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addGenericExact(token)) {
            return token;
        } else {
            return null;
        }
    }
    
    public static String addDynamic(String token) throws ProcessException {
        if ((token = normalizeToken(token, false)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addDynamicExact(token)) {
            return token;
        } else {
            return null;
        }
    }
    
    public static boolean dropGeneric(String token) throws ProcessException {
        if ((token = normalizeToken(token, true)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (dropGenericExact(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean dropDynamic(String token) throws ProcessException {
        if ((token = normalizeToken(token, false)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (dropDynamicExact(token)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> getGeneric() throws ProcessException {
        TreeSet<String> genericSet = new TreeSet<>();
        for (String token : getGenericAll()) {
            genericSet.add(token);
        }
        return genericSet;
    }
    
    public static TreeSet<String> getDynamic() throws ProcessException {
        TreeSet<String> genericSet = new TreeSet<>();
        for (String token : getDynamicAll()) {
            genericSet.add(token);
        }
        return genericSet;
    }
    
    public static boolean isGenericEC2(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return false;
        } else {
            String mask = convertHostToMask(host);
            if (mask == null) {
                return false;
            } else if (mask.equals(".ec#-#-#-#-#.ap-northeast-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.ap-south-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.ap-southeast-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.ca-central-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.compute-#.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.eu-central-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.eu-west-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.sa-east-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.us-east-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.us-gov-west-#.compute.amazonaws.com")) {
                return true;
            } else if (mask.equals(".ec#-#-#-#-#.us-west-#.compute.amazonaws.com")) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static boolean containsGeneric(String token) {
        return findGeneric(token) != null;
    }
    
    public static boolean containsGenericSoft(String token) {
        return findGenericSoft(token) != null;
    }
    
    public static boolean containsDynamic(String token) {
        return findDynamic(token) != null;
    }
    
    public static String convertDomainToMask(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else {
            String domain = Domain.extractDomainSafe(host, true);
            if (domain == null) {
                return null;
            } else {
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
            }
        }
    }
    
    public static String convertHostToMask(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else if (host.contains("mail")) {
            return null;
        } else if (host.contains("http")) {
            return null;
        } else if (host.contains("smtp")) {
            return null;
        } else if (host.contains("cpanel")) {
            return null;
        } else if (host.contains("relay")) {
            return null;
        } else if (host.contains("mta")) {
            return null;
        } else if (host.contains("zimbra")) {
            return null;
        } else if (host.contains("postfix")) {
            return null;
        } else if (host.contains("correio")) {
            return null;
        } else if (host.contains("newsletter")) {
            return null;
        } else if (host.contains("bounce")) {
            return null;
        } else if (host.contains("gateway")) {
            return null;
        } else if (host.contains("mbox")) {
            return null;
        } else if (host.startsWith(".www.")) {
            return null;
        } else if (host.startsWith(".mx-")) {
            return null;
        } else {
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
                            if (subMask.contains("HHHH")) {
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
                    }
                    while (mask.contains("##")) {
                        mask = mask.replace("##", "#");
                    }
                    mask += domain;
                    if (mask.equals(host)) {
                        return null;
                    } else if (mask.startsWith(".pm#")) {
                        return null;
                    } else if (mask.startsWith(".mx#")) {
                        return null;
                    } else if (mask.startsWith(".pop#")) {
                        return null;
                    } else if (mask.startsWith(".dns#")) {
                        return null;
                    } else if (mask.startsWith(".out#")) {
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
        }
    }
    
    public static String findGeneric(
            String token
            ) {
        String mask = null;
        LinkedList<String> regexList = new LinkedList<>();
        if (token == null) {
            return null;
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsGeneric(token2)) {
                    return token2;
                }
                regexList.addFirst(token2);
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsGeneric(host)) {
                    return host;
                }
            }
            if ((host = convertHostToMask(token)) != null) {
                mask = host;
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    String token2 = '.' + host;
                    if (MAP.containsGeneric(token2)) {
                        return token2;
                    }
                    regexList.addFirst(token2);
                } while (host.contains("."));
            }
        } else if (token.contains("@")) {
            int index = token.lastIndexOf('@') + 1;
            token = token.substring(index);
            token = Domain.normalizeHostname(token, true);
            return findGeneric(token);
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
                            if (Domain.isOfficialTLD(subMask)) {
                                // Do nothing.
                            } else if (Domain.isDomain(subMask)) {
                                if ((subMask = Generic.convertDomainToMask(subMask)) != null) {
                                    Matcher matcher = pattern.matcher(subMask.replace('#', '0'));
                                    if (matcher.matches()) {
                                        if (addGenericExact(subMask)) {
                                            Block.clear(subMask.replace('#', '0'), "GENERIC");
                                            Server.logDebug("new GENERIC '" + subMask + "' added by '" + regex + "'.");
                                            return subMask;
                                        }
                                    }
                                }
                            } else {
                                Matcher matcher = pattern.matcher(subMask.replace('#', '0').replace(".H.", ".0a."));
                                if (matcher.matches()) {
                                    if (addGenericExact(subMask)) {
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
    
    public static String findGenericSoft(
            String token
            ) {
        if (token == null) {
            return null;
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsGeneric(token2)) {
                    return token2;
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsGeneric(host)) {
                    return host;
                }
            }
            if ((host = convertHostToMask(token)) != null) {
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    String token2 = '.' + host;
                    if (MAP.containsGeneric(token2)) {
                        return token2;
                    }
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
                    if (MAP.containsGeneric(token2)) {
                        return token2;
                    }
                } while (host.contains("."));
            }
        }
        return null;
    }
    
    public static String findDynamic(
            String token
            ) {
        if (token == null) {
            return null;
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsDynamic(token2)) {
                    return token2;
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsDynamic(host)) {
                    return host;
                }
            }
            if ((host = convertHostToMask(token)) != null) {
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    String token2 = '.' + host;
                    if (MAP.containsDynamic(token2)) {
                        return token2;
                    }
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
                    if (MAP.containsDynamic(token2)) {
                        return token2;
                    }
                } while (host.contains("."));
            }
        }
        return null;
    }

    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/generic.set");
                TreeSet<String> set = getGenericAll();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(set, outputStream);
                    CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
                time = System.currentTimeMillis();
                file = new File("./data/generic.map");
                TreeMap<String,Boolean> map = getMapAll();
                outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
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
        File file = new File("./data/generic.map");
        if (file.exists()) {
            try {
                Map<String,Boolean> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String token : map.keySet()) {
                    boolean dyn = map.get(token);
                    if (token.startsWith("REGEX=")) {
                        REGEX.addExact(token);
                    } else {
                        MAP.putExact(token, dyn);
                    }
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        } else if ((file = new File("./data/generic.set")).exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                for (String token : set) {
                    if (token.startsWith("REGEX=")) {
                        REGEX.addExact(token);
                    } else {
                        MAP.addGenericExact(token);
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
