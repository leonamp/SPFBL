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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Core;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import net.spfbl.core.Reverse;
import net.spfbl.core.Server;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de reversos genéricos do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Generic {
    
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
            if (token == null) {
                return false;
            } else if (MAP.containsKey(token)) {
                return false;
            } else {
                Boolean old = MAP.put(token, false);
                return old == null || old.equals(true);
            }
        }
        
        private static synchronized boolean addDynamicExact(String token) {
            if (token == null) {
                return false;
            } else {
                Boolean old = MAP.put(token, true);
                return old == null || old.equals(false);
            }
        }
        
        private static synchronized boolean putExact(String token, boolean dyn) {
            if (token == null) {
                return false;
            } else {
                Boolean old = MAP.put(token, dyn);
                return old == null || !old.equals(dyn);
            }
        }
        
        private static synchronized boolean dropGenericExact(String token) {
            if (token == null) {
                return false;
            } else {
                return MAP.remove(token) != null;
            }
        }
        
        private static synchronized boolean dropDynamicExact(String token) {
            if (token == null) {
                return false;
            } else {
                Boolean dyn = MAP.get(token);
                if (dyn == null) {
                    return false;
                } else if (dyn) {
                    MAP.put(token, false);
                    return true;
                } else {
                    return false;
                }
            }
        }
        
        public static boolean containsGeneric(String token) {
            return MAP.containsKey(token);
        }
        
        public static boolean containsDynamic(String token) {
            Boolean dyn = MAP.get(token);
            if (dyn == null) {
                return false;
            } else {
                return dyn;
            }
        }
    }
    
    public static boolean dropGenericExact(String token) {
        if (token == null) {
            return false;
        } else if (MAP.dropGenericExact(token)) {
            append("DROP " + token);
            return true;
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
            append("PUT " + token + " false");
            return true;
        } else {
            return false;
        }
    }

    public static boolean dropGenericAll() {
        MAP.clearGeneric();
        return true;
    }
    
    public static boolean dropDynamicAll() {
        MAP.clearDynamic();
        return true;
    }
    
    private static boolean addGenericSafe(String token) {
        try {
            return addGenericExact(token);
        } catch (ProcessException ex) {
            Server.logError(ex);
            return false;
        }
    }

    private static boolean addGenericExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (MAP.addGenericExact(token)) {
            append("PUT " + token + " false");
            return true;
        } else {
            return false;
        }
    }
    
    public static String addDynamicPTR(String ptr) {
        String mask = convertHostToMask(ptr);
        if (addDynamicExact(mask)) {
            return mask;
        } else {
            return null;
        }
    }
        
    
    private static boolean addDynamicExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("REGEX=")) {
            return false;
        } else if (MAP.addDynamicExact(token)) {
            append("PUT " + token + " true");
            return true;
        } else {
            return false;
        }
    }
    
    public static TreeSet<String> getGenericAll() throws ProcessException {
        TreeSet<String> set = MAP.getGenericAll();
        return set;
    }
    
    public static TreeSet<String> getDynamicAll() throws ProcessException {
        TreeSet<String> set = MAP.getDynamicAll();
        return set;
    }
    
    public static TreeMap<String,Boolean> getMapAll() throws ProcessException {
        TreeMap<String,Boolean> map = MAP.getMapAll();
        return map;
    }
    
    public static boolean isDynamicIP(String ip) {
        if (FQDN.hasFQDN(ip)) {
            return false;
        } else if (Subnet.isReservedIP(ip)) {
            return false;
        } else {
            Reverse reverse = Reverse.get(ip);
            if (reverse == null || reverse.isEmpty()) {
                return SubnetIPv6.isSLAAC(ip);
            } else {
                for (String address : reverse.getAddressSet()) {
                    if (Generic.containsDynamic(address)) {
                        Block.tryToDominoBlockIP(ip, "DYNAMIC");
                        return true;
                    }
                }
                return false;
            }
        }
    }
    
    public static String getDynamicMaskRDNS(String ip) {
        if (FQDN.hasFQDN(ip)) {
            return null;
        } else if (Subnet.isReservedIP(ip)) {
            return null;
        } else {
            Reverse reverse = Reverse.get(ip);
            if (reverse == null || reverse.isEmpty()) {
                return null;
            } else {
                String mask;
                for (String address : reverse.getAddressSet()) {
                    if ((mask = Generic.findDynamic(address)) != null) {
                        Block.tryToDominoBlockIP(ip, "DYNAMIC");
                        return mask;
                    }
                }
                return null;
            }
        }
    }
    
    public static boolean containsGenericExact(String address) {
        if (address == null) {
            return false;
        } else {
            return MAP.containsGeneric(address);
        }
    }
    
    public static void clearGeneric(String ip, String cause) {
        for (String ptr : Reverse.getPointerSetSafe(ip)) {
            String mask;
            if ((mask = convertDomainToMask(ptr)) != null) {
                if (dropGenericExact(mask)) {
                    Server.logDebug(null, "false positive GENERIC '" + mask + "' detected by '" + cause + "'.");
                }
            }
            String host = ptr;
            mask = convertHostToMask(host);
            if (mask == null) {
                host = Domain.normalizeHostname(host, true);
            } else {
                host = mask;
            }
            if (host != null) {
                if (dropGenericExact(host)) {
                    Server.logDebug(null, "false positive GENERIC '" + host + "' detected by '" + cause + "'.");
                }
                int index;
                while ((index = host.indexOf('.', 1)) > 0) {
                    host = host.substring(index);
                    if (dropGenericExact(host)) {
                        Server.logDebug(null, "false positive GENERIC '" + host + "' detected by '" + cause + "'.");
                    }
                }
            }
        }
    }
    
    public static boolean containsGenericMaskFQDN(String host) {
        String mask = convertHostToMask(host);
        if (mask == null) {
            return false;
        } else {
            return MAP.containsGeneric(mask);
        }
    }
    
    public static boolean containsGenericFQDN(String host) {
        String mask;
        if ((mask = convertDomainToMask(host)) != null) {
            if (MAP.containsGeneric(mask)) {
                return true;
            }
        }
        mask = convertHostToMask(host);
        if (mask == null) {
            host = Domain.normalizeHostname(host, true);
        } else {
            host = mask;
        }
        if (host == null) {
            return false;
        } else if (MAP.containsGeneric(host)) {
            return true;
        } else {
            int index;
            while ((index = host.indexOf('.', 1)) > 0) {
                host = host.substring(index);
                if (MAP.containsGeneric(host)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean containsGenericEmail(String email) {
        if (email == null) {
            return false;
        } else {
            int index = email.indexOf('@') + 1;
            String hostname = '.' + email.substring(index);
            do {
                index = hostname.indexOf('.') + 1;
                hostname = hostname.substring(index);
                if (MAP.containsGeneric('.' + hostname)) {
                    return true;
                }
            } while (hostname.contains("."));
            return false;
        }
    }
    
    public static boolean containsGenericDomain(String address) {
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
                    if (MAP.containsGeneric('.' + hostname)) {
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
        } else if (isValidIP(token)) {
            return null;
        } else if (Domain.isMailFrom(token)) {
            return null;
        } else if (token.contains("#") || token.matches("\\bH\\b")) {
            token = token.replace('H', '#');
            return token.replaceAll("\\#+", "#");
        } else if (isHostname(token)) {
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
            } else if (mask.equals(".ec#-#-#-#-#.cn-north-#.compute.amazonaws.com.cn")) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static boolean containsGeneric(String token) {
        return findGeneric(token) != null;
    }
    
    public static boolean containsMask(String mask) {
        if (mask == null) {
            return false;
        } else {
            return MAP.containsGeneric(mask);
        }
    }
    
    public static boolean containsGenericSoft(String token) {
        return findGenericSoft(token) != null;
    }
    
    public static boolean containsDynamic(String token) {
        return findDynamic(token) != null;
    }
    
    public static String returnDynamicPTR(Set<String> tokenSet) {
        if (tokenSet == null) {
            return null;
        } else {
            for (String token : tokenSet) {
                if (findDynamic(token) != null) {
                    return token;
                }
            }
            return null;
        }
    }
    
    public static String returnGenericPTR(Set<String> tokenSet) {
        if (tokenSet == null) {
            return null;
        } else {
            for (String token : tokenSet) {
                if (findGeneric(token) != null) {
                    return token;
                }
            }
            return null;
        }
    }
    
    public static String convertDomainToMask(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else {
            String domain = Domain.extractDomainSafe(host, true);
            if (domain == null) {
                return null;
            } else {
                String mask = domain.toLowerCase();
                mask = mask.replaceAll("[0-9a-f]{32}", "#");
                mask = mask.replaceAll("[0-9a-f]{16}", "#");
                mask = mask.replaceAll("[0-9a-f]{8}", "#");
                mask = mask.replaceAll("[0-9#]+", "#");
                if (mask.equals(domain)) {
                    return null;
                } else {
                    return mask;
                }
            }
        }
    }
    
    public static String convertHostOrDomainToMask(String host) {
        String mask = convertHostToMask(host);
        if (mask == null) {
            return convertDomainToMask(host);
        } else {
            return mask;
        }
    }
    
    public static String convertHostToMask(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else if (host.startsWith(".xn--")) {
            return null;
        } else {
            try {
                String domain = Domain.extractDomain(host, true);
                if (domain == null) {
                    return null;
                } else {
                    int index = host.length() - domain.length();
                    if (index > 0) {
                        String mask = host.substring(0, index);
                        if (mask.contains("mail")) {
                            return null;
                        } else if (mask.contains("smtp")) {
                            return null;
                        } else if (mask.contains("cpanel")) {
                            return null;
                        } else if (mask.contains("relay")) {
                            return null;
                        } else if (mask.contains("mta")) {
                            return null;
                        } else if (mask.contains("zimbra")) {
                            return null;
                        } else if (mask.contains("postfix")) {
                            return null;
                        } else if (mask.contains("correio")) {
                            return null;
                        } else if (mask.contains("newsletter")) {
                            return null;
                        } else if (mask.contains("bounce")) {
                            return null;
                        } else if (mask.contains("mxout")) {
                            return null;
                        } else if (mask.contains("gateway")) {
                            return null;
                        } else if (mask.contains("mbox")) {
                            return null;
                        } else if (mask.startsWith(".mx-")) {
                            return null;
                        } else {
                            mask = mask.replaceAll("\\b[0-9]+\\b", "#");
                            mask = mask.replaceAll("\\b[0-9a-f]{4,16}\\b", "#");
                            mask = mask.replaceAll("[0-9a-f]{16}\\b", "#");
                            mask = mask.replaceAll("[0-9a-f]{12}\\b", "#");
                            mask = mask.replaceAll("[0-9a-f]{8}\\b", "#");
                            mask = mask.replaceAll("[0-9#]+", "#");
                            mask += domain;
                            if (mask.equals(host)) {
                                return null;
                            } else if (mask.startsWith(".pm#")) {
                                return null;
                            } else if (mask.startsWith(".mx#")) {
                                return null;
                            } else if (mask.startsWith(".pop#")) {
                                return null;
                            } else if (mask.startsWith(".out#")) {
                                return null;
                            } else {
                                return mask;
                            }
                        }
                    } else {
                        return null;
                    }
                }
            } catch (ProcessException ex) {
                return null;
            }
        }
    }
    
    public static String findGeneric(String token) {
        LinkedList<String> regexList = new LinkedList<>();
        if (token == null) {
            return null;
        } else if (isHostname(token)) {
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
                if ((token2 = convertHostToMask(token2)) != null) {
                    if (MAP.containsGeneric(token2)) {
                        return token2;
                    }
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsGeneric(host)) {
                    return host;
                }
            }
        } else if (token.contains("@")) {
            int index = token.lastIndexOf('@') + 1;
            token = token.substring(index);
            token = Domain.normalizeHostname(token, true);
            return findGeneric(token);
        } else {
            regexList.add(token);
        }
        return null;
    }
    
    public static String findGenericSoft(
            String token
            ) {
        if (token == null) {
            return null;
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsGeneric(token2)) {
                    return token2;
                }
                if ((token2 = convertHostToMask(token2)) != null) {
                    if (MAP.containsGeneric(token2)) {
                        return token2;
                    }
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsGeneric(host)) {
                    return host;
                }
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
    
    public static boolean containsDynamicDomain(String token) {
        if ((token = Domain.normalizeHostname(token, true)) == null) {
            return false;
        } else {
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsDynamic(token2)) {
                    return true;
                }
                if ((token2 = convertHostToMask(token2)) != null) {
                    if (MAP.containsDynamic(token2)) {
                        return true;
                    }
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsDynamic(host)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static String findDynamic(String token) {
        if (token == null) {
            return null;
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
            String host = token;
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token2 = '.' + host;
                if (MAP.containsDynamic(token2)) {
                    return token2;
                }
                if ((token2 = convertHostToMask(token2)) != null) {
                    if (MAP.containsDynamic(token2)) {
                        return token2;
                    }
                }
            } while (host.contains("."));
            if ((host = convertDomainToMask(token)) != null) {
                if (MAP.containsDynamic(host)) {
                    return host;
                }
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
    
    private static final File FILE = new File("./data/generic.txt");
    private static Writer WRITER = null;
    private static final LinkedList<String> LIST = new LinkedList<>();
    private static final Semaphore SEMAPHORE = new Semaphore(0);
    
    private static void append(String line) {
        if (SEMAPHORE.tryAcquire()) {
            try {
                writeList();
                WRITER.append(line);
                WRITER.write('\n');
                WRITER.flush();
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                SEMAPHORE.release();
            }
        } else {
            LIST.offer(line);
        }
    }
    
    private static void writeList() {
        try {
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line);
                WRITER.write('\n');
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private static void startWriter() {
        try {
            WRITER = new FileWriter(FILE, true);
            writeList();
            if (Core.isRunning()) {
                WRITER.flush();
            } else {
                WRITER.close();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            if (Core.isRunning()) {
                SEMAPHORE.release();
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
                    MAP.putExact(token, dyn);
                }
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
                    MAP.addGenericExact(token);
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (FILE.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        StringTokenizer tokenizer = new StringTokenizer(line, " ");
                        String token = tokenizer.nextToken();
                        if (token.equals("PUT")) {
                            String generic = tokenizer.nextToken();
                            boolean dynamic = Boolean.valueOf(tokenizer.nextToken());
                            MAP.putExact(generic, dynamic);
                        } else if (token.equals("DROP")) {
                            String generic = tokenizer.nextToken();
                            MAP.dropGenericExact(generic);
                        } else if (token.equals("REP")) {
                            String zone = tokenizer.nextToken();
                            float xiSum = Float.parseFloat(tokenizer.nextToken());
                            float xi2Sum = Float.parseFloat(tokenizer.nextToken());
                            int last = Integer.parseInt(tokenizer.nextToken());
                            String flag = tokenizer.nextToken();
                            byte min = 0;
                            byte max = 0;
                            if (tokenizer.hasMoreTokens()) {
                                min = Byte.parseByte(tokenizer.nextToken());
                                max = Byte.parseByte(tokenizer.nextToken());
                            }
                            Node.load(zone, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("QUEUE")) {
                            String helo = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(helo, value);
                        }
                    } catch (Exception ex) {
                        Server.logError(line);
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, FILE);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        startWriter();
    }
    
    public static boolean store() {
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    TreeMap<String,Boolean> map = MAP.getMapAll();
                    for (String generic : map.keySet()) {
                        boolean dynamic = map.get(generic);
                        writer.write("PUT ");
                        writer.write(generic);
                        writer.write(' ');
                        writer.write(Boolean.toString(dynamic));
                        writer.write('\n');
                        writer.flush();
                    }
                    ROOT.store(writer, ".");
                    THREAD.store(writer);
                }
                Files.move(temp, source, REPLACE_EXISTING);
                Server.logStore(time, FILE);
                return true;
            } finally {
                startWriter();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }

    private static final Node ROOT = new Node();
    
    public static boolean addHarmful(String helo) {
        return addOperation(helo, (byte) -4);
    }
    
    public static boolean addUndesirable(String helo) {
        return addOperation(helo, (byte) -2);
    }
    
    public static boolean addUnacceptable(String helo) {
        return addOperation(helo, (byte) -1);
    }
    
    public static boolean addAcceptable(String helo) {
        return addOperation(helo, (byte) 1);
    }
    
    public static boolean addDesirable(String helo) {
        return addOperation(helo, (byte) 2);
    }
    
    public static boolean addBeneficial(String helo) {
        return addOperation(helo, (byte) 4);
    }
    
    private static boolean addOperation(String helo, Byte value) {
        if (helo == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(helo, value));
            return true;
        }
    }
    
    public static boolean isDynamicPattern(String mask) {
        if (mask == null) {
            return false;
        } else {
            String domain = Domain.extractDomainSafe(mask, false);
            if (domain != null) {
                mask = mask.replace(domain, "");
            }
            if (mask.matches(".*\\bdynamic\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bftth\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bpppoe\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bnat\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bcgnat\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bdinamico\\b.*")) {
                return true;
            } else if (mask.matches(".*\\badsl\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bwireless\\b.*")) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    private static boolean isStaticPattern(String mask) {
        if (mask == null) {
            return false;
        } else {
            String domain = Domain.extractDomainSafe(mask, false);
            if (domain != null) {
                mask = mask.replace(domain, "");
            }
            if (mask.matches(".*\\bstatic\\b.*")) {
                return true;
            } else if (mask.matches(".*\\bdedicated\\b.*")) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    private static final ProcessThread THREAD = new ProcessThread();
    
    public static void startThread() {
        THREAD.start();
    }
    
    public static void terminateThread() {
        THREAD.terminate();
    }
    
    private static class ProcessThread extends Thread {
        
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private boolean run = true;
        
        private ProcessThread() {
            super("GNRCTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notifyQueue();
        }
        
        private SimpleImmutableEntry poll() {
            return QUEUE.poll();
        }
        
        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        private boolean continueRun() {
            return run;
        }
        
        public void terminate() {
            run = false;
            notifyQueue();
        }
        
        public synchronized void notifyQueue() {
            notify();
        }
        
        @Override
        public void run() {
            try {
                Server.logTrace("thread started.");
                SimpleImmutableEntry<String,Byte> entry;
                while (Core.isRunning() && continueRun()) {
                    while (Core.isRunning() && (entry = poll()) != null) {
                        String helo = entry.getKey();
                        String mask;
                        if (isValidIPv4(helo)) {
                            mask = ".#";
                        } else if (Domain.isRootDomain(helo)) {
                            mask = Generic.convertDomainToMask(helo);
                        } else {
                            mask = Generic.convertHostToMask(helo);
                        }
                        if (mask != null) {
                            byte value = entry.getValue();
                            if (value < -1 && Ignore.containsFQDN(helo)) {
                                value = -1;
                            } else if (value < -2 && Provider.containsFQDN(helo)) {
                                value = -2;
                            }
//                            Server.logTrace("reputation " + value + " " + mask);
                            int level = 0;
                            LinkedList<String> stack = new LinkedList<>();
                            StringTokenizer tokenizer = new StringTokenizer(mask, ".");
                            while (tokenizer.hasMoreTokens()) {
                                stack.push(tokenizer.nextToken());
                            }
                            Node reputation = ROOT;
                            String zone = ".";
                            reputation.addValue(value, level);
                            Flag flag = reputation.refreshFlag(zone, level, Flag.ACCEPTABLE);
                            while (!stack.isEmpty()) {
                                if (++level > 7) {
                                    break;
                                } else {
                                    String key = stack.pop();
                                    reputation = reputation.newReputation(zone, key);
                                    if (reputation == null) {
                                        break;
                                    } else {
                                        zone += key + '.';
                                        reputation.addValue(value, level);
                                        flag = reputation.refreshFlag(zone, level, flag);
                                    }
                                }
                            }
                            if (flag == Flag.HARMFUL || flag == Flag.UNDESIRABLE) {
                                if (!Generic.containsGeneric(mask)) {
                                    if (isDynamicPattern(mask) && addDynamicExact(mask)) {
                                        Server.logDebug(null, "new DYNAMIC '" + mask + "' added by '" + flag.name() + "'.");
                                    } else if (isStaticPattern(mask) && Generic.addGenericSafe(mask)) {
                                        Server.logDebug(null, "new GENERIC '" + mask + "' added by '" + flag.name() + "'.");
                                    }
                                }
                            }
                        }
                    }
                    waitNext();
                }
                
            } finally {
                Server.logTrace("thread closed.");
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String fqdn = entry.getKey();
                    Byte value = entry.getValue();
                    writer.write("QUEUE ");
                    writer.write(fqdn);
                    if (value != null) {
                        writer.write(' ');
                        writer.write(Byte.toString(value));
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
    
    public static Flag getFlag(String helo) {
        if (helo == null) {
            return null;
        } else if (!Regex.isHostname(helo)) {
            return UNACCEPTABLE;
        } else {
            String mask = Generic.convertHostToMask(helo);
            if (mask == null) {
                return ACCEPTABLE;
            } else {
                LinkedList<String> stack = new LinkedList<>();
                StringTokenizer tokenizer = new StringTokenizer(mask, ".");
                while (tokenizer.hasMoreTokens()) {
                    stack.push(tokenizer.nextToken());
                }
                Node node = ROOT;
                Flag flag = node.getFlag();
                while (!stack.isEmpty()) {
                    String key = stack.pop();
                    node = node.getReputation(key);
                    if (node == null) {
                        break;
                    } else {
                        Flag newFlag = node.getFlag();
                        if (newFlag == null) {
                            break;
                        } else {
                            flag = newFlag;
                        }
                    }
                }
                return flag;
            }
        }
    }

    private static class Node extends Reputation {
        
        private static final int POPULATION[] = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private Node() {
            super();
        }
        
        private Node(Node other) {
            super(other, 2.0f);
        }
        
        private void addValue(int value, int level) {
            super.add(value, POPULATION[level]);
        }
        
        private TreeMap<String,Node> MAP = null;
        
        private synchronized Node newReputation(String zone, String key) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (key == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (flag == Flag.HARMFUL && minimum == -4 && maximum == -4) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1) {
                MAP = null;
                return null;
            } else if (flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1) {
                MAP = null;
                return null;
            } else if (flag == Flag.DESIRABLE && minimum == 2 && maximum == 2) {
                MAP = null;
                return null;
            } else if (flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4) {
                MAP = null;
                return null;
            } else {
                Node node = null;
                if (MAP == null) {
                    MAP = new TreeMap<>();
                } else {
                    node = MAP.get(key);
                }
                if (node == null) {
                    node = new Node(this);
                    MAP.put(key, node);
                }
                return node;
            }
        }
        
        private synchronized void clearMap() {
            MAP = null;
        }
        
        private synchronized void dropMap(String key) {
            if (MAP != null) {
                MAP.remove(key);
                if (MAP.isEmpty()) {
                    MAP = null;
                }
            }
        }
        
        private synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAP != null) {
                keySet.addAll(MAP.keySet());
            }
            return keySet;
        }
        
        private synchronized Node getReputation(String key) {
            if (MAP == null) {
                return null;
            } else {
                return MAP.get(key);
            }
        }
        
        private Flag refreshFlag(String zone, int level, Flag defaultFlag) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION[level], false
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP " + zone + " " + xisArray[0] + " " + xisArray[1] + " "
                                + last + " " + newFlag + " "
                                + extremes[0] + " " + extremes[1]
                );
            }
            if (newFlag == null) {
                return defaultFlag;
            } else {
                return newFlag;
            }
        }
        
        private static void load(
                String zone,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                Node node = ROOT;
                String zoneNode = ".";
                while (node != null && tokenizer.hasMoreTokens()) {
                    String key = tokenizer.nextToken();
                    node = node.newReputation(zoneNode, key);
                    zoneNode += key + '.';
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void store(FileWriter writer, String zone) throws IOException {
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REP ");
            writer.write(zone);
            writer.write(' ');
            writer.write(Float.toString(xiResult[0]));
            writer.write(' ');
            writer.write(Float.toString(xiResult[1]));
            writer.write(' ');
            writer.write(Integer.toString(last));
            writer.write(' ');
            writer.write(flag.toString());
            writer.write(' ');
            writer.write(Byte.toString(extremes[0]));
            writer.write(' ');
            writer.write(Byte.toString(extremes[1]));
            writer.write('\n');
            writer.flush();
            if (flag instanceof Integer) {
                clearMap();
            } else if (flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4) {
                clearMap();
            } else if (flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2) {
                clearMap();
            } else if (flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1) {
                clearMap();
            } else if (flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1) {
                clearMap();
            } else if (flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2) {
                clearMap();
            } else if (flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4) {
                clearMap();
            } else {
                for (String key : keySet()) {
                    Node reputation = getReputation(key);
                    if (reputation != null) {
                        if (reputation.isExpired()) {
                            dropMap(key);
                        } else {
                            reputation.store(writer, zone + key + '.');
                        }
                    }
                }
            }
        }
    }
}
