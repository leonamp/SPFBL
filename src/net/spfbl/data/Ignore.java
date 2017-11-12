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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de elementos que o sistema deve ignorar.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Ignore {
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    /**
     * Conjunto de remetentes bloqueados.
     */
    private static class SET {
        
        private static final HashSet<String> SET = new HashSet<>();
        
        public static synchronized boolean isEmpty() {
            return SET.isEmpty();
        }
        
        public static synchronized void clear() {
            SET.clear();
        }
        
        public static synchronized TreeSet<String> getAll() {
            TreeSet<String> set = new TreeSet<>();
            set.addAll(SET);
            return set;
        }
        
        private static synchronized boolean addExact(String token) {
            return SET.add(token);
        }
        
        private static synchronized boolean dropExact(String token) {
            return SET.remove(token);
        }
        
        public static synchronized boolean contains(String token) {
            return SET.contains(token);
        }
    }
    
    /**
     * Representa o conjunto de blocos IP bloqueados.
     */
    private static class CIDR {
        
        private static final HashMap<String,TreeSet<String>> MAP = new HashMap<>();
        
        public static synchronized boolean isEmpty() {
            return MAP.isEmpty();
        }
        
        public static synchronized void clear() {
            MAP.clear();
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
        
        private static synchronized TreeSet<String> getClientSet(String client) {
            return MAP.get(client);
        }
        
        public static boolean contains(String client, String cidr) {
            if (cidr == null) {
                return false;
            } else {
                String key = Subnet.expandCIDR(cidr);
                TreeSet<String> cidrSet = getClientSet(client);
                return cidrSet.contains(key);
            }
        }
        
        private static String getFloor(String client, String ip) {
            TreeSet<String> cidrSet = getClientSet(client);
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

        public static String get(String client, String ip) {
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
            return result;
        }
    }

    public static boolean addExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("CIDR=")) {
            if (CIDR.addExact(token)) {
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
        TreeSet<String> ignoreSet = SET.getAll();
        ignoreSet.addAll(CIDR.getAll());
        return ignoreSet;
    }

    public static boolean containsExact(String address) {
        return SET.contains(address);
    }

    public static boolean dropExact(String token) {
        if (token == null) {
            return false;
        } else if (token.contains("CIDR=")) {
            if (CIDR.dropExact(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else if (SET.dropExact(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    private static String normalizeTokenCIDR(String token) throws ProcessException {
        return SPF.normalizeToken(token, false, false, true, false, false, false);
    }

    public static boolean add(String token) throws ProcessException {
        if ((token = normalizeTokenCIDR(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (addExact(token)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> dropAll() throws ProcessException {
        TreeSet<String> ignoreSet = new TreeSet<>();
        for (String token : getAll()) {
            if (dropExact(token)) {
                ignoreSet.add(token);
            }
        }
        return ignoreSet;
    }

    public static boolean drop(String token) throws ProcessException {
        if ((token = normalizeTokenCIDR(token)) == null) {
            throw new ProcessException("TOKEN INVALID");
        } else if (dropExact(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean containsCIDR(String ip) {
        return CIDR.get(null, ip) != null;
    }
    
    public static boolean containsSoft(String token) {
        if (token == null) {
            return false;
        } else if (Domain.isValidEmail(token)) {
            if (Ignore.containsExact(token = token.toLowerCase())) {
                return true;
            } else {
                int index = token.indexOf('@') + 1;
                String hostname = token.substring(index);
                return Ignore.containsHost(hostname);
            }
        } else if (Domain.isHostname(token)) {
            String hostname = Domain.normalizeHostname(token, true);
            return Ignore.containsHost(hostname);
        } else {
            return false;
        }
    }

    public static boolean contains(String token) {
        if (token == null) {
            return false;
        } else {
            // Verifica o remetente.
            if (token.startsWith("@")) {
                String sender = token.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (containsExact(sender)) {
                    return true;
                } else if (containsExact(part)) {
                    return true;
                } else if (containsExact(senderDomain)) {
                    return true;
                } else if (containsHost('.' + senderDomain.substring(1))) {
                    return true;
                } else {
                    int index3 = senderDomain.length();
                    while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = senderDomain.substring(0, index3 + 1);
                        if (containsExact(subdomain)) {
                            return true;
                        }
                    }
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (containsExact(subsender)) {
                            return true;
                        }
                    }
                }
            } else if (token.contains("@")) {
                String sender = token.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                if (containsExact(sender)) {
                    return true;
                } else if (containsExact(part)) {
                    return true;
                } else {
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (containsExact(subsender)) {
                            return true;
                        }
                    }
                }
            }
            // Verifica o HELO.
            String helo;
            if ((helo = Domain.extractHost(token, true)) != null) {
                if (containsHost(helo)) {
                    return true;
                }
            }
            // Verifica o IP.
            String ip;
            if (Subnet.isValidIP(token)) {
                ip = Subnet.normalizeIP(token);
                if (containsExact(ip)) {
                    return true;
                } else if (CIDR.get(null, ip) != null) {
                    return true;
                }
            }
            return false;
        }
    }

    public static boolean containsHost(String host) {
        do {
            int index = host.indexOf('.') + 1;
            host = host.substring(index);
            String token = '.' + host;
            if (containsExact(token)) {
                return true;
            }
        } while (host.contains("."));
        return false;
    }

    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing ignore.set");
                long time = System.currentTimeMillis();
                File file = new File("./data/ignore.set");
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
        File file = new File("./data/ignore.set");
        if (file.exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                // Processo temporário de transição.
                for (String token : set) {
                    if ((token = normalizeTokenCIDR(token)) != null) {
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
                        }
                        try {
                            if (client == null) {
                                addExact(identifier);
                            } else {
                                addExact(client + ':' + identifier);
                            }
                        } catch (ProcessException ex) {
                            Server.logDebug("IGNORE CIDR " + identifier + " " + ex.getErrorMessage());
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
