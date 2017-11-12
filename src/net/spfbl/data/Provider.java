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
public class Provider {
    
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
            TreeSet<String> set = new TreeSet<>();
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
                set = new TreeSet<>();
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
    
    private static boolean dropExact(String token) {
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

    private static boolean addExact(String token) throws ProcessException {
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
        if (address == null) {
            return false;
        } else {
            return SET.contains(address);
        }
    }
    
    private static String normalizeProvider(String token) throws ProcessException {
        return SPF.normalizeToken(token, false, false, true, false, false, false);
    }

    public static boolean add(String address) throws ProcessException {
        if ((address = normalizeProvider(address)) == null) {
            throw new ProcessException("ERROR: PROVIDER INVALID");
        } else if (addExact(address)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> dropAll() throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<>();
        for (String token : getAll()) {
            if (dropExact(token)) {
                blockSet.add(token);
            }
        }
        return blockSet;
    }

    public static boolean drop(String address) throws ProcessException {
        if ((address = normalizeProvider(address)) == null) {
            throw new ProcessException("ERROR: PROVIDER INVALID");
        } else if (dropExact(address)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean contains(String token) {
        if (token == null) {
            return false;
        } else if (Subnet.isValidIP(token)) {
            String ip = Subnet.normalizeIP(token);
            return containsCIDR(ip);
        } else if (Domain.isHostname(token)) {
            String host = Domain.normalizeHostname(token, true);
            return containsDomain(host);
        } else {
            return false;
        }
    }
    
    public static boolean containsCIDR(String ip) {
        return CIDR.get(null, ip) != null;
    }
    
    public static boolean containsMX(String sender) {
        if (sender == null) {
            return false;
        } else if (Domain.isMailFrom(sender)) {
            int index = sender.indexOf('@');
            return SET.contains(sender.substring(index));
        } else {
            return false;
        }
    }
    
    public static boolean containsDomain(String address) {
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
                    if (SET.contains('.' + hostname)) {
                        return true;
                    }
                } while (hostname.contains("."));
                return false;
            }
        }
    }

    public static boolean containsHELO(String ip, String helo) {
        if (SPF.matchHELO(ip, helo)) {
            helo = Domain.extractHost(helo, true);
            do {
                int index = helo.indexOf('.') + 1;
                helo = helo.substring(index);
                if (SET.contains('.' + helo)) {
                    return true;
                }
            } while (helo.contains("."));
        }
        return CIDR.get(null, ip) != null;
    }

    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/provider.set");
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
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/provider.set");
        if (file.exists()) {
            try {
                TreeSet<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                for (String token : set) {
                    try {
                        addExact(token);
                    } catch (ProcessException ex) {
                        Server.logDebug("PROVIDER CIDR " + token + " " + ex.getErrorMessage());
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
