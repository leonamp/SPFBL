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
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
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
        
        public static boolean contains(String token) {
            return SET.contains(token);
        }
    }
    
    /**
     * Representa o conjunto de blocos IP de provedores.
     */
    private static class CIDR {
        
        private static final AddressSet SET = new AddressSet();
        
        public static void load() {
            try {
                File file = new File("./data/provider.cidr.txt");
                if (file.exists()) {
                    SET.start(file);
                }
            } catch (IOException ex) {
                Server.logError(ex);
            }
        }
        
        public static TreeSet<String> getAll() {
            return SET.getAllLegacy();
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
        
        private static boolean addExact(String token) {
            if (token == null) {
                return false;
            } else if (token.startsWith("CIDR=")) {
                return SET.add(token.substring(5));
            } else {
                return SET.add(token);
            }
        }
        
        public static boolean contains(String cidr) {
            return SET.contains(cidr);
        }
        
        public static String get(String client, String ip) {
            if (client == null) {
                return SET.getLegacy(ip);
            } else {
                return null;
            }
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
        return SPF.normalizeToken(
                token, false, false, true, false,
                false, false, false, false, false
        );
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
        } else if (isValidIP(token)) {
            String ip = Subnet.normalizeIP(token);
            return containsIPorFQDN(ip);
        } else if (isHostname(token)) {
            String host = Domain.normalizeHostname(token, true);
            return containsDomain(host);
        } else {
            return false;
        }
    }
    
    public static boolean containsCIDR(String ip) {
        if (ip == null) {
            return false;
        } else {
            return CIDR.contains(ip);
        }
    }
    
    public static boolean containsIPorFQDN(String ip) {
        if (ip == null) {
            return false;
        } else if (CIDR.contains(ip)) {
            return true;
        } else {
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
        }
    }
    
    private static final Regex EMAIL_OUTLOOK_GENERIC = new Regex("^outlook_[0-9a-f]{16}@outlook.com$");
    
    public static boolean isFreeMail(String sender) {
        if ((sender = Domain.normalizeEmail(sender)) == null) {
            return false;
        } else if (EMAIL_OUTLOOK_GENERIC.matches(sender)) {
            return false;
        } else if (isValidEmail(sender)) {
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
    
    public static boolean containsDomainEmail(String email) {
        if (email == null) {
            return false;
        } else {
            int index = email.indexOf('@') + 1;
            String hostname = '.' + email.substring(index);
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
    
    public static String returnProviderPTR(Set<String> tokenSet) {
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
        if ((host = Domain.extractHost(host, true)) == null) {
            return false;
        } else if (SET.contains(host)) {
            return true;
        } else {
            int index;
            while ((index = host.indexOf('.', 1)) > 0) {
                host = host.substring(index);
                if (SET.contains(host)) {
                    return true;
                }
            }
            return false;
        }
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
                        // Do nothing.
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
