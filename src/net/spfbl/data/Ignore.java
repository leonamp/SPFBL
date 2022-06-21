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
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import net.spfbl.core.ProcessException;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
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
        
        public static boolean contains(String token) {
            return SET.contains(token);
        }
    }
    
    /**
     * Representa o conjunto de blocos IP de ignorados.
     */
    private static class CIDR {
        
        private static final AddressSet SET = new AddressSet();
        
        public static void load() {
            try {
                File file = new File("./data/ignore.cidr.txt");
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

    public static boolean addExact(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (token.contains("CIDR=")) {
            if (CIDR.addExact(token)) {
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
        return SPF.normalizeToken(
                token, false, false, true, false,
                false, false, false, false, false
        );
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
    
    public static String returnIgnorePTR(Set<String> tokenSet) {
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
    
    public static boolean containsIPorFQDN(String ip) {
        if (ip == null) {
            return false;
        } else if (CIDR.get(null, ip) == null) {
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
    
    public static boolean containsIP(String ip) {
        if (ip == null) {
            return false;
        } else {
            return CIDR.get(null, ip) != null;
        }
    }
    
    public static boolean containsSoft(String token) {
        if (token == null) {
            return false;
        } else if (isValidEmail(token)) {
            if (Ignore.containsExact(token = token.toLowerCase())) {
                return true;
            } else {
                int index = token.indexOf('@') + 1;
                String hostname = token.substring(index);
                return Ignore.containsHost(hostname);
            }
        } else if (isHostname(token)) {
            String hostname = Domain.normalizeHostname(token, true);
            return Ignore.containsHost(hostname);
        } else {
            return false;
        }
    }
    
    public static boolean containsSender(String sender) {
        if (sender == null) {
            return false;
        } else if (sender.contains("@")) {
            int index = sender.lastIndexOf('@');
            sender = sender.substring(index);
            return Ignore.containsExact(sender);
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
            if (isValidIP(token)) {
                ip = Subnet.normalizeIP(token);
                return containsIPorFQDN(ip);
            }
            return false;
        }
    }

    public static boolean containsHost(String host) {
        if (host == null) {
            return false;
        } else {
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
    }

    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing ignore.set");
                long time = System.currentTimeMillis();
                File file = new File("./data/ignore.set");
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
        File file = new File("./data/ignore.set");
        if (file.exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                // Processo temporário de transição.
                for (String token : set) {
                    String normalized;
                    if (token.contains(":MALWARE=")) {
                        normalized = token;
                    } else {
                        normalized = normalizeTokenCIDR(token);
                    }
                    if (normalized == null) {
                        Server.logError("undefined ignore pattern: " + token);
                    } else {
                        token = normalized;
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
                        if (isValidCIDR(identifier)) {
                            identifier = "CIDR=" + Subnet.normalizeCIDR(identifier);
                        }
                        try {
                            if (client == null) {
                                addExact(identifier);
                            } else {
                                addExact(client + ':' + identifier);
                            }
                        } catch (ProcessException ex) {
                            // DO nothing.
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
