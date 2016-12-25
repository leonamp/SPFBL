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
package net.spfbl.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.TreeSet;
import net.spfbl.data.Generic;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um bloco cliente do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Client implements Serializable, Comparable<Client> {
    
    private static final long serialVersionUID = 1L;

    private final String cidr;
    private String domain;
    private String email;
    private Permission permission = Permission.NONE;
    private Personality personality = Personality.RATIONAL;
    private int limit = 100;
    private NormalDistribution frequency = null;
    private long last = 0;
    
    private Action actionBLOCK = Action.REJECT;
    private Action actionRED = Action.FLAG;
    
    public enum Permission {
        NONE,
        DNSBL,
        SPFBL,
        ALL
    }
    
    public enum Personality {
        PASSIVE,
        RATIONAL,
        AGRESSIVE
    }
    
    private Client(String cidr, String domain, String email) throws ProcessException {
        if (Subnet.isValidCIDR(cidr) && (domain == null || Domain.isHostname(domain))) {
            this.cidr = Subnet.normalizeCIDR(cidr);
            this.domain = Domain.extractHost(domain, false);
            if (email == null || email.length() == 0) {
                this.email = null;
            } else if (Domain.isEmail(email)) {
                this.email = email.toLowerCase();
            } else {
                throw new ProcessException("INVALID EMAIL");
            }
        } else {
            throw new ProcessException("INVALID CLIENT");
        }
    }
    
    public void setDomain(String domain) throws ProcessException {
        if (domain == null) {
            this.domain = null;
            CHANGED = true;
        } else if (Domain.isHostname(domain)) {
            this.domain = Domain.extractHost(domain, false);
            CHANGED = true;
        } else {
            throw new ProcessException("INVALID DOMAIN");
        }
    }
    
    public void setEmail(String email) throws ProcessException {
        if (email == null || email.length() == 0) {
            this.email = null;
            CHANGED = true;
        } else if (Domain.isEmail(email)) {
            this.email = email.toLowerCase();
            CHANGED = true;
        } else {
            throw new ProcessException("INVALID EMAIL");
        }
    }
    
    public boolean tryPermission(String permission) {
         try {
             setPermission(permission);
             return true;
         } catch (ProcessException ex) {
             return false;
         }
    }
    
    public void setPermission(String permission) throws ProcessException {
        try {
            setPermission(Permission.valueOf(permission));
        } catch (Exception ex) {
            throw new ProcessException("INVALID PERMISSION");
        }
    }
    
    public void setPermission(Permission permission) throws ProcessException {
        if (permission == null) {
            throw new ProcessException("INVALID PERMISSION");
        } else if (this.permission != permission) {
            this.permission = permission;
            CHANGED = true;
        }
    }
    
    public boolean setPersonality(String personality) throws ProcessException {
        try {
            return setPersonality(Personality.valueOf(personality));
        } catch (Exception ex) {
            throw new ProcessException("INVALID PERSONALITY");
        }
    }
    
    public boolean setPersonality(Personality personality) throws ProcessException {
        if (personality == null) {
            throw new ProcessException("INVALID PERSONALITY");
        } else if (this.personality == personality) {
            return false;
        } else {
            this.personality = personality;
            return CHANGED = true;
        }
    }
    
    public boolean setActionBLOCK(String action) throws ProcessException {
        try {
            return setActionBLOCK(Action.valueOf(action));
        } catch (Exception ex) {
            throw new ProcessException("INVALID BLOCK ACTION");
        }
    }
    
    public boolean setActionBLOCK(Action action) throws ProcessException {
        if (action == null || action == Action.DEFER) {
            throw new ProcessException("INVALID BLOCK ACTION");
        } else if (this.actionBLOCK == action) {
            return false;
        } else {
            this.actionBLOCK = action;
            return CHANGED = true;
        }
    }
    
    public boolean setActionRED(String action) throws ProcessException {
        try {
            return setActionRED(Action.valueOf(action));
        } catch (Exception ex) {
            throw new ProcessException("INVALID RED ACTION");
        }
    }
    
    public boolean setActionRED(Action action) throws ProcessException {
        if (action == null) {
            throw new ProcessException("INVALID RED ACTION");
        } else if (this.actionRED == action) {
            return false;
        } else {
            this.actionRED = action;
            return CHANGED = true;
        }
    }
    
    public boolean setLimit(String limit) throws ProcessException {
        try {
            return setLimit(Integer.parseInt(limit));
        } catch (NumberFormatException ex) {
            throw new ProcessException("INVALID LIMIT", ex);
        }
    }
    
    public boolean setLimit(int limit) throws ProcessException {
        if (limit <= 0 || limit > 3600000) {
            throw new ProcessException("INVALID LIMIT");
        } else if (this.limit == limit) {
            return false;
        } else {
            this.limit = limit;
            return CHANGED = true;
        }
    }
    
    public String getCIDR() {
        return cidr;
    }
    
    public String getDomain() {
        if (domain == null) {
            return "NXDOMAIN";
        } else {
            return domain;
        }
    }
    
    public String getEmail() {
        return email;
    }
    
    public User getUser() {
        return User.get(email);
    }
    
    public boolean hasUser() {
        return User.exists(email);
    }
    
    public boolean hasEmail() {
        return email != null;
    }
    
    public boolean hasSecretOTP() {
        User user = getUser();
        if (user == null) {
            return false;
        } else {
            return user.hasSecretOTP();
        }
    }
    
    public boolean contains(String ip) {
        return Subnet.containsIP(cidr, ip);
    }
    
    public Permission getPermission() {
        return permission;
    }
    
    public boolean hasPermission(Permission permission) {
        if (this.permission == Permission.NONE) {
            return permission == Permission.NONE;
        } else if (this.permission == Permission.ALL) {
            return permission != Permission.NONE;
        } else {
            return this.permission == permission;
        }
    }
    
    public boolean isPassive() {
        return personality == Personality.PASSIVE;
    }
    
    public boolean isAgressive() {
        return personality == Personality.AGRESSIVE;
    }
    
    public Personality getPersonality() {
        return personality;
    }
    
    public Action getActionBLOCK() {
        return actionBLOCK;
    }
    
    public Action getActionRED() {
        return actionRED;
    }
    
    /**
     * Mapa de usuário com busca log2(n).
     */
    private static final TreeMap<String,Client> MAP = new TreeMap<String,Client>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public static Client create(
            String cidr, String domain, String permission, String email
            ) throws ProcessException {
        if (Subnet.isValidCIDR(cidr)) {
            String ip = Subnet.getFirstIP(cidr);
            Client client = getByIP(ip);
            if (client == null) {
                ip = Subnet.expandIP(ip);
                client = new Client(cidr, domain, email);
                client.setPermission(permission);
                MAP.put(ip, client);
                CHANGED = true;
                return client;
            } else {
                return null;
            }
        } else {
            throw new ProcessException("INVALID CIDR");
        }
    }
    
    public synchronized static TreeSet<Client> getSet() {
        TreeSet<Client> clientSet = new TreeSet<Client>();
        clientSet.addAll(MAP.values());
        return clientSet;
    }
    
    public static TreeSet<Client> dropAll() throws ProcessException {
        TreeSet<Client> clientSet = new TreeSet<Client>();
        for (Client client : getSet()) {
            if (client != null) {
                String cidr = client.getCIDR();
                client = drop(cidr);
                if (client != null) {
                    clientSet.add(client);
                }
            }
        }
        return clientSet;
    }
    
    public static Client drop(String cidr) throws ProcessException {
        if (cidr == null || !Subnet.isValidCIDR(cidr)) {
            throw new ProcessException("INVALID CIDR");
        } else {
            cidr = Subnet.normalizeCIDR(cidr);
            String ip = Subnet.getFirstIP(cidr);
            String key = Subnet.expandIP(ip);
            Client client = getExact(key);
            if (client == null) {
                return null;
            } else if (client.getCIDR().equals(cidr)) {
                return dropExact(key);
            } else {
                return null;
            }
        }
    }
    
    private synchronized static Client getExact(String key) {
        return MAP.get(key);
    }
    
    private synchronized static Client dropExact(String key) {
        Client client = MAP.remove(key);
        if (client != null) {
            CHANGED = true;
        }
        return client;
    }
    
    public static String getOrigin(InetAddress address) {
        if (address == null) {
            return "UNKNOWN";
        } else {
            String ip = address.getHostAddress();
            Client client = Client.get(address);
            if (client == null) {
                return ip + " UNKNOWN";
            } else if (client.hasEmail()) {
                return ip + " " + client.getDomain() + " " + client.getEmail();
            } else {
                return ip + " " + client.getDomain();
            }
        }
    }
    
    public static String getIdentification(InetAddress address) {
        if (address == null) {
            return "UNKNOWN";
        } else {
            Client client = Client.get(address);
            if (client == null) {
                return "UNKNOWN";
            } else if (client.hasEmail()) {
                return client.getEmail();
            } else {
                return client.getDomain();
            }
        }
    }
    
    public static String getDomain(InetAddress address) {
        if (address == null) {
            return "UNKNOW";
        } else {
            String ip = address.getHostAddress();
            Client client = getByIP(ip);
            if (client == null) {
                return ip;
            } else {
                return client.getDomain();
            }
        }
    }
    
    public static Client getByEmail(String email) throws ProcessException {
        if (email == null) {
            return null;
        } else if (!Domain.isEmail(email)) {
            throw new ProcessException("INVALID E-MAIL");
        } else {
            return MAP.get(email);
        }
    }
    
    public synchronized static Client getByCIDR(String cidr) throws ProcessException {
        if (cidr == null) {
            return null;
        } else if (!Subnet.isValidCIDR(cidr)) {
            throw new ProcessException("INVALID CIDR");
        } else {
            cidr = Subnet.normalizeCIDR(cidr);
            String ip = Subnet.getFirstIP(cidr);
            String key = Subnet.expandIP(ip);
            Client cliente = getExact(key);
            if (cliente == null) {
                return null;
            } else if (cliente.getCIDR().equals(cidr)) {
                return cliente;
            } else {
                return null;
            }
        }
    }
    
    public static Client get(InetAddress address) {
        if (address == null) {
            return null;
        } else {
            return getByIP(address.getHostAddress());
        }
    }
    
    public static Client create(
            InetAddress address,
            String permissao
            ) throws ProcessException {
        Client client = get(address);
        if (client == null) {
            String cidr = null;
            if (address instanceof Inet4Address) {
                cidr = address.getHostAddress() + "/32";
            } else if (address instanceof Inet6Address) {
                cidr = address.getHostAddress() + "/128";
            }
            if (cidr != null) {
                String ip = address.getHostAddress();
                String hostame = Reverse.getHostname(ip);
                String domain;
                if (Generic.contains(hostame)) {
                    domain = null;
                } else {
                    try {
                        domain = Domain.extractDomain(hostame, false);
                    } catch (ProcessException ex) {
                        domain = null;
                    }
                }
                client = Client.create(cidr, domain, permissao, null);
                if (client != null) {
                    Server.logDebug("CLIENT ADDED " + client);
                }
            }
        }
        return client;
    }
    
    public static HashMap<Object,TreeSet<Client>> getMap(Permission permission) {
        if (permission == null) {
            return null;
        } else {
            HashMap<Object,TreeSet<Client>> clientMap = new HashMap<Object,TreeSet<Client>>();
            for (Client client : getSet()) {
                if (client.hasPermission(permission)) {
                    User user = client.getUser();
                    Object key = user == null ? client.getDomain() : user;
                    TreeSet<Client> clientSet = clientMap.get(key);
                    if (clientSet == null) {
                        clientSet = new TreeSet<Client>();
                        clientMap.put(key, clientSet);
                    }
                    clientSet.add(client);
                }
            }
            return clientMap;
        }
    }
    
    public static TreeSet<Client> getSet(Permission permission) {
        if (permission == null) {
            return null;
        } else {
            TreeSet<Client> clientSet = new TreeSet<Client>();
            for (Client client : getSet()) {
                if (client.hasPermission(permission)) {
                    clientSet.add(client);
                }
            }
            return clientSet;
        }
    }
    
    public synchronized static Client getByIP(String ip) {
        if (ip == null) {
            return null;
        } else {
            String key = Subnet.expandIP(ip);
            key = MAP.floorKey(key);
            Client client;
            if (key == null) {
                return null;
            } else if ((client = MAP.get(key)).contains(ip)) {
                return client;
            } else {
                return null;
            }
        }
    }
    
    public static synchronized HashMap<String,Client> getMap() {
        HashMap<String,Client> map = new HashMap<String,Client>();
        map.putAll(MAP);
        return map;
    }
    
    public static void store() {
        if (CHANGED) {
            try {
                Server.logTrace("storing client.map");
                long time = System.currentTimeMillis();
                HashMap<String,Client> map = getMap();
                File file = new File("./data/client.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
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
    
    public static synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/client.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Client) {
                        Client client = (Client) value;
                        if (client.limit == 0) {
                            client.limit = 100;
                        }
                        if (client.actionBLOCK == null) {
                            client.actionBLOCK = Action.REJECT;
                        }
                        if (client.actionRED == null) {
                            client.actionRED = Action.FLAG;
                        }
                        if (client.personality == null) {
                            client.personality = Personality.RATIONAL;
                        }
                        MAP.put(key, client);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public boolean hasFrequency() {
        return frequency != null;
    }
    
    public long getIdleTimeMillis() {
        if (last == 0) {
            return 0;
        } else {
            return System.currentTimeMillis() - last;
        }
    }
    
    public boolean isAbusing() {
        if (frequency == null) {
            return false;
        } else if (isDead()) {
            return false;
        } else {
            return frequency.getMaximumInt() < limit;
        }
    }
    
    public boolean isDead() {
        int frequencyInt = frequency.getMaximumInt();
        long idleTimeInt = getIdleTimeMillis();
        return idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000;
    }
    
    public String getFrequencyLiteral() {
        if (hasFrequency()) {
            if (isDead()) {
                return "DEAD";
            } else {
                char sinal = '~';
                int frequencyInt = frequency.getMaximumInt();
                long idleTimeInt = getIdleTimeMillis();
                if (frequencyInt < limit) {
                    frequencyInt = limit;
                    sinal = '<';
                } else if (idleTimeInt > frequencyInt * 3) {
                    sinal = '>';
                }
                if (frequencyInt >= 3600000) {
                    return sinal + ((frequencyInt / 3600000) + "h");
                } else if (frequencyInt >= 60000) {
                    return sinal + ((frequencyInt / 60000) + "min");
                } else if (frequencyInt >= 1000) {
                    return sinal + ((frequencyInt / 1000) + "s");
                } else {
                    return sinal + (frequencyInt + "ms");
                }
            }
        } else {
            return "UNDEFINED";
        }
    }
    
    private Float getInterval() {
        long current = System.currentTimeMillis();
        Float interval;
        if (last == 0) {
            interval = null;
        } else {
            interval = (float) (current - last);
        }
        last = current;
        return interval;
    }
    
    public boolean addQuery() {
        Float interval = getInterval();
        if (interval == null) {
            return false;
        } else if (frequency == null) {
            frequency = new NormalDistribution(interval < 1000 ? 1000 : interval);
            return true;
        } else {
            frequency.addElement(interval);
            return true;
        }
    }
    
    @Override
    public int hashCode() {
        return email.hashCode();
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof Client) {
            Client other = (Client) o;
            return this.email.equals(other.email);
        } else {
            return false;
        }
    }
    
    @Override
    public int compareTo(Client other) {
        if (other == null) {
            return -1;
        } else {
            return this.toString().compareTo(other.toString());
        }
    }
    
    @Override
    public String toString() {
        User user = getUser();
        if (user == null) {
            return getDomain() + ":" + cidr
                    + (permission == null ? " NONE" : " " + permission.name())
                    + " " + getFrequencyLiteral()
                    + (email == null ? "" : " <" + email + ">");
        } else {
            return getDomain() + ":" + cidr
                    + (permission == null ? " NONE" : " " + permission.name())
                    + " " + getFrequencyLiteral()
                    + " " + user;
        }
    }
}
