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
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import net.spfbl.data.Generic;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
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
    private boolean administrator = false;
    private int limit = 100;
    
    private NormalDistribution frequency = null;
    private long last = 0;
    
    private Action actionBLOCK = Action.REJECT;
    private Action actionRED = Action.FLAG;
    private Action actionYELLOW = Action.DEFER;
    private Action actionGRACE = Action.DEFER;
    
    public enum Permission {
        NONE,
        DNSBL,
        SPFBL,
//        ALL // Obsoleto
    }
    
    public enum Personality {
        PASSIVE,
        RATIONAL,
        AGRESSIVE
    }
    
    private Client(Client other) {
        this.cidr = other.cidr;
        this.domain = other.domain;
        this.email = other.email;
        this.permission = other.permission;
        this.personality = other.personality;
        this.administrator = other.administrator;
        this.limit = other.limit;
        this.frequency = other.frequency == null ? null : other.frequency.replicate();
        this.last = other.last;
        this.actionBLOCK = other.actionBLOCK;
        this.actionRED = other.actionRED;
        this.actionYELLOW = other.actionYELLOW;
        this.actionGRACE = other.actionGRACE;
    }
    
    private Client(String cidr, String domain, String email) throws ProcessException {
        if (Subnet.isValidCIDR(cidr) && (domain == null || Domain.isHostname(domain))) {
            this.cidr = Subnet.normalizeCIDR(cidr);
            this.domain = Domain.extractHost(domain, false);
            if (email == null || email.length() == 0) {
                this.email = null;
            } else if (Domain.isValidEmail(email)) {
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
        } else if (Domain.isValidEmail(email)) {
            this.email = email.toLowerCase();
            CHANGED = true;
        } else {
            throw new ProcessException("INVALID EMAIL");
        }
    }
    
    public boolean tryPermission(String permission) {
         try {
             return setPermission(permission);
         } catch (ProcessException ex) {
             return false;
         }
    }
    
    public boolean isPermission(String permission) {
        if (permission == null) {
            return false;
        } else {
            return this.permission.name().equals(permission);
        }
    }
    
    public boolean isPermission(Permission permission) {
        if (permission == null) {
            return false;
        } else {
            return this.permission == permission;
        }
    }
    
    public boolean setPermission(String permission) throws ProcessException {
        try {
            if (permission == null) {
                return false;
            } else if (permission.equals("ADMIN")) {
                if (this.administrator) {
                    return false;
                } else {
                    this.permission = Permission.SPFBL;
                    this.administrator = true;
                    return CHANGED = true;
                }
            } else if (setPermission(Permission.valueOf(permission))) {
                this.administrator = false;
                return true;
            } else {
                return false;
            }
        } catch (Exception ex) {
            throw new ProcessException("INVALID PERMISSION");
        }
    }
    
    public boolean setPermission(Permission permission) throws ProcessException {
        if (permission == null) {
            throw new ProcessException("INVALID PERMISSION");
//        } else if (permission == Permission.ALL) {
//            if (this.administrator) {
//                return false;
//            } else {
//                this.permission = Permission.SPFBL;
//                this.administrator = true;
//                return CHANGED = true;
//            }
        } else if (this.permission == permission) {
            return false;
        } else {
            this.permission = permission;
            return CHANGED = true;
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
    
    public boolean setActionYELLOW(String action) throws ProcessException {
        try {
            return setActionYELLOW(Action.valueOf(action));
        } catch (Exception ex) {
            throw new ProcessException("INVALID YELLOW ACTION");
        }
    }
    
    public boolean setActionYELLOW(Action action) throws ProcessException {
        if (action == null) {
            throw new ProcessException("INVALID YELLOW ACTION");
        } else if (action == this.actionYELLOW) {
            return false;
        } else if (action == Action.DEFER) {
            this.actionYELLOW = Action.DEFER;
            return CHANGED = true;
        } else if (action == Action.HOLD) {
            this.actionYELLOW = Action.HOLD;
            return CHANGED = true;
        } else {
            throw new ProcessException("INVALID YELLOW ACTION");
        }
    }
    
    public boolean setActionGRACE(String action) throws ProcessException {
        try {
            return setActionGRACE(Action.valueOf(action));
        } catch (Exception ex) {
            throw new ProcessException("INVALID GRACE ACTION");
        }
    }
    
    public boolean setActionGRACE(Action action) throws ProcessException {
        if (action == null) {
            throw new ProcessException("INVALID GRACE ACTION");
        } else if (this.actionGRACE == action) {
            return false;
        } else {
            this.actionGRACE = action;
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
    
    public boolean isDomain(String domain) {
        if (domain == null) {
            return false;
        } else {
            return getDomain().equals(domain);
        }
    }
    
    public boolean isEmailDomaim(String domain) {
        String emailDomaim = getEmailDomaim();
        if (emailDomaim == null || domain == null) {
            return false;
        } else {
            int index = domain.indexOf('@') + 1;
            domain = Domain.normalizeHostname(domain.substring(index), true);
            emailDomaim = Domain.normalizeHostname(emailDomaim, true);
            return emailDomaim.equals(domain);
        }
    }
    
    public String getEmailDomaim() {
        String emailLocal = getEmail();
        if (emailLocal == null) {
            return null;
        } else {
            int index = emailLocal.indexOf('@') + 1;
            return emailLocal.substring(index);
        }
    }
    
    public boolean isEmailPostmaster() {
        String emailLocal = getEmail();
        if (emailLocal == null) {
            return false;
        } else {
            return emailLocal.startsWith("postmaster@");
        }
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
    
    public boolean isEmail(String email) {
        if (email == null) {
            return false;
        } else {
            return email.equals(this.email);
        }
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
    
    public boolean containsFull(String ip) {
        if (Subnet.containsIP(cidr, ip)) {
            return true;
        } else {
            Client client = getByIP(ip);
            if (client == null) {
                return false;
            } else {
                return client.isEmail(this.email);
            }
        }
    }
    
    public Permission getPermission() {
        return permission;
    }
    
    public boolean isAdministrator() {
        return administrator;
    }
    
    public boolean isAdministratorEmail() {
        return Core.isAdminEmail(email);
    }
    
    public boolean hasPermission(Permission permission) {
        if (this.permission == Permission.NONE) {
            return permission == Permission.NONE;
//        } else if (this.permission == Permission.ALL) {
//            return permission != Permission.NONE;
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
    
    public Action getActionYELLOW() {
        return actionYELLOW;
    }
    
    public Action getActionGRACE() {
        return actionGRACE;
    }
    
    /**
     * Mapa de usuário com busca log2(n).
     */
    private static final TreeMap<String,Client> MAP = new TreeMap<>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public static Client create(
            String cidr, String domain, String permission, String email
            ) throws ProcessException {
        if (Subnet.isValidCIDR(cidr)) {
            TreeSet<Client> clientSet = Client.getSetByCIDR(cidr, permission);
            if (clientSet == null || clientSet.isEmpty()) {
                String first = Subnet.getFirstIP(cidr);
                String ip = Subnet.expandIP(first);
                Client client = new Client(cidr, domain, email);
                client.setPermission(permission);
                put(ip, client);
                CHANGED = true;
                return client;
            } else {
                return null;
            }
        } else {
            throw new ProcessException("INVALID CIDR");
        }
    }
    
    private synchronized static Client put(String ip, Client client) {
        return MAP.put(ip, client);
    }
    
    public synchronized static TreeSet<Client> getSet() {
        TreeSet<Client> clientSet = new TreeSet<>();
        clientSet.addAll(MAP.values());
        return clientSet;
    }
    
    public static TreeSet<Client> getClientSet(String domain) {
        TreeSet<Client> clientSet = new TreeSet<>();
        for (Client client : getSet()) {
            if (client.isDomain(domain)) {
                clientSet.add(client);
            }
        }
        return clientSet;
    }
    
    public static TreeSet<Client> dropAll() throws ProcessException {
        TreeSet<Client> clientSet = new TreeSet<>();
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
    
    public static String getOrigin(InetAddress address, String permissao) {
        if (address == null) {
            return "UNKNOWN";
        } else {
            String ip = address.getHostAddress();
            Client client = Client.get(address, permissao);
            if (client == null) {
                return ip + " UNKNOWN";
            } else if (client.isPermission("DNSBL")) {
                return ip + " " + client.getDomain();
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
        } else if (!Domain.isValidEmail(email)) {
            throw new ProcessException("INVALID E-MAIL");
        } else {
            return getExact(email);
        }
    }
    
    public static Client getByEmailSafe(String email) {
        if (email == null) {
            return null;
        } else if (!Domain.isValidEmail(email)) {
            return null;
        } else {
            return getExact(email);
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
    
    public static Client get(InetAddress address, String permissao) {
        if (address instanceof Inet4Address) {
            return getByIP(address.getHostAddress(), permissao);
        } else if (address instanceof Inet6Address) {
            String ip = SubnetIPv6.getIPv4(address.getHostAddress());
            if (ip == null) {
                ip = address.getHostAddress();
            }
            return getByIP(ip, permissao);
        } else {
            return null;
        }
    }
    
    public static Client create(
            InetAddress address,
            String permissao
            ) throws ProcessException {
        Client client = get(address, permissao);
        if (client == null) {
            String ip = null;
            String cidr = null;
            if (address instanceof Inet4Address) {
                ip = SubnetIPv4.normalizeIPv4(address.getHostAddress());
                cidr = ip + "/32";
            } else if (address instanceof Inet6Address) {
                ip = SubnetIPv6.getIPv4(address.getHostAddress());
                if (ip == null) {
                    ip = SubnetIPv6.normalizeIPv6(address.getHostAddress());
                    cidr = ip + "/52";
                } else {
                    cidr = ip + "/32";
                }
            }
            if (ip != null && cidr != null) {
                client = Client.getByCIDR(cidr);
                if (client == null) {
                    String hostame = Reverse.getHostname(ip);
                    String domain;
                    if (Generic.containsGeneric(hostame)) {
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
                } else {
                    return client;
                }
            }
        }
        return client;
    }
    
    public static HashMap<Object,TreeSet<Client>> getMap(Permission permission) {
        if (permission == null) {
            return null;
        } else {
            HashMap<Object,TreeSet<Client>> clientMap = new HashMap<>();
            for (Client client : getSet()) {
                if (client.hasPermission(permission)) {
                    User user = client.getUser();
                    Object key = user == null ? client.getDomain() : user;
                    TreeSet<Client> clientSet = clientMap.get(key);
                    if (clientSet == null) {
                        clientSet = new TreeSet<>();
                        clientMap.put(key, clientSet);
                    }
                    clientSet.add(client);
                }
            }
            return clientMap;
        }
    }
    
    public static HashMap<Object,TreeSet<Client>> getAdministratorMap() {
        HashMap<Object,TreeSet<Client>> clientMap = new HashMap<>();
        for (Client client : getSet()) {
            if (client.isAdministrator()) {
                User user = client.getUser();
                Object key = user == null ? client.getDomain() : user;
                TreeSet<Client> clientSet = clientMap.get(key);
                if (clientSet == null) {
                    clientSet = new TreeSet<>();
                    clientMap.put(key, clientSet);
                }
                clientSet.add(client);
            }
        }
        return clientMap;
    }
    
    public static TreeSet<Client> getSet(Permission permission) {
        if (permission == null) {
            return null;
        } else {
            TreeSet<Client> clientSet = new TreeSet<>();
            for (Client client : getSet()) {
                if (client.hasPermission(permission)) {
                    clientSet.add(client);
                }
            }
            return clientSet;
        }
    }
    
    public static TreeSet<Client> getAdministratorSet() {
        TreeSet<Client> clientSet = new TreeSet<>();
        for (Client client : getSet()) {
            if (client.isAdministrator()) {
                clientSet.add(client);
            }
        }
        return clientSet;
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
    
    public synchronized static Client getByIP(String ip, String permissao) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            String key = SubnetIPv4.expandIPv4(ip);
            while ((key = MAP.floorKey(key)) != null) {
                if (key.contains(":")) {
                    break;
                } else {
                    Client client = MAP.get(key);
                    if (client.isPermission(permissao)) {
                        if (client.contains(ip)) {
                            return client;
                        } else {
                            return null;
                        }
                    } else if ((key = SubnetIPv4.expandIPv4(SubnetIPv4.getPreviousIPv4(SubnetIPv4.normalizeIPv4(key)))) == null) {
                        return null;
                    }
                }
            }
            return null;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            String key = SubnetIPv6.expandIPv6(ip);
            while ((key = MAP.floorKey(key)) != null) {
                if (key.contains(".")) {
                    break;
                } else {
                    Client client = MAP.get(key);
                    if (client.isPermission(permissao)) {
                        if (client.contains(ip)) {
                            return client;
                        } else {
                            return null;
                        }
                    } else if ((key = SubnetIPv6.expandIPv6(SubnetIPv6.getPreviousIPv6(SubnetIPv6.normalizeIPv6(key)))) == null) {
                        return null;
                    }
                }
            }
            return null;
        } else {
            return null;
        }
    }
    
    public synchronized static TreeSet<Client> getSetByCIDR(
            String cidr, String permission
    ) {
        if ((cidr = Subnet.normalizeCIDR(cidr)) == null) {
            return null;
        } else {
            String first = Subnet.getFirstIP(cidr);
            String last = Subnet.getLastIP(cidr);
            String keyFirst = Subnet.expandIP(first);
            String keyLast = Subnet.expandIP(last);
            SortedMap<String,Client> subMap = MAP.subMap(
                    keyFirst, true, keyLast, true
            );
            TreeSet<Client> clientSet = new TreeSet<>();
            for (Client client : subMap.values()) {
                if (client.isPermission(permission)) {
                    if (client.contains(first)) {
                        clientSet.add(client);
                    } else if (client.contains(last)) {
                        clientSet.add(client);
                    } else {
                        String cidrClient = client.getCIDR();
                        String firstClient = Subnet.getFirstIP(cidrClient);
                        String lastClient = Subnet.getLastIP(cidrClient);
                        if (Subnet.containsIP(cidr, firstClient)) {
                            clientSet.add(client);
                        } else if (Subnet.containsIP(cidr, lastClient)) {
                            clientSet.add(client);
                        }
                    }
                }
            }
            return clientSet;
        }
    }
    
    public static synchronized HashMap<String,Client> getMap() {
        HashMap<String,Client> map = new HashMap<>();
        map.putAll(MAP);
        return map;
    }
    
    public static synchronized HashMap<String,Client> getCloneMap() {
        TreeSet<String> removeSet = new TreeSet<>();
        HashMap<String,Client> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Client client = MAP.get(key);
            if (client.isPermission("DNSBL") && !client.hasEmail() && client.isDead()) {
                removeSet.add(key);
            } else {
                map.put(key, new Client(client));
            }
        }
        for (String key : removeSet) {
            MAP.remove(key);
        }
        return map;
    }
    
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,Client> map = getCloneMap();
//                for (String key : map.keySet()) {
//                    Client value = map.get(key);
//                    if (value.administrator) {
//                        // Compatibilidade com versões anteriores.
//                        value.permission = Permission.ALL;
//                    }
//                }
                File file = new File("./data/client.map");
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
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
        File file = new File("./data/client.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Client) {
                        Client client = (Client) value;
                        if (client.permission == null) {
                            client.permission = Permission.NONE;
                            client.administrator = false;
//                        } else if (client.permission == Permission.ALL) {
//                            client.permission = Permission.SPFBL;
//                            client.administrator = true;
                        }
                        if (client.limit == 0) {
                            client.limit = 100;
                        }
                        if (client.actionBLOCK == null) {
                            client.actionBLOCK = Action.REJECT;
                        }
                        if (client.actionRED == null) {
                            client.actionRED = Action.FLAG;
                        }
                        if (client.actionYELLOW == null) {
                            client.actionYELLOW = Action.DEFER;
                        }
                        if (client.actionGRACE == null) {
                            client.actionGRACE = Action.DEFER;
                        }
                        if (client.personality == null) {
                            client.personality = Personality.RATIONAL;
                        }
                        put(key, client);
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
        if (isDead()) {
            return false;
        } else {
            return frequency.getMaximumInt() < limit;
        }
    }
    
    public boolean isAbusing(Permission permission) {
        if (this.permission != permission) {
            return false;
        } else if (isDead()) {
            return false;
        } else {
            return frequency.getMaximumInt() < limit;
        }
    }
    
    public boolean isDead() {
        if (frequency == null) {
            return true;
        } else {
            int frequencyInt = frequency.getMaximumInt();
            long idleTimeInt = getIdleTimeMillis();
            return idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000;
        }
    }
    
    public boolean isIdle() {
        if (frequency == null) {
            return true;
        } else {
            return frequency.getMinimumInt() > 60000;
        }
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
            int startTime = 1000;
            frequency = new NormalDistribution(interval < startTime ? startTime : interval);
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
                    + (administrator ? " ADMIN" : " " + permission.name())
                    + " " + getFrequencyLiteral()
                    + (email == null ? "" : " <" + email + ">");
        } else {
            return getDomain() + ":" + cidr
                    + (administrator ? " ADMIN" : " " + permission.name())
                    + " " + getFrequencyLiteral()
                    + " " + user.getContact();
        }
    }
}
