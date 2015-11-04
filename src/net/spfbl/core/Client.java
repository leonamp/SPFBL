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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
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
    
    /**
     * Permissões de cliente.
     */
    private boolean permission_spfbl = false; // Pode consultar o serviço SPFBL.
    private boolean permission_dnsbl = false; // Pode consultar o serviço DNSBL.
    
    public static void main(String[] args) throws Exception {
        File clientsFile = new File("./data/clients.txt");
        BufferedReader reader = new BufferedReader(new FileReader(clientsFile));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                StringTokenizer tokenizer = new StringTokenizer(line, "\t");
                if (tokenizer.countTokens() == 3) {
                    String cidr = tokenizer.nextToken();
                    String email = tokenizer.nextToken();
                    String nome = tokenizer.nextToken();
                    String domain;
                    if (Domain.isEmail(email)) {
                        domain = Domain.extractDomain(email, false);
                        User user = User.create(email, nome);
                        if (user != null) {
                            user.setPermissionSPFBL(true);
                            System.out.println(user);
                        }
                    } else {
                        domain = email;
                        email = null;
                    }
                    Client client = create(cidr, domain, email);
                    client.setPermissionSPFBL(true);
                    System.out.println(client);
                }
            }
        } finally {
            reader.close();
        }
    }
    
    private Client(String cidr, String domain, String email) throws ProcessException {
        if (Subnet.isValidCIDR(cidr) && Domain.isHostname(domain)) {
            this.cidr = Subnet.normalizeCIDR(cidr);
            this.domain = Domain.extractHost(domain, false);
            if (email == null || email.length() == 0) {
                this.email = null;
            } else if (Domain.isEmail(email)) {
                this.email = email.toLowerCase();
            } else {
                throw new ProcessException("ERROR: INVALID EMAIL");
            }
        } else {
            throw new ProcessException("ERROR: INVALID CLIENT");
        }
    }
    
    public void setDomain(String domain) throws ProcessException {
        if (Domain.isHostname(domain)) {
            this.domain = Domain.extractHost(domain, false);
            CHANGED = true;
        } else {
            throw new ProcessException("ERROR: INVALID DOMAIN");
        }
    }
    
    public void setPermissionSPFBL(boolean spfbl) {
        this.permission_spfbl = spfbl;
    }
    
    public void setPermissionDNSBL(boolean dnsbl) {
        this.permission_dnsbl = dnsbl;
    }
    
    public String getCIDR() {
        return cidr;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public String getEmail() {
        return email;
    }
    
    public User getUser() {
        return User.get(email);
    }
    
    public boolean contains(String ip) {
        return Subnet.containsIP(cidr, ip);
    }
    
    public boolean hasPermissionSPFBL() {
        return permission_spfbl;
    }
    
    public boolean hasPermissionDNSBL() {
        return permission_dnsbl;
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
            String cidr, String domain, String email
            ) throws ProcessException {
        if (Subnet.isValidCIDR(cidr)) {
            String ip = Subnet.getFirstIP(cidr);
            Client client = get(ip);
            if (client == null) {
                ip = Subnet.expandIP(ip);
                client = new Client(cidr, domain, email);
                MAP.put(ip, client);
                CHANGED = true;
                return client;
            } else {
                return null;
            }
        } else {
            throw new ProcessException("ERROR: INVALID CIDR");
        }
    }
    
    public synchronized static TreeSet<Client> getSet() {
        TreeSet<Client> clientSet = new TreeSet<Client>();
        clientSet.addAll(MAP.values());
        return clientSet;
    }
    
    public synchronized static Client drop(String email) {
        Client client = MAP.remove(email);
        if (client != null) {
            CHANGED = true;
        }
        return client;
    }
    
    public synchronized static Client get(String ip) {
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
                        MAP.put(key, client);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
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
        return domain + ":" + cidr
                + (email == null ? "" : " <" + email + ">")
                + (permission_spfbl ? " SPFBL" : "")
                + (permission_dnsbl ? " DNSBL" : "");
    }
}
