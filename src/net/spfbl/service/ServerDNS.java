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
package net.spfbl.service;

import net.spfbl.dns.Zone;
import net.spfbl.spf.SPF;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import net.spfbl.core.Server;
import net.spfbl.whois.SubnetIPv4;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.AbusePeriod;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import net.spfbl.core.Client.Permission;
import net.spfbl.core.Core;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isReverseIPv6;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Reverse;
import net.spfbl.data.Abuse;
import net.spfbl.data.CIDR;
import static net.spfbl.data.Domain.usingSince;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.Provider;
import net.spfbl.data.FQDN;
import net.spfbl.data.NoReply;
import net.spfbl.data.White;
import static net.spfbl.spf.SPF.Qualifier.PASS;
import net.spfbl.whois.Domain;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;

/**
 * Servidor de consulta DNSBL.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class ServerDNS extends Server {

    private final Name HOSTNAME;
    private final int PORT;
    private final DatagramSocket SERVER_SOCKET;

    /**
     * Configuração e intanciamento do servidor.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public ServerDNS(String hostname, int port) throws SocketException, TextParseException {
        super("SERVERDNS");
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logInfo("binding DNS socket on port " + port + "...");
        HOSTNAME = Name.fromString(hostname + '.');
        PORT = port;
        SERVER_SOCKET = new DatagramSocket(port);
        Server.logTrace(getName() + " thread allocation.");
    }
    
    private static final LinkedList<DatagramPacket> RECEIVE_PACKET_LIST = new LinkedList<>();
    
    private synchronized static DatagramPacket pollReceiveDatagramPacket() {
        return RECEIVE_PACKET_LIST.poll();
    }
    
    private synchronized static void addReceiveDatagramPacket(DatagramPacket packet) {
        if (RECEIVE_PACKET_LIST.size() < 4) {
            RECEIVE_PACKET_LIST.add(packet);
        }
    }
    
    private static final LinkedList<DatagramPacket> SEND_PACKET_LIST = new LinkedList<>();
    
    private synchronized static DatagramPacket pollSendDatagramPacket() {
        return SEND_PACKET_LIST.poll();
    }
    
    private synchronized static void addSendDatagramPacket(DatagramPacket packet) {
        if (SEND_PACKET_LIST.size() < 4) {
            SEND_PACKET_LIST.add(packet);
        }
    }
    
    private static final int DEFAULT_LENGTH = 1024;
    
    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        try {
            Server.logInfo("listening DNS on UDP port " + PORT + ".");
            while (continueListenning()) {
                try {
                    DatagramPacket packet = pollReceiveDatagramPacket();
                    if (packet == null) {
                        byte[] receiveData = new byte[DEFAULT_LENGTH];
                        packet = new DatagramPacket(
                                receiveData, DEFAULT_LENGTH
                        );
                    }
                    SERVER_SOCKET.receive(packet);
                    long time = System.currentTimeMillis();
                    Connection connection = pollConnection();
                    if (connection == null) {
                        InetAddress ipAddress = packet.getAddress();
                        String result = "TOO MANY CONNECTIONS\n";
                        Server.logQueryDNSBL(time, ipAddress, null, result);
                    } else {
                        connection.process(packet, time);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie DNS server closed.");
        }
    }

    /**
     * Fecha todas as conexões e finaliza o servidor UDP.
     */
    @Override
    protected void close() {
        Connection connection;
        while ((connection = last()) != null) {
            connection.interrupt();
        }
        Server.logInfo("unbinding DNS socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }

    /**
     * Mapa para cache dos registros DNS consultados.
     */
    private static final HashMap<String,Zone> MAP = new HashMap<>();

    private static final long SERIAL = 2015102501;

    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private static synchronized Zone dropExact(String token) {
        Zone ret = MAP.remove(token);
        if (ret == null) {
            return null;
        } else {
            CHANGED = true;
            return ret;
        }
    }

    private static synchronized boolean putExact(String key, Zone zone) {
        if (key == null) {
            return false;
        } else if (zone == null) {
            return false;
        } else if (zone.isDNSAL() && !Core.isMatrixDefence()) {
            return false;
        } else {
            Zone ret = MAP.put(key, zone);
            if (zone.equals(ret)) {
                return false;
            } else {
                return CHANGED = true;
            }
        }
    }

    private static synchronized TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    private static synchronized HashMap<String,Zone> getMap() {
        HashMap<String,Zone> map = new HashMap<>();
        map.putAll(MAP);
        return map;
    }

    public static synchronized HashMap<String,Zone> getDNSBLMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isDNSBL()) {
                map.put(key, zone);
            }
        }
        return map;
    }
    
    public static synchronized HashMap<String,Zone> getURIBLMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isURIBL()) {
                map.put(key, zone);
            }
        }
        return map;
    }
    
    public static synchronized HashMap<String,Zone> getDNSWLMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isDNSWL()) {
                map.put(key, zone);
            }
        }
        return map;
    }
    
    public static synchronized HashMap<String,Zone> getSCOREMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isSCORE()) {
                map.put(key, zone);
            }
        }
        return map;
    }
    
    public static synchronized HashMap<String,Zone> getDNSALMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isDNSAL()) {
                map.put(key, zone);
            }
        }
        return map;
    }

    public static synchronized HashMap<String,Zone> getSINCEMap() {
        HashMap<String,Zone> map = new HashMap<>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isSINCE()) {
                map.put(key, zone);
            }
        }
        return map;
    }

    private static Zone getExact(String host) {
        return MAP.get(host);
    }

    public static synchronized TreeSet<Zone> getValues() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        serverSet.addAll(MAP.values());
        return serverSet;
    }

    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean addDNSBL(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.DNSBL, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }
    
    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean addURIBL(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.URIBL, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }
    
    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean addDNSWL(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.DNSWL, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }
    
    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean addSCORE(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.SCORE, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }

    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean addDNSAL(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.DNSAL, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }

    public static boolean addSINCE(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.SINCE, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }

    public static boolean set(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = getExact(hostname);
            if (server == null) {
                return false;
            } else {
                server.setMessage(message);
                return CHANGED = true;
            }
        } else {
            return false;
        }
    }

    private static Zone get(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            return getExact(hostname);
        } else {
            return null;
        }
    }
    
    public static TreeSet<Zone> dropAllDNSBL() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isDNSBL()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }
    
    public static TreeSet<Zone> dropAllURIBL() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isURIBL()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }
    
    public static TreeSet<Zone> dropAllDNSWL() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isDNSWL()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }
    
    public static TreeSet<Zone> dropAllSCORE() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isSCORE()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }

    public static TreeSet<Zone> dropAllDNSAL() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isDNSAL()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }

    public static TreeSet<Zone> dropAllSINCE() {
        TreeSet<Zone> serverSet = new TreeSet<>();
        for (Zone zone : getValues()) {
            if (zone != null && zone.isSINCE()) {
                String hostname = zone.getHostName();
                zone = dropExact(hostname);
                if (zone != null) {
                    serverSet.add(zone);
                }
            }
        }
        return serverSet;
    }

    public static Zone dropDNSBL(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isDNSBL()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }
    
    public static Zone dropURIBL(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isURIBL()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }
    
    public static Zone dropDNSWL(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isDNSWL()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }
    
    public static Zone dropSCORE(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isSCORE()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }

    public static Zone dropDNSAL(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isDNSAL()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }

    public static Zone dropSINCE(String hostname) {
        if (hostname == null) {
            return null;
        } else if (isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone zone = dropExact(hostname);
            if (zone.isSINCE()) {
                return zone;
            } else if (putExact(hostname, zone)) {
                return null;
            } else {
                return zone;
            }
        } else {
            return null;
        }
    }

    public static void store() {
        dropAllExpiredClientCache();
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/zone.map");
                HashMap<String,Zone> map = getMap();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
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
        File file = new File("./data/zone.map");
        if (file.exists()) {
            try {
                Map<String,Zone> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Zone value = map.get(key);
                    putExact(key, value);
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static String normalizeHost(String address) {
        if (address == null) {
            return null;
        } else if (address.length() == 0) {
            return null;
        } else if (address.contains("@")) {
            address = address.replace("\\@", "@");
            address = Core.removerAcentuacao(address);
            return address.toLowerCase();
        } else if (address.contains(":")) {
            int index = address.lastIndexOf(':');
            index = address.indexOf('.', index);
            String ipv6 = index > 0 ? address.substring(0, index) : null;
            if (isValidIPv6(ipv6)) {
                String reverse = SubnetIPv6.reverseIPv6(ipv6);
                String zone = address.substring(index + 1);
                return reverse + zone;
            } else {
                return null;
            }
        } else if (!isHostname(address)) {
            return null;
        } else if (address.startsWith(".")) {
            return Core.removerAcentuacao(address.substring(1)).toLowerCase();
        } else{
            return Core.removerAcentuacao(address).toLowerCase();
        }
    }
    
    private static final HashMap<InetAddress,String> CIDR_MAP = new HashMap<>();
    
    private static String getCIDR(InetAddress address) {
        if (address == null) {
            return null;
        } else {
            return CIDR_MAP.get(address);
        }
    }
    
    private static synchronized String removeInetAddress(InetAddress address) {
        if (address == null) {
            return null;
        } else {
            return CIDR_MAP.remove(address);
        }
    }
    
    private static synchronized String putCIDR(
            InetAddress address, String cidr
    ) {
        return CIDR_MAP.put(address, cidr);
    }
    
    public static synchronized ArrayList<InetAddress> getAddressKeySet() {
        int size = CIDR_MAP.size();
        ArrayList<InetAddress> addressSet = new ArrayList<>(size);
        addressSet.addAll(CIDR_MAP.keySet());
        return addressSet;
    }
    
    private static final HashMap<String,AbusePeriod> ABUSE_MAP = new HashMap<>();
    
    private static boolean containsAbusePeriodKey(String cidr) {
        if (cidr == null) {
            return false;
        } else {
            return ABUSE_MAP.containsKey(cidr);
        }
    }
    
    private static AbusePeriod getAbusePeriod(String cidr) {
        if (cidr == null) {
            return null;
        } else {
            return ABUSE_MAP.get(cidr);
        }
    }
    
    private static synchronized AbusePeriod removeAbuseKey(String cidr) {
        if (cidr == null) {
            return null;
        } else {
            return ABUSE_MAP.remove(cidr);
        }
    }
    
    private static synchronized AbusePeriod putAbusePeriod(
            String cidr, AbusePeriod period
    ) {
        if (cidr == null) {
            return null;
        } else if (period == null) {
            return null;
        } else {
            return ABUSE_MAP.put(cidr, period);
        }
    }
    
    public static synchronized TreeSet<String> getAbuseKeySet() {
        TreeSet<String> cidrSet = new TreeSet<>();
        cidrSet.addAll(ABUSE_MAP.keySet());
        return cidrSet;
    }
    
    public static TreeSet<String> getBannedKeySet() {
        TreeSet<String> bannedSet = new TreeSet<>();
        for (String cidr : getAbuseKeySet()) {
            AbusePeriod period = getAbusePeriod(cidr);
            if (period.isBanned()) {
                bannedSet.add(cidr);
            } else if (period.isExpired()) {
                removeAbuseKey(cidr);
            }
        }
        for (InetAddress address : getAddressKeySet()) {
            String cidr = getCIDR(address);
            if (!containsAbusePeriodKey(cidr)) {
                removeInetAddress(address);
            }
        }
        return bannedSet;
    }
    
    private static AbusePeriod isAbusing(InetAddress address, Client client) {
        if (client == null) {
            return null;
        } else if (client.isAbusing(Permission.DNSBL)) {
            AbusePeriod period = registerAbuseEvent(address);
            if (period == null) {
                return null;
            } else if (period.isAbusing(32, client.getLimit())) {
                return period;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    private static AbusePeriod registerAbuseEvent(InetAddress address) {
        if (address == null) {
            return null;
        } else {
            String cidr = getCIDR(address);
            if (cidr == null) {
                if (address instanceof Inet4Address) {
                    cidr = SubnetIPv4.normalizeCIDRv4(address.getHostAddress() + "/25");
                    putCIDR(address, cidr);
                } else if (address instanceof Inet6Address) {
                    cidr = SubnetIPv6.normalizeCIDRv6(address.getHostAddress() + "/52");
                    putCIDR(address, cidr);
                }
            }
            if (cidr == null) {
                return null;
            } else {
                AbusePeriod period = getAbusePeriod(cidr);
                if (period == null) {
                    period = new AbusePeriod();
                    putAbusePeriod(cidr, period);
                }
                period.registerEvent();
                if (period.isAbusing(16384, 1000)) {
                    period.setBannedInterval(Server.WEEK_TIME);
                }
                return period;
            }
        }
    }
    
    public static void storeAbuse() {
        long time = System.currentTimeMillis();
        File file = new File("./data/dns.abuse.txt");
        try (FileWriter writer = new FileWriter(file)) {
            for (String cidr : getAbuseKeySet()) {
                AbusePeriod period = getAbusePeriod(cidr);
                if (period != null) {
                    writer.append(cidr);
                    writer.append(' ');
                    writer.append(period.storeLine());
                    writer.append('\n');
                }
            }
            Server.logStore(time, file);
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    public static void loadAbuse() {
        long time = System.currentTimeMillis();
        File file = new File("./data/dns.abuse.txt");
        if (file.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        int index = line.indexOf(' ');
                        String cidr = line.substring(0, index);
                        if (cidr.contains(":") && cidr.endsWith("/52")) {
                            line = line.substring(index + 1);
                            AbusePeriod period = AbusePeriod.loadLine(line);
                            putAbusePeriod(cidr, period);
                        } else if (!cidr.contains(":") && cidr.endsWith("/25")) {
                            line = line.substring(index + 1);
                            AbusePeriod period = AbusePeriod.loadLine(line);
                            putAbusePeriod(cidr, period);
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static final HashMap<InetAddress,ClientCache> CLIENT_CACHE_MAP = new HashMap<>();
    
    private static class ClientCache {
        
        private final Client client;
        private final long ttl;
        
        private ClientCache(Client client) {
            this.client = client;
            this.ttl = System.currentTimeMillis() + Server.HOUR_TIME;
        }
        
        public Client getClient() {
            return client;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > ttl;
        }
    }
    
    private synchronized static void putClientCache(
            InetAddress ipAddress, ClientCache clientCache
    ) {
        if (ipAddress != null && clientCache != null) {
            CLIENT_CACHE_MAP.put(ipAddress, clientCache);
        }
    }
    
    private synchronized static void removeClientCache(InetAddress ipAddress) {
        CLIENT_CACHE_MAP.remove(ipAddress);
    }
    
    private synchronized static ArrayList<InetAddress> getClientCacheKeySet() {
        ArrayList<InetAddress> keySet = new ArrayList<>();
        keySet.addAll(CLIENT_CACHE_MAP.keySet());
        return keySet;
    }
    
    private static ClientCache getClientCache(InetAddress ipAddress) {
        if (ipAddress == null) {
            return null;
        } else {
            return CLIENT_CACHE_MAP.get(ipAddress);
        }
    }
    
    private static Client createClient(InetAddress ipAddress) throws ProcessException {
        if (ipAddress == null) {
            return null;
        } else {
            ClientCache clientCache = getClientCache(ipAddress);
            if (clientCache == null || clientCache.isExpired()) {
                Client client = Client.create(ipAddress, "DNSBL");
                clientCache = new ClientCache(client);
                putClientCache(ipAddress, clientCache);
                return client;
            } else {
                return clientCache.getClient();
            }
        }
    }
    
    private static void dropAllExpiredClientCache() {
        for (InetAddress ipAddress : getClientCacheKeySet()) {
            ClientCache clientCache = getClientCache(ipAddress);
            if (clientCache != null && clientCache.isExpired()) {
                removeClientCache(ipAddress);
            }
        }
    }
    
    private static boolean LOG = false;
    
    public static void setLog(boolean mustLog) {
        LOG = mustLog;
    }
    
    private static final long TTL_10_MINUTES = 600;
    private static final long TTL_1_HOUR = 3600;
    private static final long TTL_1_DAY = 86400;
    private static final long TTL_3_DAYS = 259200;
    private static final long TTL_5_DAYS = 432000;
    private static final long TTL_7_DAYS = 604800;
    
    private class Connection extends Thread {
        
        private DatagramPacket PACKET = null;
        private long TIME = 0;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        
        public Connection(int id) {
            String name =  "DNSUDP" + Core.formatCentena(id);
            Server.logInfo("creating " + name + "...");
            setName(name);
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        private void process(DatagramPacket packet, long time) {
            PACKET = packet;
            TIME = time;
            SEMAPHORE.release();
        }
        
        @Override
        public void interrupt() {
            Server.logInfo("closing " + getName() + "...");
            PACKET = null;
            TIME = 0;
            SEMAPHORE.release();
        }

        public DatagramPacket getPacket() {
            try {
                SEMAPHORE.acquire();
                return PACKET;
            } catch (InterruptedException ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        @Override
        public void run() {
            try {
                DatagramPacket packet;
                while ((packet = getPacket()) != null) {
                    InetAddress ipAddress = packet.getAddress();
                    String origin = ipAddress.getHostAddress();
                    String query = "ERROR";
                    String type = null;
                    String result = "IGNORED";
                    String tag = "DNSQR";
                    Core.Level level = Core.Level.DEBUG;
                    try {
                        byte[] data = packet.getData();
                        tag = "DNSQR";
                        // Processando consulta DNS.
                        Message message = new Message(data);
                        Header header = message.getHeader();
                        Record question = message.getQuestion();
                        if (question == null) {
                            query = "NO QUESTION";
                            result = "IGNORED";
                        } else {
                            Name name = question.getName();
                            type = Type.string(question.getType());
                            query = name.toString();
                            // Identificação do cliente.
                            Client client = createClient(ipAddress);
                            if (client == null) {
                                result = "IGNORED";
                            } else {
                                client.addQuery();
                                origin += ' ' + client.getDomain();
                                long ttl = TTL_1_DAY;
                                String host;
                                Zone zone = null;
                                String clientQuery;
                                String information;
                                AbusePeriod abusePeriod;
                                if ((abusePeriod = isAbusing(ipAddress, client)) != null) {
                                    result = "REFUSED";
                                    information = null;
                                } else if ((host = normalizeHost(query)) == null) {
                                    abusePeriod = registerAbuseEvent(ipAddress);
                                    result = "FORMERR";
                                    level = Core.Level.TRACE;
                                    information = null;
                                } else {
                                    int index = host.length() - 1;
                                    host = host.substring(0, index);
                                    String hostname;
                                    String reverse = "";
                                    if ((zone = getExact('.' + host)) == null) {
                                        while ((index = host.lastIndexOf('.', index)) != -1) {
                                            reverse = host.substring(0, index);
                                            hostname = host.substring(index);
                                            if ((zone = getExact(hostname)) == null) {
                                                index--;
                                            } else {
                                                break;
                                            }
                                        }
                                    }
                                    if (zone == null) {
                                        // Não existe zona cadastrada.
                                        abusePeriod = registerAbuseEvent(ipAddress);
                                        result = "NOTAUTH";
                                        information = null;
                                    } else if (type.equals("NS")) {
                                        result = HOSTNAME.toString();
                                        information = zone.getMessage();
                                    } else if (type.equals("A") && zone.isHostName(host)) {
                                        // O A é o próprio servidor.
                                        if ((result = Core.getHostname()) != null) {
                                            result = Reverse.getAddress4Safe(result);
                                        }
                                        if (result == null) {
                                            result = "NOERROR";
                                            information = null;
                                        } else {
                                            information = zone.getMessage();
                                        }
                                    } else if (type.equals("AAAA") && zone.isHostName(host)) {
                                        // O A é o próprio servidor.
                                        if ((result = Core.getHostname()) != null) {
                                            result = Reverse.getAddress6(result);
                                        }
                                        if (result == null) {
                                            result = "NOERROR";
                                            information = null;
                                        } else {
                                            information = zone.getMessage();
                                        }
                                    } else if (reverse.length() == 0) {
                                        // O reverso é inválido.
                                        result = "NXDOMAIN";
                                        information = null;
                                    } else if (isValidIPv4(reverse)) {
                                        // A consulta é um IPv4.
                                        String resultNL;
                                        if (isIncompleteIPv6(reverse)) {
                                            resultNL = "NOERROR";
                                        } else {
                                            resultNL = "NXDOMAIN";
                                        }
                                        clientQuery = SubnetIPv4.reverseToIPv4(reverse);
                                        if (clientQuery.startsWith("127.")) {
                                            if (clientQuery.equals("127.0.0.0")) {
                                                // Consulta de teste para negativo.
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (clientQuery.equals("127.0.0.1")) {
                                                // Consulta de teste para negativo.
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                // Consulta de teste para positivo.
                                                result = clientQuery;
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            }
                                        } else if (zone.isDNSBL()) {
                                            Object value = CIDR.valueIPv4(clientQuery);
                                            if (value == Boolean.FALSE) {
                                                // Reserved IP.
                                                result = resultNL;
                                                information = null;
                                                ttl = resultNL.equals("NXDOMAIN") ? TTL_5_DAYS : TTL_1_DAY;
                                            } else {
                                                boolean blocked = false;
                                                if (value instanceof Integer) {
                                                    blocked = true;
                                                } else if (value instanceof Boolean) {
                                                    blocked = (Boolean) value;
                                                } else if (Block.containsFQDNFromIP(clientQuery)) {
                                                    blocked = true;
                                                    Block.tryToDominoBlockIP(clientQuery, "BLOCK");
                                                }
                                                SPF.Status status = SPF.getStatus(clientQuery, false);
                                                if (blocked) {
                                                    if (status == SPF.Status.RED) {
                                                        result = "127.0.0.2";
                                                        information = zone.getMessage(clientQuery);
                                                        ttl = TTL_5_DAYS;
                                                    } else if (status == SPF.Status.YELLOW) {
                                                        result = "127.0.0.2";
                                                        information = zone.getMessage(clientQuery);
                                                        ttl = TTL_3_DAYS;
                                                    } else if (FQDN.containsKeyFQDN(clientQuery)) {
                                                        result = "127.0.0.3";
                                                        information = zone.getMessage(clientQuery);
                                                        ttl = TTL_1_DAY;
                                                    } else {
                                                        result = "127.0.0.4";
                                                        information = zone.getMessage(clientQuery);
                                                        ttl = TTL_3_DAYS;
                                                    }
                                                } else if (status == SPF.Status.RED) {
                                                    FQDN.checkIdentifiedIP(clientQuery);
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else if (Abuse.isUndesirableRange(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_3_DAYS;
                                                } else if (resultNL.equals("NXDOMAIN")) {
                                                    FQDN.checkIdentifiedIP(clientQuery);
                                                    result = resultNL;
                                                    information = null;
                                                    ttl = TTL_1_HOUR;
                                                } else {
                                                    FQDN.checkIdentifiedIP(clientQuery);
                                                    result = resultNL;
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                }
                                            }
                                        } else if (zone.isURIBL()) {
                                            if (Block.containsExact("HREF=" + clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                            } else {
                                                result = resultNL;
                                                information = null;
                                            }
                                        } else if (zone.isDNSWL()) {
                                            SPF.Status status = SPF.getStatus(clientQuery, false);
                                            if (status != SPF.Status.GREEN) {
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Block.containsIPorFQDN(clientQuery)) {
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Ignore.containsIPorFQDN(clientQuery)) {
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.3";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else if (White.containsIPorFQDN(clientQuery)) {
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.4";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Provider.containsIPorFQDN(clientQuery)) {
                                                if (FQDN.containsKeyFQDN(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                } else if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                } else {
                                                    result = resultNL;
                                                    information = null;
                                                }
                                                ttl = TTL_1_DAY;
                                            } else if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Abuse.isSubscribedBeneficial(clientQuery)) {
                                                result = "127.0.0.6";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            }
                                        } else if (zone.isSCORE()) {
                                            Float probability = SPF.getSpamProbability(clientQuery, 32);
                                            if (probability != null) {
                                                int score = 100 - (int) (100.0f * probability);
                                                result = "127.0.1." + score;
                                                information = zone.getMessage(clientQuery);
                                            } else if (Ignore.containsIPorFQDN(clientQuery)) {
                                                result = "127.0.1.100";
                                                information = zone.getMessage(clientQuery);
                                            } else {
                                                result = resultNL;
                                                information = null;
                                            }
                                        } else if (zone.isDNSAL()) {
                                            Object value = CIDR.valueIPv4(clientQuery);
                                            if (value == Boolean.FALSE) {
                                                // Reserved IP.
                                                result = resultNL;
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                String email = null;
                                                String fqdn = FQDN.getFQDN(clientQuery, false);
                                                if (fqdn != null) {
                                                    email = Abuse.getEmailFQDN(fqdn);
                                                } else if (value == null) {
                                                    FQDN.checkIP(clientQuery);
                                                }
                                                if (email == null) {
                                                    email = Abuse.getEmailIPv4(clientQuery);
                                                }
                                                if (email == null) {
                                                    result = resultNL;
                                                    information = null;
                                                    ttl = TTL_5_DAYS;
                                                } else if (NoReply.isSubscribed(email)) {
                                                    result = "127.0.0.2";
                                                    information = email;
                                                    ttl = TTL_3_DAYS;
                                                } else {
                                                    result = "127.0.0.3";
                                                    information = email;
                                                    ttl = TTL_1_DAY;
                                                }
                                            }
                                        } else {
                                            result = resultNL;
                                            information = null;
                                        }
                                    } else if (isReverseIPv6(reverse)) {
                                        // A consulta é um IPv6.
                                        clientQuery = SubnetIPv6.reverseToIPv6(reverse);
                                        if (clientQuery.equals("0:0:0:0:0:ffff:7f00:1")) {
                                            // Consulta de teste para negativo.
                                            result = "NXDOMAIN";
                                            information = null;
                                            ttl = TTL_1_DAY;
                                        } else if (clientQuery.equals("0:0:0:0:0:ffff:7f00:2")) {
                                            // Consulta de teste para positivo.
                                            result = "127.0.0.2";
                                            information = zone.getMessage(clientQuery);
                                            ttl = TTL_5_DAYS;
                                        } else if (clientQuery.equals("0:0:0:0:0:ffff:7f00:3")) {
                                            // Consulta de teste para positivo.
                                            result = "127.0.0.3";
                                            information = zone.getMessage(clientQuery);
                                            ttl = TTL_5_DAYS;
                                        } else if (zone.isDNSBL()) {
                                            clientQuery = SubnetIPv6.tryTransformFromIPv6ToIPv4(clientQuery);
                                            Object value;
                                            if (clientQuery.contains(":")) {
                                                value = CIDR.valueIPv6(clientQuery);
                                            } else {
                                                value = CIDR.valueIPv4(clientQuery);
                                            }
                                            if (value == Boolean.FALSE) {
                                                // Reserved IP.
                                                result = "NXDOMAIN";
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                boolean blocked = false;
                                                if (value instanceof Integer) {
                                                    blocked = true;
                                                } else if (value instanceof Boolean) {
                                                    blocked = (Boolean) value;
                                                } else if (Block.containsFQDNFromIP(clientQuery)) {
                                                    blocked = true;
                                                    Block.tryToDominoBlockIP(clientQuery, "BLOCK");
                                                }
                                                SPF.Status status = SPF.getStatus(clientQuery, false);
                                                if (blocked) {
                                                    if (status == SPF.Status.RED) {
                                                        result = "127.0.0.2";
                                                        ttl = TTL_5_DAYS;
                                                    } else if (status == SPF.Status.YELLOW) {
                                                        result = "127.0.0.2";
                                                        ttl = TTL_3_DAYS;
                                                    } else if (FQDN.containsKeyFQDN(clientQuery)) {
                                                        result = "127.0.0.3";
                                                        ttl = TTL_1_DAY;
                                                    } else {
                                                        result = "127.0.0.4";
                                                        ttl = TTL_1_DAY;
                                                    }
                                                    information = zone.getMessage(clientQuery);
                                                } else if (status == SPF.Status.RED) {
                                                    FQDN.checkIdentifiedIP(clientQuery);
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else if (Abuse.isUndesirableRange(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_3_DAYS;
                                                } else {
                                                    FQDN.checkIdentifiedIP(clientQuery);
                                                    result = "NXDOMAIN";
                                                    information = null;
                                                    ttl = TTL_1_HOUR;
                                                }
                                            }
                                        } else if (zone.isURIBL()) {
                                            clientQuery = SubnetIPv6.tryTransformFromIPv6ToIPv4(clientQuery);
                                            if (Block.containsExact("HREF=" + clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                            } else {
                                                result = "NXDOMAIN";
                                                information = null;
                                            }
                                        } else if (zone.isDNSWL()) {
                                            clientQuery = SubnetIPv6.tryTransformFromIPv6ToIPv4(clientQuery);
                                            SPF.Status status = SPF.getStatus(clientQuery, false);
                                            if (status != SPF.Status.GREEN) {
                                                result = "NXDOMAIN";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Block.containsIPorFQDN(clientQuery)) {
                                                result = "NXDOMAIN";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Ignore.containsIPorFQDN(clientQuery)) {
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.3";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else if (White.containsIPorFQDN(clientQuery)) {
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.4";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Provider.containsIPorFQDN(clientQuery)) {
                                                if (FQDN.hasFQDN(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                } else if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                } else {
                                                    result = "NXDOMAIN";
                                                    information = null;
                                                }
                                                ttl = TTL_1_DAY;
                                            } else if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Abuse.isSubscribedBeneficial(clientQuery)) {
                                                result = "127.0.0.6";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                result = "NXDOMAIN";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            }
                                        } else if (zone.isSCORE()) {
                                            clientQuery = SubnetIPv6.tryTransformFromIPv6ToIPv4(clientQuery);
                                            Float probability = SPF.getSpamProbability(clientQuery, 32);
                                            if (probability != null) {
                                                int score = 100 - (int) (100.0f * probability);
                                                result = "127.0.1." + score;
                                                information = zone.getMessage(clientQuery);
                                            } else if (Ignore.containsIPorFQDN(clientQuery)) {
                                                result = "127.0.1.100";
                                                information = zone.getMessage(clientQuery);
                                            } else {
                                                result = "NXDOMAIN";
                                                information = null;
                                            }
                                        } else if (zone.isDNSAL()) {
                                            clientQuery = SubnetIPv6.tryTransformFromIPv6ToIPv4(clientQuery);
                                            Object value;
                                            if (clientQuery.contains(":")) {
                                                value = CIDR.valueIPv6(clientQuery);
                                            } else {
                                                value = CIDR.valueIPv4(clientQuery);
                                            }
                                            if (value == Boolean.FALSE) {
                                                // Reserved IP.
                                                result = "NXDOMAIN";
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                String email = null;
                                                String fqdn = FQDN.getFQDN(clientQuery, false);
                                                if (fqdn != null) {
                                                    email = Abuse.getEmailFQDN(fqdn);
                                                } else if (value == null) {
                                                    FQDN.checkIP(clientQuery);
                                                }
                                                if (email == null) {
                                                    if (clientQuery.contains(":")) {
                                                        email = Abuse.getEmailIPv6(clientQuery);
                                                    } else {
                                                        email = Abuse.getEmailIPv4(clientQuery);
                                                    }
                                                }
                                                if (email == null) {
                                                    result = "NXDOMAIN";
                                                    information = null;
                                                    ttl = TTL_5_DAYS;
                                                } else if (NoReply.isSubscribed(email)) {
                                                    result = "127.0.0.2";
                                                    information = email;
                                                    ttl = TTL_3_DAYS;
                                                } else {
                                                    result = "127.0.0.3";
                                                    information = email;
                                                    ttl = TTL_1_DAY;
                                                }
                                            }
                                        } else {
                                            result = "NXDOMAIN";
                                            information = null;
                                        }
                                    } else if ((clientQuery = zone.extractDomain(host)) != null) {
                                        if (clientQuery.endsWith(".invalid")) {
                                            // Consulta de teste para negativo.
                                            result = "NXDOMAIN";
                                            information = null;
                                            ttl = TTL_1_DAY;
                                        } else if (clientQuery.equals(".test")) {
                                            // Consulta de teste para positivo.
                                            result = "127.0.0.2";
                                            information = zone.getMessage(clientQuery);
                                            ttl = TTL_5_DAYS;
                                        } else if (isIncomplete(clientQuery)) {
                                            result = "NOERROR";
                                            information = null;
                                        } else if (zone.isDNSBL()) {
                                            if (clientQuery.contains("@")) {
                                                clientQuery = Domain.normalizeEmail(clientQuery);
                                            }
                                            SPF.Status status = SPF.getStatus(clientQuery, false);
                                            if (clientQuery == null) {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (clientQuery.contains("@")) {
                                                if (status == SPF.Status.RED) {
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else if (Block.containsExactEmail(clientQuery)) {
                                                    result = "127.0.0.3";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else if (Generic.containsGenericEmail(clientQuery)) {
                                                    result = "127.0.0.4";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_5_DAYS;
                                                } else {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                }
                                            } else if (Generic.containsDynamicDomain(clientQuery)) {
                                                if (status == SPF.Status.GREEN) {
                                                    result = "127.0.0.4";
                                                    ttl = TTL_5_DAYS;
                                                } else {
                                                    result = "127.0.0.2";
                                                    ttl = TTL_3_DAYS;
                                                }
                                                information = zone.getMessage(clientQuery);
                                            } else if (Block.containsFQDN(clientQuery)) {
                                                if (status == SPF.Status.RED) {
                                                    result = "127.0.0.2";
                                                    ttl = TTL_5_DAYS;
                                                } else if (status == SPF.Status.YELLOW) {
                                                    result = "127.0.0.2";
                                                    ttl = TTL_3_DAYS;
                                                } else {
                                                    result = "127.0.0.3";
                                                    ttl = TTL_1_DAY;
                                                }
                                                information = zone.getMessage(clientQuery);
                                            } else if (status == SPF.Status.RED) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else {
                                                String domain = Domain.extractDomainSafe(clientQuery, true);  // Improve
                                                if (domain == null) {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                } else if (SPF.getStatus(domain, false) == SPF.Status.RED) {
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else {                                                            
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                }
                                            }
                                        } else if (zone.isURIBL()) {
                                            String signature;
                                            if (clientQuery.contains("@")) {
                                                clientQuery = Domain.normalizeEmail(clientQuery);
                                                if (clientQuery == null) {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                } else if (Block.containsHREF(clientQuery)) {
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                }
                                            } else if (Block.containsHostnameHREF(clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if ((signature = getBlockedExecutableSignature(clientQuery)) != null) {
                                                clientQuery = signature;
                                                result = "127.0.0.3";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_3_DAYS;
                                            } else if ((signature = getSignatureBlockURL(clientQuery)) != null) {
                                                clientQuery = signature;
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            }
                                        } else if (zone.isDNSWL()) {
                                            SPF.Status status = SPF.getStatus(clientQuery, false);
                                            if (status != SPF.Status.GREEN) {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (clientQuery.contains("@")) {
                                                clientQuery = Domain.normalizeEmail(clientQuery);
                                                if (clientQuery == null) {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                } else if (net.spfbl.data.SPF.isBeneficial(clientQuery, PASS)) {
                                                    result = "127.0.0.2";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_1_DAY;
                                                } else if (Provider.containsDomainEmail(clientQuery)) {
                                                    result = "127.0.0.5";
                                                    information = zone.getMessage(clientQuery);
                                                    ttl = TTL_5_DAYS;
                                                } else {
                                                    result = "NOERROR";
                                                    information = null;
                                                    ttl = TTL_1_DAY;
                                                }
                                            } else if (Generic.containsGenericSoft(clientQuery)) { // Improve
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Block.containsFQDN(clientQuery)) {  // Improve
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            } else if (Ignore.containsFQDN(clientQuery)) {  // Improve
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.3";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else if (White.containsFQDN(clientQuery)) { // Improve
                                                if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                    result = "127.0.0.2";
                                                } else {
                                                    result = "127.0.0.4";
                                                }
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Provider.containsFQDN(clientQuery)) { // Improve
                                                result = "127.0.0.5";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else if (CIDR.isBeneficialFQDN(clientQuery)) {
                                                result = "127.0.0.2";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_1_DAY;
                                            } else if (Abuse.isBeneficialFQDN(clientQuery)) {
                                                result = "127.0.0.6";
                                                information = zone.getMessage(clientQuery);
                                                ttl = TTL_5_DAYS;
                                            } else {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_1_DAY;
                                            }
                                        } else if (zone.isSCORE()) {
                                            Float probability = SPF.getSpamProbability(clientQuery, 32);
                                            if (probability != null) {
                                                int score = 100 - (int) (100.0f * probability);
                                                result = "127.0.1." + score;
                                                information = zone.getMessage(clientQuery);
                                            } else if (Ignore.containsFQDN(clientQuery)) {
                                                result = "127.0.1.100";
                                                information = zone.getMessage(clientQuery);
                                            } else {
                                                result = "NOERROR";
                                                information = null;
                                            }
                                        } else if (zone.isDNSAL()) {
                                            String email;
                                            if (clientQuery.contains("@")) {
                                                email = Domain.normalizeEmail(clientQuery);
                                            } else {
                                                email = Abuse.getEmailFQDN(clientQuery); // Improve
                                            }
                                            if (email == null) {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else if (NoReply.isSubscribed(email)) {
                                                result = "127.0.0.2";
                                                information = email;
                                                ttl = TTL_3_DAYS;
                                            } else {
                                                result = "127.0.0.3";
                                                information = email;
                                                ttl = TTL_1_DAY;
                                            }
                                        } else if (zone.isSINCE()) {
                                            Integer since = usingSince(clientQuery); // Improve
                                            if (since == null) {
                                                result = "NOERROR";
                                                information = null;
                                                ttl = TTL_5_DAYS;
                                            } else if (since > 255) {
                                                result = "127.0.0.255";
                                                information = since.toString();
                                                ttl = TTL_5_DAYS;
                                            } else if (since > 7) {
                                                result = "127.0.0." + since;
                                                information = since.toString();
                                                ttl = TTL_3_DAYS;
                                            } else {
                                                result = "127.0.0." + since;
                                                information = since.toString();
                                                ttl = TTL_1_DAY;
                                            }
                                        } else {
                                            result = "NOERROR";
                                            information = null;
                                        }
                                    } else {
                                        // Não está listado.
                                        result = "NOERROR";
                                        information = null;
                                    }
                                }
                                if (zone == null) {
                                    tag = "DNSQR";
                                } else {
                                    tag = zone.getTypeName();
                                }
                                // Alterando mensagem DNS para resposta.
                                header.setFlag(Flags.QR);
                                header.setFlag(Flags.AA);
                                if (zone == null) {
                                    header.setRcode(Rcode.NOTAUTH);
                                } else if (result.equals("REFUSED")) {
                                    header.setRcode(Rcode.REFUSED);
                                    SOARecord soa = newSOA(zone, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else if (result.equals("NOTAUTH")) {
                                    header.setRcode(Rcode.NOTAUTH);
                                    SOARecord soa = newSOA(zone, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else if (result.equals("NXDOMAIN")) {
                                    header.setRcode(Rcode.NXDOMAIN);
                                    SOARecord soa = newSOA(name, name, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else if (type.equals("NS")) {
                                    header.setRcode(Rcode.NOERROR);
                                    NSRecord ns = new NSRecord(name, DClass.IN, TTL_7_DAYS, HOSTNAME);
                                    message.addRecord(ns, Section.ANSWER);
                                } else if (result.equals("FORMERR")) {
                                    header.setRcode(Rcode.FORMERR);
                                    SOARecord soa = newSOA(zone, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else if (result.equals("NOERROR")) {
                                    header.setRcode(Rcode.NOERROR);
                                    SOARecord soa = newSOA(zone, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else if (type.equals("A")) {
                                    header.setRcode(Rcode.NOERROR);
                                    InetAddress address = InetAddress.getByName(result);
                                    ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                    message.addRecord(a, Section.ANSWER);
                                } else if (type.equals("AAAA")) {
                                    header.setRcode(Rcode.NOERROR);
                                    InetAddress address = InetAddress.getByName(result);
                                    Record record;
                                    if (address instanceof Inet4Address) {
                                        record = new ARecord(name, DClass.IN, ttl, address);
                                    } else {
                                        record = new AAAARecord(name, DClass.IN, ttl, address);
                                    }
                                    message.addRecord(record, Section.ANSWER);
                                } else if (type.equals("TXT")) {
                                    header.setRcode(Rcode.NOERROR);
                                    TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, information);
                                    message.addRecord(txt, Section.ANSWER);
                                    result = information;
                                } else if (type.equals("CNAME")) {
                                    header.setRcode(Rcode.NOERROR);
                                    InetAddress address = InetAddress.getByName(result);
                                    ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                    message.addRecord(a, Section.ANSWER);
                                    TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, information);
                                    message.addRecord(txt, Section.ANSWER);
                                    result += " " + information;
                                } else if (type.equals("ANY")) {
                                    header.setRcode(Rcode.NOERROR);
                                    InetAddress address = InetAddress.getByName(result);
                                    ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                    message.addRecord(a, Section.ANSWER);
                                    TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, information);
                                    message.addRecord(txt, Section.ANSWER);
                                    SOARecord soa = newSOA(name, name, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                    result += " " + information;
                                } else if (type.equals("SOA")) {
                                    header.setRcode(Rcode.NOERROR);
                                    SOARecord soa = newSOA(name, name, ttl);
                                    message.addRecord(soa, Section.AUTHORITY);
                                } else {
                                    header.setRcode(Rcode.NOERROR);
                                    InetAddress address = InetAddress.getByName(result);
                                    ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                    message.addRecord(a, Section.ANSWER);
                                }
                                if (abusePeriod == null) {
                                    result = ttl + " " + result;
                                } else {
                                    result = abusePeriod + " " + abusePeriod.getPopulation() + " " + ttl + " " + result;
                                }
                                // Enviando resposta.
                                int portDestiny = packet.getPort();
                                byte[] sendData = message.toWire();
                                DatagramPacket sendPacket = pollSendDatagramPacket();
                                if (sendPacket == null) {
                                    sendPacket = new DatagramPacket(
                                            sendData, sendData.length,
                                            ipAddress, portDestiny
                                    );
                                } else {
                                    sendPacket.setData(sendData);
                                    sendPacket.setLength(sendData.length);
                                    sendPacket.setAddress(ipAddress);
                                    sendPacket.setPort(portDestiny);
                                }
                                SERVER_SOCKET.send(sendPacket);
                                addSendDatagramPacket(sendPacket);
                            }
                        }
                    } catch (SocketException ex) {
                        // Houve fechamento do socket.
                        result = "CLOSED";
                        level = Core.Level.TRACE;
                    } catch (WireParseException ex) {
                        // Ignorar consultas inválidas.
                        query = "UNPARSEABLE";
                        result = "IGNORED";
                        level = Core.Level.TRACE;
                    } catch (IOException ex) {
                        result = "INVALID";
                        level = Core.Level.TRACE;
                    } catch (Exception ex) {
                        Server.logError(ex);
                        result = "ERROR";
                        level = Core.Level.TRACE;
                    } finally {
                        if (LOG) {
                            Server.logQuery(
                                    TIME,
                                    level,
                                    tag,
                                    origin,
                                    (Long) null,
                                    type == null ? query : type + " " + query,
                                    result
                            );
                        }
                        addReceiveDatagramPacket(packet);
                        offerConnection(this);
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                Server.logTrace(getName() + " thread closed.");
            }
        }
        
        private SOARecord newSOA(Zone zone, long refresh) throws TextParseException {
            Name name = new Name(zone.getHostName().substring(1) + '.');
            return newSOA(name, name, refresh);
        }
        
        private SOARecord newSOA(Name name, Name host, long refresh) throws TextParseException {
            long ttlSOA = TTL_1_DAY;
            long retry = TTL_10_MINUTES;
            long expire = TTL_7_DAYS;
            long minimum = refresh;
            return new SOARecord(
                    name, DClass.IN, ttlSOA, host,
                    host, SERIAL, refresh, retry, expire, minimum
            );
        }
    }
    
    private static final Regex IPV4_PATTERN = new Regex("^"
            + "\\.?(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){1,2}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "$"
    );
    
    private static final Regex IPV6_PATTERN = new Regex("^"
            + "\\.?([0-9a-f]\\.){0,30}[2-3]"
            + "$"
    );
    
    private static boolean isIncomplete(String fqdn) {
        if (fqdn == null) {
            return true;
        } else if (fqdn.contains("@")) {
            return false;
        } else if (Domain.isOfficialTLD(fqdn)) {
            return true;
        } else if (IPV4_PATTERN.matches(fqdn)) {
            return true;
        } else {
            return IPV6_PATTERN.matches(fqdn);
        }
    }
    
    private static boolean isIncompleteIPv6(String fqdn) {
        if (fqdn == null) {
            return true;
        } else {
            return IPV6_PATTERN.matches(fqdn);
        }
    }
        
    private static final Regex EXECUTABLE_SIGNATURE_PATTERN = new Regex("^"
            + "\\.[0-9a-f]{32}\\.[0-9]+\\."
            + "(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh|zip|7z|rar|z|doc)"
            + "$"
    );
    
    private static String getBlockedExecutableSignature(String token) {
        if (token == null) {
            return null;
        } else if (EXECUTABLE_SIGNATURE_PATTERN.matches(token)) {
            String signature = token.substring(1);
            if (Block.containsExact(signature)) {
                return signature;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    private static String getSignatureBlockURL(String token) {
        if (token == null) {
            return null;
        } else {
            return Block.getSignatureBlockURL(token.substring(1));
        }
    }

    private final LinkedList<Connection> CONNECTION_QUEUE = new LinkedList<>();
    private final LinkedList<Connection> CONNECTION_LIST = new LinkedList<>();
    
    private static byte CONNECTION_LIMIT = 8;

    public static void setConnectionLimit(String limit) {
        if (limit != null && limit.length() > 0) {
            try {
                setConnectionLimit(Integer.parseInt(limit));
            } catch (Exception ex) {
                Server.logError("invalid DNS connection limit '" + limit + "'.");
            }
        }
    }

    private static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid DNS connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }
    
    private synchronized Connection poll() {
        return CONNECTION_QUEUE.poll();
    }
    
    private synchronized Connection last() {
        return CONNECTION_LIST.pollLast();
    }
    
    private synchronized Connection create() {
        Connection connection = null;
        int id = CONNECTION_LIST.size();
        if (id < CONNECTION_LIMIT) {
            connection = new Connection(id+1);
            connection.start();
            CONNECTION_LIST.add(connection);
        }
        return connection;
    }
    
    private synchronized boolean offerConnection(Connection connection) {
        if (connection == null) {
            return false;
        } else {
            if (CONNECTION_LIST.isEmpty()) {
                CONNECTION_QUEUE.offer(connection);
                ServerDNS.this.notify();
                return true;
            } else if (CONNECTION_QUEUE.size() < 2) {
                CONNECTION_QUEUE.offer(connection);
                ServerDNS.this.notify();
                return true;
            } else if (connection == CONNECTION_LIST.getLast()) {
                connection.interrupt();
                CONNECTION_LIST.removeLast();
                return false;
            } else {
                CONNECTION_QUEUE.offer(connection);
                ServerDNS.this.notify();
                return true;
            }
        }
    }
    
    private Connection pollConnection() {
        Connection connection = poll();
        if (connection == null) {
            try {
                synchronized (ServerDNS.this) {
                    ServerDNS.this.wait(10);
                }
            } catch (InterruptedException ex) {
                // Do nothing.
            }
            if ((connection = poll()) == null) {
                connection = create();
            }
        }
        return connection;
    }
}
