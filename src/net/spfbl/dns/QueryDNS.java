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
package net.spfbl.dns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import net.spfbl.core.Server;
import net.spfbl.spf.SPF;
import net.spfbl.whois.SubnetIPv4;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.core.Analise;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import net.spfbl.core.Client.Permission;
import net.spfbl.core.Core;
import net.spfbl.core.NormalDistribution;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.White;
import net.spfbl.dnsbl.ServerDNSBL;
import net.spfbl.whois.Domain;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;
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
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;

/**
 * Servidor de consulta DNSBL.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QueryDNS extends Server {

    private final int PORT;
    private final DatagramSocket SERVER_SOCKET;

    /**
     * Mapa para cache dos registros DNS consultados.
     */
    private static final HashMap<String,Zone> MAP = new HashMap<>();

    private static final long SERIAL = 2015102500;

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
    
    private static synchronized boolean putExact(String key, ServerDNSBL server) {
        Zone ret = MAP.put(key, new Zone(server));
        if (ret == null) {
            return false;
        } else if (server.getHostName().equals(ret.getHostName())) {
            return false;
        } else {
            return CHANGED = true;
        }
    }

    private static synchronized boolean putExact(String key, Zone zone) {
        Zone ret = MAP.put(key, zone);
        if (zone.equals(ret)) {
            return false;
        } else {
            return CHANGED = true;
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

    private static synchronized boolean containsExact(String host) {
        return MAP.containsKey(host);
    }

    private static synchronized Zone getExact(String host) {
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
        } else if (Domain.isHostname(hostname)) {
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
        } else if (Domain.isHostname(hostname)) {
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
        } else if (Domain.isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            Zone server = new Zone(Zone.Type.DNSWL, hostname, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }

    public static boolean set(String hostname, String message) {
        if (hostname == null) {
            return false;
        } else if (Domain.isHostname(hostname)) {
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
        } else if (Domain.isHostname(hostname)) {
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

    public static Zone dropDNSBL(String hostname) {
        if (hostname == null) {
            return null;
        } else if (Domain.isHostname(hostname)) {
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
        } else if (Domain.isHostname(hostname)) {
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
        } else if (Domain.isHostname(hostname)) {
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

    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing zone.map");
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
        } else {
            file = new File("./data/dnsbl.map");
            if (file.exists()) {
                try {
                    Map<String,ServerDNSBL> map;
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
                    }
                    for (String key : map.keySet()) {
                        ServerDNSBL value = map.get(key);
                        putExact(key, value);
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }
    
    private static String normalizeHost(String address, boolean pontuacao) {
        if (address == null) {
            return null;
        } else if (address.length() == 0) {
            return null;
        } else if (address.contains("@")) {
            address = address.replace("\\@", "@");
            address = Core.removerAcentuacao(address);
            return address.toLowerCase();
        } else if (!Domain.isHostname(address)) {
            return null;
        } else if (pontuacao && !address.startsWith(".")) {
            return "." + Core.removerAcentuacao(address).toLowerCase();
        } else if (pontuacao && address.startsWith(".")) {
            return Core.removerAcentuacao(address).toLowerCase();
        } else if (!pontuacao && !address.startsWith(".")) {
            return Core.removerAcentuacao(address).toLowerCase();
        } else{
            return Core.removerAcentuacao(address.substring(1)).toLowerCase();
        }
    }

    /**
     * Configuração e intanciamento do servidor.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public QueryDNS(int port) throws SocketException {
        super("SERVERDNS");
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding DNS socket on port " + port + "...");
        PORT = port;
        SERVER_SOCKET = new DatagramSocket(port);
        Server.logTrace(getName() + " thread allocation.");
    }

    private int CONNECTION_ID = 0;
    private long CONNECTION_TIME = 0;

    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {

        /**
         * O poll de pacotes de consulta a serem processados.
         */
        private DatagramPacket PACKET = null;
        private int ID = 0;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        private long time = 0;
        
        public Connection() {
//            super("DNSUDP" + Core.formatCentena(CONNECTION_ID++));
            String name = getNextName();
            Server.logDebug("creating " + name + "...");
            setName(name);
            // Toda connexão recebe prioridade normal.
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        private synchronized String getNextName() {
            CONNECTION_TIME = System.currentTimeMillis();
            return "DNSUDP" + Core.formatCentena(ID = ++CONNECTION_ID);
        }
        
        private synchronized boolean closeIfLast() {
            if (ID == 1) {
                return false;
            } else if (ID < CONNECTION_ID) {
                return false;
            } else if (System.currentTimeMillis() - CONNECTION_TIME < 60000) {
                return false;
            } else if (isIdle()) {
                close();
                CONNECTION_ID--;
                CONNECTION_TIME = System.currentTimeMillis();
                return true;
            } else {
                return false;
            }
        }
        
        @Override
        public void start() {
            CONNECTION_COUNT++;
            super.start();
        }

        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private void process(DatagramPacket packet, long time) {
            this.PACKET = packet;
            this.time = time;
            this.SEMAPHORE.release();
        }

        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("closing " + getName() + "...");
            PACKET = null;
            SEMAPHORE.release();
        }

        public DatagramPacket getPacket() {
            if (continueListenning()) {
                try {
                    SEMAPHORE.acquire();
                    interrupted = false;
                } catch (InterruptedException ex) {
                    Server.logError(ex);
                    interrupted = true;
                }
                return PACKET;
            } else {
                return null;
            }
        }

        public void clearPacket() {
            time = 0;
            PACKET = null;
        }
        
        private final NormalDistribution frequency = new NormalDistribution(50);
        private long last = 0;
        private final int LIMIT = 10;
        
        private boolean isIdle() {
            return frequency.getMinimum() > 100.0f;
        }
        
        private long getIdleTimeMillis() {
            if (last == 0) {
                return 0;
            } else {
                return System.currentTimeMillis() - last;
            }
        }
        
        private boolean isDead() {
            int frequencyInt = frequency.getMaximumInt();
            long idleTimeInt = getIdleTimeMillis();
            return idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000;
        }
        
        private boolean isCongested() {
            if (frequency == null) {
                return false;
            } else if (isDead()) {
                return false;
            } else {
                return frequency.getMaximumInt() < LIMIT;
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
        
        private boolean addQuery() {
            Float interval = getInterval();
            if (interval == null) {
                return false;
            } else {
                frequency.addElement(interval);
                return true;
            }
        }

        private boolean interrupted = false;

        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            try {
                do {
                    DatagramPacket packet;
                    while ((packet = getPacket()) != null) {
                        InetAddress ipAddress = packet.getAddress();
                        String origin = ipAddress.getHostAddress();
                        String query = "ERROR";
                        String type = null;
                        String result = "IGNORED";
                        String tag = "DNSQR";
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
                                if (interrupted) {
                                    result = "INTERRUPTED";
                                } else {
                                    // Identificação do cliente.
                                    Client client = Client.create(ipAddress, "DNSBL");
                                    if (client == null) {
                                        result = "IGNORED";
                                    } else if (client.hasPermission(Permission.NONE)) {
                                        client.addQuery();
                                        origin += ' ' + client.getDomain();
                                        result = "IGNORED";
                                    } else if (isCongested() && client.isAbusing()) {
                                        client.addQuery();
                                        origin += ' ' + client.getDomain();
                                        result = "IGNORED";
                                    } else {
                                        client.addQuery();
                                        origin += ' ' + client.getDomain();
                                        long ttl = 3600; // Uma hora padrão.
                                        String host = normalizeHost(query, false);
                                        Zone zone = null;
                                        String clientQuery = null;
                                        if (host == null) {
                                            result = "NXDOMAIN";
                                        } else {
                                            int index = host.length() - 1;
                                            host = host.substring(0, index);
                                            String hostname = null;
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
                                                result = "NXDOMAIN";
                                            } else if (type.equals("NS")) {
                                                if (zone.isHostName(host)) {
                                                    // O NS é o próprio servidor.
                                                    if ((result = Core.getHostname()) == null) {
                                                        result = "NXDOMAIN";
                                                    } else {
                                                        result += '.';
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                            } else if (type.equals("A") && zone.isHostName(host)) {
                                                // O A é o próprio servidor.
                                                if ((result = Core.getHostname()) == null) {
                                                    result = "NXDOMAIN";
                                                } else {
                                                    InetAddress address = InetAddress.getByName(result);
                                                    result = address.getHostAddress();
                                                }
                                            } else if (host.equals(hostname)) {
                                                // Consulta do próprio hostname do servidor.
                                                result = "NXDOMAIN";
                                            } else if (reverse.length() == 0) {
                                                // O reverso é inválido.
                                                result = "NXDOMAIN";
                                            } else if (SubnetIPv4.isValidIPv4(reverse)) {
                                                // A consulta é um IPv4.
                                                clientQuery = SubnetIPv4.reverseToIPv4(reverse);
                                                if (clientQuery.equals("127.0.0.1")) {
                                                    // Consulta de teste para negativo.
                                                    result = "NXDOMAIN";
                                                } else if (clientQuery.equals("127.0.0.2")) {
                                                    // Consulta de teste para positivo.
                                                    result = "127.0.0.2";
                                                    ttl = 0;
                                                } else if (clientQuery.equals("127.0.0.3")) {
                                                    if (client.isPassive()) {
                                                        result = "NXDOMAIN";
                                                    } else {
                                                        // Consulta de teste para positivo.
                                                        result = "127.0.0.3";
                                                        ttl = 0;
                                                    }
                                                } else if (zone.isDNSBL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Block.containsCIDR(clientQuery)) {
                                                        if (status == SPF.Status.RED) {
                                                            result = "127.0.0.2";
                                                            ttl = 604800; // Sete dias.
                                                        } else if (status == SPF.Status.YELLOW) {
                                                            Analise.processToday(clientQuery);
                                                            result = "127.0.0.2";
                                                            ttl = 432000; // Cinco dias.
                                                        } else if (client.isPassive()) {
                                                            Analise.processToday(clientQuery);
                                                            result = "NXDOMAIN";
                                                        } else {
                                                            Analise.processToday(clientQuery);
                                                            result = "127.0.0.3";
                                                            ttl = 259200; // Três dias.
                                                        }
                                                    } else if (status == SPF.Status.RED) {
                                                        Analise.processToday(clientQuery);
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isURIBL()) {
                                                    if (Block.containsHREF(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (status != SPF.Status.GREEN) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Block.containsCIDR(clientQuery)) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Ignore.containsCIDR(clientQuery)) {
                                                        if (SPF.isGood(clientQuery)) {
                                                            result = "127.0.0.2";
                                                        } else {
                                                            result = "127.0.0.3";
                                                        }
                                                        ttl = 604800; // Sete dias.
                                                    } else if (SPF.isGood(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 259200; // Três dias.
                                                    } else if (White.containsIP(clientQuery)) {
                                                        result = "127.0.0.4";
                                                    } else {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                            } else if (SubnetIPv6.isReverseIPv6(reverse)) {
                                                // A consulta é um IPv6.
                                                clientQuery = SubnetIPv6.reverseToIPv6(reverse);
                                                clientQuery = SubnetIPv6.tryTransformToIPv4(clientQuery);
                                                if (clientQuery.equals("0:0:0:0:0:ffff:7f00:1")) {
                                                    // Consulta de teste para negativo.
                                                    result = "NXDOMAIN";
                                                } else if (clientQuery.equals("0:0:0:0:0:ffff:7f00:2")) {
                                                    // Consulta de teste para positivo.
                                                    result = "127.0.0.2";
                                                    ttl = 0;
                                                } else if (clientQuery.equals("0:0:0:0:0:ffff:7f00:3")) {
                                                    if (client.isPassive()) {
                                                        result = "NXDOMAIN";
                                                    } else {
                                                        // Consulta de teste para positivo.
                                                        result = "127.0.0.3";
                                                        ttl = 0;
                                                    }
                                                } else if (zone.isDNSBL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Block.containsCIDR(clientQuery)) {
                                                        if (status == SPF.Status.RED) {
                                                            result = "127.0.0.2";
                                                            ttl = 604800; // Sete dias.
                                                        } else if (status == SPF.Status.YELLOW) {
                                                            Analise.processToday(clientQuery);
                                                            result = "127.0.0.2";
                                                            ttl = 432000; // Cinco dias.
                                                        } else if (client.isPassive()) {
                                                            Analise.processToday(clientQuery);
                                                            result = "NXDOMAIN";
                                                        } else {
                                                            Analise.processToday(clientQuery);
                                                            result = "127.0.0.3";
                                                            ttl = 259200; // Três dias.
                                                        }
                                                    } else if (status == SPF.Status.RED) {
                                                        Analise.processToday(clientQuery);
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else if (status == SPF.Status.YELLOW) {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    } else if (SubnetIPv6.isSLAAC(clientQuery)) {
                                                        result = "NXDOMAIN";
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isURIBL()) {
                                                    if (Block.containsHREF(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (status != SPF.Status.GREEN) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Block.containsCIDR(clientQuery)) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Ignore.containsCIDR(clientQuery)) {
                                                        if (SPF.isGood(clientQuery)) {
                                                            result = "127.0.0.2";
                                                        } else {
                                                            result = "127.0.0.3";
                                                        }
                                                        ttl = 604800; // Sete dias.
                                                    } else if (SPF.isGood(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 259200; // Três dias.
                                                    } else if (White.containsIP(clientQuery)) {
                                                        result = "127.0.0.4";
                                                    } else {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                            } else if ((clientQuery = zone.extractDomain(host)) != null) {
                                                if (clientQuery.equals(".invalid")) {
                                                    // Consulta de teste para negativo.
                                                    result = "NXDOMAIN";
                                                } else if (clientQuery.equals(".test")) {
                                                    // Consulta de teste para positivo.
                                                    result = "127.0.0.2";
                                                    ttl = 0;
                                                } else if (zone.isDNSBL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Generic.containsDynamic(clientQuery)) {
                                                        Analise.processToday(clientQuery);
                                                        if (status == SPF.Status.GREEN) {
                                                            result = "127.0.0.3";
                                                            ttl = 432000; // Cinco dias.
                                                        } else {
                                                            result = "127.0.0.2";
                                                            ttl = 604800; // Sete dias.
                                                        }
                                                    } else if (Block.contains(clientQuery)) {
                                                        if (status == SPF.Status.RED) {
                                                            result = "127.0.0.2";
                                                            ttl = 604800; // Sete dias.
                                                        } else if (status == SPF.Status.YELLOW) {
                                                            result = "127.0.0.2";
                                                            ttl = 432000; // Cinco dias.
                                                        } else if (client.isPassive()) {
                                                            result = "NXDOMAIN";
                                                        } else {
                                                            result = "127.0.0.3";
                                                            ttl = 259200; // Três dias.
                                                        }
                                                    } else if (status == SPF.Status.RED) {
                                                        Analise.processToday(clientQuery);
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isURIBL()) {
                                                    if (Block.containsHREF(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        Analise.processToday(clientQuery);
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (status != SPF.Status.GREEN) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Generic.containsGenericSoft(clientQuery)) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Block.contains(clientQuery)) {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    } else if (Ignore.contains(clientQuery)) {
                                                        if (SPF.isGood(clientQuery)) {
                                                            result = "127.0.0.2";
                                                        } else {
                                                            result = "127.0.0.3";
                                                        }
                                                        ttl = 604800; // Sete dias.
                                                    } else if (SPF.isGood(clientQuery)) {
                                                        result = "127.0.0.2";
                                                        ttl = 259200; // Três dias.
                                                    } else if (White.contains(clientQuery)) {
                                                        result = "127.0.0.4";
                                                    } else {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                            } else {
                                                // Não está listado.
                                                result = "NXDOMAIN";
                                            }
                                        }
                                        if (zone == null) {
                                            tag = "DNSQR";
                                        } else {
                                            tag = zone.getTypeName();
                                        }
                                        String information = null;
                                        if (result.startsWith("127.0.0.")) {
                                            if (zone == null) {
                                                result = "NXDOMAIN";
                                            } else {
                                                information = zone.getMessage(null, clientQuery);
                                                if (information == null) {
                                                    result = "NXDOMAIN";
                                                }
                                            }
                                        }
                                        // Alterando mensagem DNS para resposta.
                                        header.setFlag(Flags.QR);
                                        header.setFlag(Flags.AA);
                                        if (result.equals("NXDOMAIN")) {
                                            header.setRcode(Rcode.NXDOMAIN);
                                            if (zone != null) {
                                                long refresh = 1800;
                                                long retry = 900;
                                                long expire = 604800;
                                                long minimum = 300;
                                                name = new Name(zone.getHostName().substring(1) + '.');
                                                SOARecord soa = new SOARecord(name, DClass.IN, ttl, name,
                                                        name, SERIAL, refresh, retry, expire, minimum);
                                                message.addRecord(soa, Section.AUTHORITY);
                                            }
                                        } else if (type.equals("NS")) {
                                            Name hostname = Name.fromString(result);
                                            NSRecord ns = new NSRecord(name, DClass.IN, ttl, hostname);
                                            message.addRecord(ns, Section.ANSWER);
                                        } else if (type.equals("A") || type.equals("AAAA")) {
                                            InetAddress address = InetAddress.getByName(result);
                                            ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                            message.addRecord(a, Section.ANSWER);
                                        } else if (type.equals("TXT")) {
                                            TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, result = information);
                                            message.addRecord(txt, Section.ANSWER);
                                        } else if (type.equals("ANY") || type.equals("CNAME")) {
                                            InetAddress address = InetAddress.getByName(result);
                                            ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                            message.addRecord(a, Section.ANSWER);
                                            TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, information);
                                            message.addRecord(txt, Section.ANSWER);
                                            result += " " + information;
                                        } else {
                                            InetAddress address = InetAddress.getByName(result);
                                            ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                            message.addRecord(a, Section.ANSWER);
                                        }
                                        result = ttl + " " + result;
                                        // Enviando resposta.
                                        int portDestiny = packet.getPort();
                                        byte[] sendData = message.toWire();
                                        DatagramPacket sendPacket = new DatagramPacket(
                                                sendData, sendData.length,
                                                ipAddress, portDestiny
                                        );
                                        SERVER_SOCKET.send(sendPacket);
                                    }
                                }
                            }
                        } catch (SocketException ex) {
                            // Houve fechamento do socket.
                            result = "CLOSED";
                        } catch (WireParseException ex) {
                            // Ignorar consultas inválidas.
                            query = "UNPARSEABLE";
                            result = "IGNORED";
                        } catch (Exception ex) {
                            Server.logError(ex);
                            result = "ERROR";
                        } finally {
                            Server.logQuery(
                                    time,
                                    tag,
                                    origin,
                                    type == null ? query : type + " " + query,
                                    result
                            );
                            addQuery();
                            clearPacket();
                            // Oferece a conexão ociosa na última posição da lista.
                            offer(this);
                            CONNECION_SEMAPHORE.release();
                            notifyConnection();
                        }
                    }
                } while (interrupted);
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                CONNECTION_COUNT--;
                Server.logTrace(getName() + " thread closed.");
            }
        }
    }

    /**
     * Pool de conexões ativas.
     */
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<>();
    private final LinkedList<Connection> CONNECTION_USE = new LinkedList<>();

    /**
     * Semáforo que controla o pool de conexões.
     */
    private Semaphore CONNECION_SEMAPHORE;

    /**
     * Quantidade total de conexões intanciadas.
     */
    private int CONNECTION_COUNT = 0;

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

    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid DNS connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }

    private synchronized Connection poll() {
        return CONNECTION_POLL.poll();
    }
    
    private synchronized int pollSize() {
        return CONNECTION_POLL.size();
    }

    private synchronized void use(Connection connection) {
        CONNECTION_USE.offer(connection);
    }

    private synchronized void offer(Connection connection) {
        CONNECTION_USE.remove(connection);
        CONNECTION_POLL.offer(connection);
    }
    
    private Connection pollAndCloseIfLast() {
        Connection connection = poll();
        if (connection == null) {
            return null;
        } else if (connection.closeIfLast()) {
            return poll();
        } else {
            return connection;
        }
    }
    
    private synchronized void notifyConnection() {
        notify();
    }
    
    private synchronized Connection waitConnection() {
        try {
            wait(100);
            return poll();
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return null;
        }
    }

    /**
     * Coleta uma conexão ociosa ou inicia uma nova.
     * @return uma conexão ociosa ou nova se não houver ociosa.
     */
    private Connection pollConnection() {
        try {
            if (CONNECION_SEMAPHORE.tryAcquire(1, TimeUnit.SECONDS)) {
                Connection connection = pollAndCloseIfLast();
                if (connection == null) {
                    connection = waitConnection();
                    if (connection == null) {
                        connection = new Connection();
                        connection.start();
                    }
                }
                use(connection);
                return connection;
            } else {
                // Se não houver liberação, ignorar consulta DNS.
                // O MX que fizer a consulta terá um TIMEOUT
                // considerando assim o IP como não listado.
                return null;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }

    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        try {
            Server.logInfo("listening DNS on UDP port " + PORT + ".");
            CONNECION_SEMAPHORE = new Semaphore(CONNECTION_LIMIT);
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length
                    );
                    SERVER_SOCKET.receive(packet);
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            InetAddress ipAddress = packet.getAddress();
                            String result = "TOO MANY CONNECTIONS\n";
                            Server.logQueryDNSBL(time, ipAddress, null, result);
                        } else {
                            try {
                                connection.process(packet, time);
                            } catch (IllegalThreadStateException ex) {
                                // Houve problema na liberação do processo.
                                InetAddress ipAddress = packet.getAddress();
                                String result = "ERROR: FATAL\n";
                                Server.logError(ex);
                                Server.logQueryDNSBL(time, ipAddress, null, result);
                                offer(connection);
                            }
                        }
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
        long last = System.currentTimeMillis();
        while (CONNECTION_COUNT > 0) {
            try {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.tryAcquire(1, TimeUnit.SECONDS);
                } else {
                    connection.close();
                    last = System.currentTimeMillis();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
            if ((System.currentTimeMillis() - last) > 60000) {
                Server.logError("DNS socket close timeout.");
                break;
            }
        }
        Server.logDebug("unbinding DNS socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
