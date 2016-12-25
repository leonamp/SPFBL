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
import net.spfbl.data.Ignore;
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
    private static final HashMap<String,Zone> MAP = new HashMap<String,Zone>();

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
            CHANGED = true;
            return true;
        }
    }

    private static synchronized boolean putExact(String key, Zone zone) {
        Zone ret = MAP.put(key, zone);
        if (zone.equals(ret)) {
            return false;
        } else {
            CHANGED = true;
            return true;
        }
    }

    private static synchronized TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<String>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    private static synchronized HashMap<String,Zone> getMap() {
        HashMap<String,Zone> map = new HashMap<String,Zone>();
        map.putAll(MAP);
        return map;
    }

    public static synchronized HashMap<String,Zone> getDNSBLMap() {
        HashMap<String,Zone> map = new HashMap<String,Zone>();
        for (String key : MAP.keySet()) {
            Zone zone = MAP.get(key);
            if (zone.isDNSBL()) {
                map.put(key, zone);
            }
        }
        return map;
    }
    
    public static synchronized HashMap<String,Zone> getDNSWLMap() {
        HashMap<String,Zone> map = new HashMap<String,Zone>();
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
        TreeSet<Zone> serverSet = new TreeSet<Zone>();
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
                return true;
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
        TreeSet<Zone> serverSet = new TreeSet<Zone>();
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
    
    public static TreeSet<Zone> dropAllDNSWL() {
        TreeSet<Zone> serverSet = new TreeSet<Zone>();
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
                Server.logTrace("storing zone.map");
                long time = System.currentTimeMillis();
                File file = new File("./data/zone.map");
                HashMap<String,Zone> map = getMap();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
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
        File file = new File("./data/zone.map");
        if (file.exists()) {
            try {
                Map<String,Zone> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
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
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
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

    private int CONNECTION_ID = 1;

    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {

        /**
         * O poll de pacotes de consulta a serem processados.
         */
        private DatagramPacket PACKET = null;

        private final Semaphore SEMAPHORE = new Semaphore(0);

        private long time = 0;

        public Connection() {
            super("DNSUDP" + Core.CENTENA_FORMAT.format(CONNECTION_ID++));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
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

        private boolean isTimeout() {
            if (time == 0) {
                return false;
            } else {
                int interval = (int) (System.currentTimeMillis() - time) / 1000;
                return interval > 90;
            }
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
                                String type = Type.string(question.getType());
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
                                    } else if (client.isAbusing()) {
                                        client.addQuery();
                                        origin += ' ' + client.getDomain();
                                        result = "IGNORED";
                                    } else {
                                        client.addQuery();
                                        origin += ' ' + client.getDomain();
                                        long ttl = 3600; // Uma hora padrão.
                                        String host = Domain.extractHost(query, false);
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
                                            } else if (type.equals("A") && zone.isHostName(host)) {
                                                // O A é o próprio servidor.
                                                if ((result = Core.getHostname()) == null) {
                                                    result = "NXDOMAIN";
                                                } else {
                                                    InetAddress address = InetAddress.getByName(result);
                                                    result = address.getHostAddress();
                                                }
                                            } else if (type.equals("NS") && zone.isHostName(host)) {
                                                // O NS é o próprio servidor.
                                                if ((result = Core.getHostname()) == null) {
                                                    result = "NXDOMAIN";
                                                } else {
                                                    result += '.';
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
                                                    Analise.processToday(clientQuery);
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Block.containsCIDR(clientQuery)) {
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
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    Analise.processToday(clientQuery);
                                                    if (Block.containsCIDR(clientQuery)) {
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
                                                Analise.processToday(clientQuery);
                                                if (zone.isDNSBL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Block.containsCIDR(clientQuery)) {
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
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    Analise.processToday(clientQuery);
                                                    if (Block.containsCIDR(clientQuery)) {
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
                                                    } else {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                            } else if ((clientQuery = zone.extractDomain(host)) != null) {
                                                if (zone.isDNSBL()) {
                                                    SPF.Status status = SPF.getStatus(clientQuery, false);
                                                    if (Block.containsDomain(clientQuery)) {
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
                                                        result = "127.0.0.2";
                                                        ttl = 86400; // Um dia.
                                                    } else {
                                                        result = "NXDOMAIN";
                                                    }
                                                } else if (zone.isDNSWL()) {
                                                    Analise.processToday(clientQuery);
                                                    if (Block.containsDomain(clientQuery)) {
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
                                                    } else {
                                                        result = "NXDOMAIN";
                                                        ttl = 86400; // Um dia.
                                                    }
                                                } else {
                                                    result = "NXDOMAIN";
                                                }
                                                clientQuery = Domain.normalizeHostname(clientQuery, false);
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
                                        if (type.equals("TXT") && result.startsWith("127.0.0.")) {
                                            if (zone == null) {
                                                result = "NXDOMAIN";
                                            } else {
                                                String information = zone.getMessage(clientQuery);
                                                if (information == null) {
                                                    result = "NXDOMAIN";
                                                } else {
                                                    result = information;
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
                                        } else if (type.equals("TXT")) {
                                            TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, result);
                                            message.addRecord(txt, Section.ANSWER);
                                        } else if (result.startsWith("127.0.0.")) {
                                            InetAddress address = InetAddress.getByName(result);
                                            ARecord a = new ARecord(name, DClass.IN, ttl, address);
                                            message.addRecord(a, Section.ANSWER);
                                        } else if (type.equals("NS")) {
                                            Name hostname = Name.fromString(result);
                                            NSRecord ns = new NSRecord(name, DClass.IN, ttl, hostname);
                                            message.addRecord(ns, Section.ANSWER);
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
                                    query = type + " " + query;
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
                                    query,
                                    result
                            );
                            clearPacket();
                            // Oferece a conexão ociosa na última posição da lista.
                            offer(this);
                            CONNECION_SEMAPHORE.release();
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
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<Connection>();
    private final LinkedList<Connection> CONNECTION_USE = new LinkedList<Connection>();

    /**
     * Semáforo que controla o pool de conexões.
     */
    private final Semaphore CONNECION_SEMAPHORE = new Semaphore(0);

    /**
     * Quantidade total de conexões intanciadas.
     */
    private int CONNECTION_COUNT = 0;

    private static byte CONNECTION_LIMIT = 16;

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

    private synchronized Connection pollUsing() {
        return CONNECTION_USE.poll();
    }

    private synchronized void use(Connection connection) {
        CONNECTION_USE.offer(connection);
    }

    private synchronized void offer(Connection connection) {
        CONNECTION_USE.remove(connection);
        CONNECTION_POLL.offer(connection);
    }

    private synchronized void offerUsing(Connection connection) {
        CONNECTION_USE.offer(connection);
    }

    public void interruptTimeout() {
        Connection connection = pollUsing();
        if (connection != null) {
            if (connection.isTimeout()) {
                offerUsing(connection);
                connection.interrupt();
            } else {
                offerUsing(connection);
            }
        }
    }

    /**
     * Coleta uma conexão ociosa ou inicia uma nova.
     * @return uma conexão ociosa ou nova se não houver ociosa.
     */
    private Connection pollConnection() {
        try {
            if (CONNECION_SEMAPHORE.tryAcquire(1, TimeUnit.SECONDS)) {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.release();
                } else {
                    use(connection);
                }
                return connection;
            } else if (CONNECTION_COUNT < CONNECTION_LIMIT) {
            // Cria uma nova conexão se não houver conecxões ociosas.
                // O servidor aumenta a capacidade conforme a demanda.
                Server.logDebug("creating DNSUDP" + Core.CENTENA_FORMAT.format(CONNECTION_ID) + "...");
                Connection connection = new Connection();
                connection.start();
                CONNECTION_COUNT++;
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
     * @throws Exception se houver falha em algum fechamento.
     */
    @Override
    protected void close() {
        while (CONNECTION_COUNT > 0) {
            try {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.tryAcquire(500, TimeUnit.MILLISECONDS);
                } else {
                    connection.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        Server.logDebug("unbinding DNS socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
