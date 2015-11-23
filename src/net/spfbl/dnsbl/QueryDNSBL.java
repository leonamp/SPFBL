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
package net.spfbl.dnsbl;

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
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.core.Client;
import net.spfbl.whois.Domain;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * Servidor de consulta DNSBL.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QueryDNSBL extends Server {

    private final int PORT;
    private final DatagramSocket SERVER_SOCKET;
    
    /**
     * Mapa para cache dos registros DNS consultados.
     */
    private static final HashMap<String,ServerDNSBL> MAP = new HashMap<String,ServerDNSBL>();
    
    private static final long SERIAL = 2015102500;
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    private static ServerDNSBL dropExact(String token) {
        ServerDNSBL ret = MAP.remove(token);
        if (ret == null) {
            return null;
        } else {
            CHANGED = true;
            return ret;
        }
    }

    private static boolean putExact(String key, ServerDNSBL value) {
        ServerDNSBL ret = MAP.put(key, value);
        if (value.equals(ret)) {
            return false;
        } else {
            CHANGED = true;
            return true;
        }
    }

    private static TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<String>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }

    public static HashMap<String,ServerDNSBL> getMap() {
        HashMap<String,ServerDNSBL> map = new HashMap<String,ServerDNSBL>();
        map.putAll(MAP);
        return map;
    }

    private static boolean containsExact(String host) {
        return MAP.containsKey(host);
    }

    private static ServerDNSBL getExact(String host) {
        return MAP.get(host);
    }

    public static TreeSet<ServerDNSBL> getValues() {
        TreeSet<ServerDNSBL> serverSet = new TreeSet<ServerDNSBL>();
        serverSet.addAll(MAP.values());
        return serverSet;
    }
    
    /**
     * Adiciona um registro DNS no mapa de cache.
     */
    public static boolean add(String hostname, InetAddress address, String message) {
        if (hostname == null || address == null) {
            return false;
        } else if (Domain.isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            ServerDNSBL server = new ServerDNSBL(hostname, address, message);
            return putExact(hostname, server) ;
        } else {
            return false;
        }
    }
    
    public static boolean set(String hostname, InetAddress address, String message) {
        if (hostname == null || address == null) {
            return false;
        } else if (Domain.isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            ServerDNSBL server = getExact(hostname);
            if (server == null) {
                return false;
            } else {
                server.setInetAddress(address);
                server.setMessage(message);
                return true;
            }
        } else {
            return false;
        }
    }
    
    private static ServerDNSBL get(String hostname) {
        if (hostname == null) {
            return null;
        } else if (Domain.isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            return getExact(hostname);
        } else {
            return null;
        }
    }
    
    public static TreeSet<ServerDNSBL> dropAll() {
        TreeSet<ServerDNSBL> serverSet = new TreeSet<ServerDNSBL>();
        for (ServerDNSBL server : getValues()) {
            if (server != null) {
                String hostname = server.getHostName();
                server = dropExact(hostname);
                if (server != null) {
                    serverSet.add(server);
                }
            }
        }
        return serverSet;
    }
    
    public static ServerDNSBL drop(String hostname) {
        if (hostname == null) {
            return null;
        } else if (Domain.isHostname(hostname)) {
            hostname = Domain.normalizeHostname(hostname, true);
            return dropExact(hostname);
        } else {
            return null;
        }
    }
    
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/dnsbl.map");
                HashMap<String,ServerDNSBL> map = getMap();
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
        File file = new File("./data/dnsbl.map");
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
        } else if ((file = new File("./data/dns.map")).exists()) {
            try {
                HashMap<String,InetAddress> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    InetAddress value = map.get(key);
                    String message = "<IP> is listed in this server.";
                    ServerDNSBL server = new ServerDNSBL(key, value, message);
                    putExact(key, server);
                    CHANGED = true;
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Configuração e intanciamento do servidor.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public QueryDNSBL(int port) throws SocketException {
        super("SERVERDNS");
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding DNSBL socket on port " + port + "...");
        PORT = port;
        SERVER_SOCKET = new DatagramSocket(port);
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
        
        private long time = 0;
        
        public Connection() {
            super("DNSUDP" + Server.CENTENA_FORMAT.format(CONNECTION_ID++));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.NORM_PRIORITY);
        }
        
        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private synchronized void process(DatagramPacket packet, long time) {
            this.PACKET = packet;
            this.time = time;
            if (isAlive()) {
                // Libera o próximo processamento.
                notify();
            } else {
                // Inicia a thread pela primmeira vez.
                start();
            }
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private synchronized void close() {
            Server.logDebug("closing " + getName() + "...");
            PACKET = null;
            notify();
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public synchronized void run() {
            while (continueListenning() && PACKET != null) {
                InetAddress ipAddress = null;
                String query = null;
                String type = null;
                try {
                    byte[] data = PACKET.getData();
                    // Processando consulta DNS.
                    Message message = new Message(data);
                    Header header = message.getHeader();
                    Record question = message.getQuestion();
                    Name name = question.getName();
                    type = Type.string(question.getType());
                    query = name.toString();
                    String result = "UNDEFINED";
                    long ttl = 3600; // Uma hora.
                    String information = null;
                    String ip = "";
                    ServerDNSBL server = null;
                    if (Domain.isHostname(query)) {
                        query = Domain.extractHost(query, true);
                        int index = query.length() - 1;
                        query = query.substring(0, index);
                        String hostname = null;
                        String reverse = "";
                        while ((index = query.lastIndexOf('.', index)) != -1) {
                            reverse = query.substring(0, index);
                            hostname = query.substring(index);
                            if ((server = getExact(hostname)) == null) {
                                index--;
                            } else {
                                break;
                            }
                        }
                        if (server == null) {
                            // Não existe servidor DNSBL cadastrado.
                            result = "NXDOMAIN";
                        } else if (query.equals(hostname)) {
                            // Consulta do próprio hostname do servidor.
                            result = server.getHostAddress();
                        } else if (reverse.length() == 0) {
                            // O reverso é inválido.
                            result = "NXDOMAIN";
                        } else if (SubnetIPv4.isValidIPv4(reverse.substring(1))) {
                            // A consulta é um IPv4.
                            ip = SubnetIPv4.reverseToIPv4(reverse.substring(1));
                            if (ip.equals("127.0.0.1")) {
                                // Consulta de teste para negativo.
                                result = "NXDOMAIN";
                            } else if (ip.equals("127.0.0.2")) {
                                // Consulta de teste para positivio.
                                result = "127.0.0.2";
                                information = server.getMessage();
                            } else if (SPF.isBlacklisted(ip)) {
                                result = "127.0.0.2";
                                information = server.getMessage();
                                ttl = SPF.getComplainTTL(ip);
                            } else {
                                result = "NXDOMAIN";
                            }
                        } else if (SubnetIPv6.isReverseIPv6(reverse)) {
                            // A consulta é um IPv6.
                            ip = SubnetIPv6.reverseToIPv6(reverse);
                            if (SPF.isBlacklisted(ip)) {
                                result = "127.0.0.2";
                                information = server.getMessage();
                                ttl = SPF.getComplainTTL(ip);
                            } else {
                                result = "NXDOMAIN";
                            }
                        } else {
                            // Não está listado.
                            result = "NXDOMAIN";
                        }
                    }
                    if (ttl < 3600) {
                        // O TTL nunca será menor que uma hora.
                        ttl = 3600;
                    } else if (ttl > 86400) {
                        // O TTL nunca será maior que um dia.
                        ttl = 86400;
                    }
                    // Alterando mensagem DNS para resposta.
                    header.setFlag(Flags.QR);
                    header.setFlag(Flags.AA);
                    if (result.equals("NXDOMAIN")) {
                        header.setRcode(Rcode.NXDOMAIN);
                        if (server != null) {
                            long refresh = 1800;
                            long retry = 900;
                            long expire = 604800;
                            long minimum = 86400;
                            name = new Name(server.getHostName().substring(1) + '.');
                            SOARecord soa = new SOARecord(name, DClass.IN, ttl, name,
                                    name, SERIAL, refresh, retry, expire, minimum);
                            message.addRecord(soa, Section.AUTHORITY);
                        }
                    } else if (type.equals("A") && result.equals("127.0.0.2")) {
                        InetAddress address = InetAddress.getByName(result);
                        ARecord a = new ARecord(name, DClass.IN, ttl, address);
                        message.addRecord(a, Section.ANSWER);
                        result = ttl + " " + result;
                    } else if (type.equals("TXT") && information != null) {
                        ttl = 604800; // Uma semana somente para TXT.
                        information = information.replace("<IP>", ip);
                        TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, information);
                        message.addRecord(txt, Section.ANSWER);
                        result = ttl + " " + information;
                    } else if (type.equals("A")) {
                        InetAddress address = InetAddress.getByName(result);
                        ARecord a = new ARecord(name, DClass.IN, ttl, address);
                        message.addRecord(a, Section.ANSWER);
                        result = ttl + " " + result;
                    } else {
                        result = ttl + " " + result;
                    }
                    // Enviando resposta.
                    ipAddress = PACKET.getAddress();
                    int portDestiny = PACKET.getPort();
                    byte[] sendData = message.toWire();
                    DatagramPacket sendPacket = new DatagramPacket(
                            sendData, sendData.length,
                            ipAddress, portDestiny
                            );
                    SERVER_SOCKET.send(sendPacket);
                    // Log da consulta com o respectivo resultado.
                    Client client = Client.get(ipAddress);
                    if (client == null) {
                        String origin = ipAddress.getHostAddress();
                        Server.logQueryDNSBL(time, origin, type + ' ' + query, result);
                    } else {
                        client.addQuery();
                        String origin = ipAddress.getHostAddress() + ' ' + client.getDomain();
                        Server.logQueryDNSBL(time, origin, type + ' ' + query, result);
                    }
                } catch (SocketException ex) {
                    // Houve fechamento do socket.
                    Server.logQueryDNSBL(time, ipAddress == null ? null : ipAddress.getHostAddress(), type + ' ' + query, "SOCKET CLOSED");
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    try {
                        PACKET = null;
                        // Oferece a conexão ociosa na última posição da lista.
                        offer(this);
                        CONNECION_SEMAPHORE.release();
                        // Aguarda nova chamada.
                        wait();
                    } catch (InterruptedException ex) {
                        Server.logError(ex);
                    }
                }
            }
            CONNECTION_COUNT--;
        }
    }
    
    /**
     * Pool de conexões ativas.
     */
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<Connection>();
    
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
                Server.logError("invalid DNSBL connection limit '" + limit + "'.");
            }
        }
    }
    
    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid DNSBL connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }
    
    private synchronized Connection poll() {
        return CONNECTION_POLL.poll();
    }
    
    private synchronized void offer(Connection connection) {
        CONNECTION_POLL.offer(connection);
    }
    
    /**
     * Coleta uma conexão ociosa ou inicia uma nova.
     * @return uma conexão ociosa ou nova se não houver ociosa.
     */
    private Connection pollConnection() {
        if (CONNECION_SEMAPHORE.tryAcquire()) {
            Connection connection = poll();
            if (connection == null) {
                CONNECION_SEMAPHORE.release();
            }
            return connection;
        } else if (CONNECTION_COUNT < CONNECTION_LIMIT) {
            // Cria uma nova conexão se não houver conecxões ociosas.
            // O servidor aumenta a capacidade conforme a demanda.
            Server.logDebug("creating DNSUDP" + Server.CENTENA_FORMAT.format(CONNECTION_ID) + "...");
            Connection connection = new Connection();
            CONNECTION_COUNT++;
            return connection;
        } else {
            // Se não houver liberação, ignorar consulta DNS.
            // O MX que fizer a consulta terá um TIMEOUT 
            // considerando assim o IP como não listado.
            return null;
        }
    }
    
    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        try {
            Server.logDebug("listening DNSBL on UDP port " + PORT + "...");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
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
            Server.logDebug("querie DNSBL server closed.");
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
                    CONNECION_SEMAPHORE.tryAcquire(100, TimeUnit.MILLISECONDS);
                } else if (connection.isAlive()) {
                    connection.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        Server.logDebug("unbinding DSNBL socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
