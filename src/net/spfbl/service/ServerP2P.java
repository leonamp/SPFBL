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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 *
 */
package net.spfbl.service;

import net.spfbl.spf.SPF;
import java.io.IOException;
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.concurrent.Semaphore;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import net.spfbl.core.Core;
import net.spfbl.core.Peer;
import static net.spfbl.core.Regex.isValidEmail;
import net.spfbl.core.Server;
import net.spfbl.data.FQDN;
import net.spfbl.whois.Domain;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Servidor de recebimento de bloqueio por P2P.
 *
 * Este serviço ouve todas as informações de bloqueio da rede P2P.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class ServerP2P extends Server {

    private final String HOSTNAME;
    private final int PORT;
    private final int PORTS;
    private final int SIZE; // Tamanho máximo da mensagem do pacote UDP de reposta.
    private final DatagramSocket SERVER;
    private DatagramSocket SERVERS = null;

    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta UDP a ser vinculada.
     * @param size o tamanho máximo do pacote UDP.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public ServerP2P(String hostname, int port, int ports, int size) throws SocketException {
        super("SERVERP2P");
        setPriority(Thread.MIN_PRIORITY);
        Server.logInfo("binding P2P socket on port " + port + "...");
        HOSTNAME = hostname;
        PORT = port;
        PORTS = ports;
//        SIZE = size - 20 - 8; // Tamanho máximo da mensagem já descontando os cabeçalhos de IP e UDP.
        SIZE = size;
        // Criando conexões.
        SERVER = new DatagramSocket(port);
        Server.logTrace(getName() + " thread allocation.");
    }

    @Override
    public void run() {
        startService();
        if (!Core.hasRecaptchaKeys()) {
            Server.logError("P2PS socket was not binded because reCAPTCHA keys was not defined.");
        } else {
            Core.waitStartHTTP();
            if (Core.getServiceHTTPS() == 0) {
                Server.logError("P2PS socket was not binded because HTTPS was not started.");
            } else {
                try {
                    Server.logInfo("binding P2PS socket on port " + PORTS + "...");
                    SERVERS = new DatagramSocket(PORTS);
                    Thread sslService = new Thread() {
                        @Override
                        public void run() {
                            setName("SERVERP2P");
                            startSecuredService();
                        }
                    };
                    sslService.start();
                } catch (BindException ex) {
                    Server.logError("P2PS socket was not binded because UDP port " + PORTS + " is already in use.");
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    private void startService() {
        try {
            Server.logInfo("listening P2P port " + PORT + ".");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length
                    );
                    SERVER.receive(packet);
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            InetAddress address = packet.getAddress();
                            Peer peer = Peer.get(address);
                            Server.logQuery(
                                    time,
                                    "PEERB",
                                    (peer == null ? address.getHostAddress() : peer.getAddress()),
                                    (Long) null,
                                    null,
                                    "TOO MANY CONNECTIONS"
                                    );
                        } else {
                            connection.process(packet, false, time);
                        }
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie P2P server closed.");
        }
    }

    private void startSecuredService() {
        try {
            Server.logInfo("listening P2PS port " + PORTS + ".");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length
                    );
                    SERVERS.receive(packet);
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            Server.logQuery(
                                    time,
                                    "PEERB",
                                    packet.getAddress(),
                                    (Long) null, null,
                                    "TOO MANY CONNECTIONS"
                                    );
                        } else {
                            connection.process(packet, true, time);
                        }
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie P2PS server closed.");
        }
    }

    @Override
    protected void close() {
        Connection connection;
        while ((connection = last()) != null) {
            connection.interrupt();
        }
        if (SERVERS != null) {
            Server.logInfo("unbinding P2PS socket on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logInfo("unbinding P2P socket on port " + PORT + "...");
        SERVER.close();
    }

    public boolean hasConnection() {
        return HOSTNAME != null;
    }

    public String getConnection() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return HOSTNAME + ":" + PORT;
        }
    }

    public String getSecuredConnection() {
        if (HOSTNAME == null) {
            return null;
        } else if (PORTS == 0) {
            return HOSTNAME + ":" + PORT;
        } else if (SERVERS == null) {
            return HOSTNAME + ":" + PORT;
        } else {
            int https = Core.getServiceHTTPS();
            switch (https) {
                case 0:
                    return HOSTNAME + ":" + PORT;
                case 443:
                    return HOSTNAME + ":" + PORT + ":" + PORTS;
                default:
                    return HOSTNAME + ":" + PORT + ":" + PORTS + ":" + https;
            }
        }
    }
    
    private static boolean LOG = false;
    
    public static void setLog(boolean mustLog) {
        LOG = mustLog;
    }
    
    private class Connection extends Thread {

        /**
         * O poll de pacotes de consulta a serem processados.
         */
        private DatagramPacket PACKET = null;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        private boolean SECURED = false;
        private long TIME = 0;

        public Connection(int id) {
            String name = "P2PUDP" + Core.formatCentena(id);
            Server.logInfo("creating " + name + "...");
            setName(name);
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }

        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private void process(DatagramPacket packet, boolean secured, long time) {
            PACKET = packet;
            SECURED = secured;
            TIME = time;
            SEMAPHORE.release();
        }
        
        @Override
        public void interrupt() {
            Server.logInfo("closing " + getName() + "...");
            PACKET = null;
            SECURED = false;
            SEMAPHORE.release();
        }

        public DatagramPacket getPacket() {
            if (ServerP2P.this.continueListenning()) {
                try {
                    SEMAPHORE.acquire();
                    return PACKET;
                } catch (InterruptedException ex) {
                    Server.logError(ex);
                    return null;
                }
            } else {
                return null;
            }
        }

        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            DatagramPacket packet;
            while ((packet = getPacket()) != null) {
                try {
                    String type = "PEERR";
                    String message = null;
                    String result = null;
                    InetAddress ipAddress = packet.getAddress();
                    String address = ipAddress.getHostAddress();
                    Peer peer = Peer.get(ipAddress);
                    byte[] data = packet.getData();
                    int length = packet.getLength();
                    data = ArrayUtils.subarray(data, 0, length);
                    if (SECURED) {
                        message = "CIPHERED DATA";
                        if (peer == null) {
                            result = "UNKNOWN";
                        } else {
                            SecretKey secretKey = peer.getDecryptKey();
                            if (secretKey == null) {
                                result = "NO DECRYPT KEY";
                            } else {
                                try {
                                    Cipher cipher = Cipher.getInstance("AES");
                                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                                    data = cipher.doFinal(data);
                                } catch (Exception ex) {
                                    result = "DECRYPT ERROR";
                                }
                            }
                        }
                    }
                    if (result == null) {
                        message = new String(data, "ISO-8859-1");
                        StringTokenizer tokenizer = new StringTokenizer(message, " ");
                        if (tokenizer.hasMoreTokens()) {
                            String command = tokenizer.nextToken();
                            if (command.equals("HELO") && tokenizer.hasMoreTokens()) {
                                try {
                                    String connection = tokenizer.nextToken().toLowerCase();
                                    String version = null;
                                    String email = null;
                                    if (tokenizer.hasMoreTokens()) {
                                        version = tokenizer.nextToken();
                                        if (isValidEmail(version)) {
                                            email = version;
                                            email = email.toLowerCase();
                                            version = null;
                                        } else if (tokenizer.hasMoreTokens()) {
                                            email = tokenizer.nextToken();
                                            email = email.toLowerCase();
                                        }
                                    }
                                    if (connection == null || !connection.contains(":")) {
                                        result = "INVALID";
                                    } else if (email != null && !isValidEmail(email)) {
                                        result = "INVALID";
                                    } else if (version != null && !Core.isValidVersion(version)) {
                                        result = "INVALID";
                                    } else {
                                        StringTokenizer connectionTokenizer = new StringTokenizer(connection, ":");
                                        String hostname = connectionTokenizer.nextToken();
                                        String port = connectionTokenizer.nextToken();
                                        String ports = connectionTokenizer.hasMoreTokens() ? connectionTokenizer.nextToken() : null;
                                        String https = connectionTokenizer.hasMoreTokens() ? connectionTokenizer.nextToken() : null;
                                        if (FQDN.addFQDN(ipAddress.getHostAddress(), hostname, true)) {
                                            if (peer == null) {
                                                peer = Peer.create(hostname, port, ports, https);
                                                if (peer == null) {
                                                    result = "NOT CREATED";
                                                } else {
                                                    peer.setVersion(version);
                                                    peer.setEmail(email);
                                                    peer.addNotification();
                                                    result = "CREATED";
                                                    peer.requestSecretKey(HOSTNAME);
                                                }
                                            } else if (peer.getAddress().equals(hostname)) {
                                                peer.setPort(port);
                                                peer.setSecuredPort(ports, https);
                                                peer.setVersion(version);
                                                peer.setEmail(email);
                                                peer.addNotification();
                                                result = "UPDATED";
                                                peer.requestSecretKey(HOSTNAME);
                                            } else {
                                                peer.drop();
                                                peer = peer.clone(hostname);
                                                peer.addNotification();
                                                result = "UPDATED";
                                                peer.requestSecretKey(HOSTNAME);
                                            }
                                        } else {
                                            result = "NOT MATCH";
                                        }
                                    }
                                } catch (Exception ex) {
                                    Server.logError(ex);
                                    result = "ERROR " + ex.getMessage();
                                } finally {
                                    type = "PEERH";
                                }
                            } else if (peer == null) {
                                result = "UNKNOWN";
                            } else if (command.equals("REPUTATION") && tokenizer.countTokens() > 2) {
                                address = peer.getAddress();
                                String key = tokenizer.nextToken();
                                String ham = tokenizer.nextToken();
                                String spam = tokenizer.nextToken();
                                String frequencyXi = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                String frequencyXi2 = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                peer.addNotification();
                                result = peer.setReputation(
                                        key, ham, spam,
                                        frequencyXi, frequencyXi2
                                );
                                SPF.createDistribution(key);
                            } else if (command.equals("BLOCK") && tokenizer.hasMoreTokens()) {
                                address = peer.getAddress();
                                type = "PEERB";
                                String block = tokenizer.nextToken();
                                peer.addNotification();
                                result = peer.processBlock(block);
                            } else if (SPF.isValidReputation(command) && tokenizer.countTokens() > 1) {
                                address = peer.getAddress();
                                String key = command;
                                String ham = tokenizer.nextToken();
                                String spam = tokenizer.nextToken();
                                String frequencyXi = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                String frequencyXi2 = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                peer.addNotification();
                                result = peer.setReputation(
                                        key, ham, spam,
                                        frequencyXi, frequencyXi2
                                );
                                SPF.createDistribution(key);
                            } else if (Peer.isValidBlock(command) && !tokenizer.hasMoreTokens()) {
                                address = peer.getAddress();
                                type = "PEERB";
                                String block = command;
                                peer.addNotification();
                                result = peer.processBlock(block);
                            } else {
                                address = peer.getAddress();
                                result = "INVALID";
                                type = "PEERI";
                            }
                        } else {
                            result = "INVALID";
                        }
                    }
                    if (LOG) {
                        // Log do bloqueio com o respectivo resultado.
                        Server.log(
                                TIME,
                                Core.Level.DEBUG,
                                type,
                                address,
                                (Long) null,
                                message,
                                result
                                );
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    offerConnection(this);
                }
            }
            Server.logTrace(getName() + " thread closed.");
        }
    }

    public boolean isTooBig(String token) {
        if (token == null) {
            return false;
        } else {
            try {
                return token.getBytes("ISO-8859-1").length > SIZE;
            } catch (Exception ex) {
                return false;
            }
        }
    }

    /**
     * Envia um pacote do resultado em UDP para o destino.
     * @param message o resultado que deve ser enviado.
     * @param address o IP do destino.
     * @param port a porta de resposta do destino.
     * @return send result.
     */
    public String send(
            String message,
            String address,
            int port,
            int ports,
            SecretKey secretKey
    ) {
        try {
            byte[] sendData;
            if (ports == 0) {
                sendData = message.getBytes("ISO-8859-1");
            } else if (secretKey == null) {
                sendData = message.getBytes("ISO-8859-1");
            } else {
                try {
                    byte[] simplyfiedData;
                    if (message.startsWith("REPUTATION ")) {
                        simplyfiedData = message.substring(11).getBytes("ISO-8859-1");
                    } else if (message.startsWith("BLOCK ")) {
                        simplyfiedData = message.substring(6).getBytes("ISO-8859-1");
                    } else {
                        simplyfiedData = message.getBytes("ISO-8859-1");
                    }
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    sendData = cipher.doFinal(simplyfiedData);
                    port = ports;
                } catch (Exception ex) {
                    Server.logError(ex);
                    sendData = message.getBytes("ISO-8859-1");
                }
            }
            if (sendData.length > SIZE) {
                return "TOO BIG";
            } else {
                InetAddress inetAddress = InetAddress.getByName(address);
                DatagramPacket sendPacket = new DatagramPacket(
                        sendData, sendData.length,
                        inetAddress, port
                );
                SERVER.send(sendPacket);
                return address;
            }
        } catch (UnknownHostException ex) {
            return "UNKNOWN";
        } catch (IOException ex) {
            return "UNREACHABLE";
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
                Server.logError("invalid P2P connection limit '" + limit + "'.");
            }
        }
    }

    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid P2P connection limit '" + limit + "'.");
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
                ServerP2P.this.notify();
                return true;
            } else if (CONNECTION_QUEUE.size() < 2) {
                CONNECTION_QUEUE.offer(connection);
                ServerP2P.this.notify();
                return true;
            } else if (connection == CONNECTION_LIST.getLast()) {
                connection.interrupt();
                CONNECTION_LIST.removeLast();
                return false;
            } else {
                CONNECTION_QUEUE.offer(connection);
                ServerP2P.this.notify();
                return true;
            }
        }
    }
    
    private Connection pollConnection() {
        Connection connection = poll();
        if (connection == null) {
            try {
                synchronized (ServerP2P.this) {
                    ServerP2P.this.wait(10);
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
