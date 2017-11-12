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
 */
package net.spfbl.core;

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
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Servidor de recebimento de bloqueio por P2P.
 * 
 * Este serviço ouve todas as informações de bloqueio da rede P2P.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class PeerUDP extends Server {

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
    public PeerUDP(String hostname, int port, int ports, int size) throws SocketException {
        super("SERVERP2P");
        setPriority(Thread.MIN_PRIORITY);
        Server.logDebug("binding P2P socket on port " + port + "...");
        HOSTNAME = hostname;
        PORT = port;
        PORTS = ports;
//        SIZE = size - 20 - 8; // Tamanho máximo da mensagem já descontando os cabeçalhos de IP e UDP.
        SIZE = size;
        // Criando conexões.
        SERVER = new DatagramSocket(port);
        Server.logTrace(getName() + " thread allocation.");
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
            if (https == 0) {
                return HOSTNAME + ":" + PORT;
            } else if (https == 443) {
                return HOSTNAME + ":" + PORT + ":" + PORTS;
            } else {
                return HOSTNAME + ":" + PORT + ":" + PORTS + ":" + https;
            }
        }
    }
    
    private static boolean hasAddress(String hostname,
            InetAddress ipAddress) throws UnknownHostException {
        for (InetAddress address : InetAddress.getAllByName(hostname)) {
            if (address.equals(ipAddress)) {
                return true;
            }
        }
        return false;
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
        private boolean SECURED = false;
        private long time = 0;
        
        public Connection() {
            String name = getNextName();
            Server.logDebug("creating " + name + "...");
            setName(name);
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        private synchronized String getNextName() {
            CONNECTION_TIME = System.currentTimeMillis();
            return "P2PUDP" + Core.formatCentena(ID = ++CONNECTION_ID);
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
        private void process(DatagramPacket packet, boolean secured, long time) {
            this.PACKET = packet;
            this.SECURED = secured;
            this.time = time;
            SEMAPHORE.release();
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("closing " + getName() + "...");
            PACKET = null;
            SECURED = false;
            SEMAPHORE.release();
        }
        
        public DatagramPacket getPacket() {
            if (PeerUDP.this.continueListenning()) {
                try {
                    SEMAPHORE.acquire();
                    return PACKET;
                } catch (InterruptedException ex) {
                    return null;
                }
            } else {
                return null;
            }
        }
        
        public void clearPacket() {
            time = 0;
            PACKET = null;
            SECURED = false;
        }
        
        private final NormalDistribution frequency = new NormalDistribution(50);
        private long last = 0;
        
        private boolean isIdle() {
            return frequency.getMinimum() > 100.f;
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
                        String command = tokenizer.nextToken();
                        if (command.equals("HELO") && tokenizer.hasMoreTokens()) {
                            try {
                                String connection = tokenizer.nextToken().toLowerCase();
                                String version = null;
                                String email = null;
                                if (tokenizer.hasMoreTokens()) {
                                    version = tokenizer.nextToken();
                                    if (Domain.isValidEmail(version)) {
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
                                } else if (email != null && !Domain.isValidEmail(email)) {
                                    result = "INVALID";
                                } else if (version != null && !Core.isValidVersion(version)) {
                                    result = "INVALID";
                                } else {
                                    StringTokenizer connectionTokenizer = new StringTokenizer(connection, ":");
                                    String hostname = connectionTokenizer.nextToken();
                                    String port = connectionTokenizer.nextToken();
                                    String ports = connectionTokenizer.hasMoreTokens() ? connectionTokenizer.nextToken() : null;
                                    String https = connectionTokenizer.hasMoreTokens() ? connectionTokenizer.nextToken() : null;
                                    if (hasAddress(hostname, ipAddress)) {
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
                            } catch (UnknownHostException ex) {
                                result = "INVALID";
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
                    }
                    // Log do bloqueio com o respectivo resultado.
                    Server.log(time,
                            Core.Level.DEBUG,
                            type,
                            address,
                            message,
                            result
                            );
                    addQuery();
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    clearPacket();
                    // Oferece a conexão ociosa na última posição da lista.
                    offer(this);
                    CONNECION_SEMAPHORE.release();
                    notifyConnection();
                }
            }
            CONNECTION_COUNT--;
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
                        // Cria uma nova conexão se não houver conexões ociosas.
                        // O servidor aumenta a capacidade conforme a demanda.
                        connection = new Connection();
                        connection.start();
                    }
                }
                use(connection);
                return connection;
            } else {
                return null;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    private void startService() {
        try {
            Server.logInfo("listening P2P port " + PORT + ".");
            CONNECION_SEMAPHORE = new Semaphore(CONNECTION_LIMIT);
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
                                    null,
                                    "TOO MANY CONNECTIONS"
                                    );
                        } else {
                            try {
                                connection.process(packet, false, time);
                            } catch (IllegalThreadStateException ex) {
                                // Houve problema na liberação do processo.
                                InetAddress ipAddress = packet.getAddress();
                                String result = "ERROR: FATAL\n";
                                Server.logError(ex);
                                Server.logQueryP2PUDP(time, ipAddress, null, result);
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
                                    null,
                                    "TOO MANY CONNECTIONS"
                                    );
                        } else {
                            try {
                                connection.process(packet, true, time);
                            } catch (Exception ex) {
                                // Houve problema na liberação do processo.
                                InetAddress ipAddress = packet.getAddress();
                                String result = "ERROR: FATAL\n";
                                Server.logError(ex);
                                Server.logQueryP2PUDP(time, ipAddress, null, result);
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
            Server.logInfo("querie P2PS server closed.");
        }
    }
    
    /**
     * Inicialização do serviço.
     */
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
                    Server.logDebug("binding P2PS socket on port " + PORTS + "...");
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
                Server.logError("querie P2P socket close timeout.");
                break;
            }
        }
        if (SERVERS != null) {
            Server.logDebug("unbinding P2PS socket on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logDebug("unbinding P2P socket on port " + PORT + "...");
        SERVER.close();
    }
}
