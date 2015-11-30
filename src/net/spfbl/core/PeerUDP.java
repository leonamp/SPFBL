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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.whois.Domain;

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
    private final int SIZE; // Tamanho máximo da mensagem do pacote UDP de reposta.
    private final DatagramSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta UDP a ser vinculada.
     * @param size o tamanho máximo do pacote UDP.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public PeerUDP(String hostname, int port, int size) throws SocketException {
        super("SERVERP2P");
        setPriority(Thread.MIN_PRIORITY);
        Server.logDebug("binding P2P socket on port " + port + "...");
        HOSTNAME = hostname;
        PORT = port;
        SIZE = size - 20 - 8; // Tamanho máximo da mensagem já descontando os cabeçalhos de IP e UDP.
        // Criando conexões.
        SERVER_SOCKET = new DatagramSocket(port);
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
    
    private static boolean hasAddress(String hostname,
            InetAddress ipAddress) throws UnknownHostException {
        for (InetAddress address : InetAddress.getAllByName(hostname)) {
            if (address.equals(ipAddress)) {
                return true;
            }
        }
        return false;
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
            super("P2PUDP" + Server.CENTENA_FORMAT.format(CONNECTION_ID++));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
        }
        
        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private void process(DatagramPacket packet, long time) {
            this.PACKET = packet;
            this.time = time;
            SEMAPHORE.release();
        }
        
        private boolean isTimeout() {
            if (time == 0) {
                return false;
            } else {
                int interval = (int) (System.currentTimeMillis() - time) / 1000;
                return interval > 20;
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
                    String address;
                    String result;
                    String type;
                    InetAddress ipAddress = packet.getAddress();
                    byte[] data = packet.getData();
                    String token = new String(data, "ISO-8859-1").trim();
                    if (token.startsWith("HELO ")) {
                        address = ipAddress.getHostAddress();
                        try {
                            int index = token.indexOf(' ') + 1;
                            String helo = token.substring(index);
                            StringTokenizer tokenizer = new StringTokenizer(helo, " ");
                            String connection = null;
                            String email = null;
                            if (tokenizer.hasMoreTokens()) {
                                connection = tokenizer.nextToken();
                                connection = connection.toLowerCase();
                                if (tokenizer.hasMoreTokens()) {
                                    email = tokenizer.nextToken();
                                    email = email.toLowerCase();
                                }
                            }
                            if (connection == null || connection.length() == 0) {
                                result = "INVALID";
                            } else if (email != null && !Domain.isEmail(email)) {
                                result = "INVALID";
                            } else {
                                index = connection.indexOf(':');
                                String hostname = connection.substring(0, index);
                                String port = connection.substring(index + 1);
                                if (hasAddress(hostname, ipAddress)) {
                                    Peer peer = Peer.get(ipAddress);
                                    if (peer == null) {
                                        peer = Peer.create(hostname, port);
                                        if (peer == null) {
                                            result = "NOT CREATED";
                                        } else {
                                            peer.setEmail(email);
                                            peer.addNotification();
                                            result = "CREATED";
                                        }
                                    } else if (peer.getAddress().equals(hostname)) {
                                        peer.setPort(port);
                                        peer.setEmail(email);
                                        peer.addNotification();
                                        result = "UPDATED";
                                    } else {
                                        peer.drop();
                                        peer = peer.clone(hostname);
                                        peer.addNotification();
                                        result = "UPDATED";
                                    }
                                } else {
                                    result = "NOT MATCH";
                                }
                            }
                        } catch (UnknownHostException ex) {
                            result = "UNKNOWN";
                        } catch (Exception ex) {
                            Server.logError(ex);
                            result = "ERROR " + ex.getMessage();
                        } finally {
                            type = "PEERH";
                        }
                    } else if (token.startsWith("REPUTATION ")) {
                        type = "PEERR";
                        int index = token.indexOf(' ') + 1;
                        String reputation = token.substring(index);
                        StringTokenizer tokenizer = new StringTokenizer(reputation, " ");
                        if (tokenizer.countTokens() == 3) {
                            address = ipAddress.getHostAddress();
                            try {
                                String key = tokenizer.nextToken();
                                String ham = tokenizer.nextToken();
                                String spam = tokenizer.nextToken();
                                Peer peer = Peer.get(ipAddress);
                                if (peer == null) {
                                    address = ipAddress.getHostAddress();
                                    result = "UNKNOWN";
                                } else {
                                    address = peer.getAddress();
                                    peer.addNotification();
                                    result = peer.setReputation(key, ham, spam);
                                }
                            } catch (ProcessException ex) {
                                result = ex.getErrorMessage();
                            }
                        } else {
                            address = ipAddress.getHostAddress();
                            result = "INVALID";
                        }
                    } else if (token.startsWith("BLOCK ")) {
                        type = "PEERB";
                        int index = token.indexOf(' ') + 1;
                        String block = token.substring(index);
                        Peer peer = Peer.get(ipAddress);
                        if (peer == null) {
                            address = ipAddress.getHostAddress();
                            result = "UNKNOWN";
                        } else {
                            address = peer.getAddress();
                            peer.addNotification();
                            result = peer.processBlock(block);
                        }
                    } else {
                        Peer peer = Peer.get(ipAddress);
                        if (peer == null) {
                            address = ipAddress.getHostAddress();
                            result = "UNKNOWN";
                            type = "PEERU";
                        } else {
                            peer.addNotification();
                            address = peer.getAddress();
                            result = peer.processReceive(token);
                            type = "PEERB";
                        }
                    }
                    // Log do bloqueio com o respectivo resultado.
                    Server.log(
                            time,
                            Core.Level.DEBUG,
                            type,
                            address,
                            token,
                            result
                            );
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    clearPacket();
                    // Oferece a conexão ociosa na última posição da lista.
                    offer(this);
                    CONNECION_SEMAPHORE.release();
                }
            }
            CONNECTION_COUNT--;
        }
    }
    
    /**
     * Envia um pacote do resultado em UDP para o destino.
     * @param token o resultado que deve ser enviado.
     * @param address o IP do destino.
     * @param port a porta de resposta do destino.
     * @throws ProcessException se houver falha no envio.
     */
    public String send(String token, String address, int port) {
        try {
            byte[] sendData = token.getBytes("ISO-8859-1");
            if (sendData.length > SIZE) {
                return "TOO BIG";
            } else {
                InetAddress inetAddress = InetAddress.getByName(address);
                DatagramPacket sendPacket = new DatagramPacket(
                        sendData, sendData.length, inetAddress, port);
                SERVER_SOCKET.send(sendPacket);
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
            if (CONNECION_SEMAPHORE.tryAcquire()) {
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
                Server.logDebug("creating P2PUDP" + Server.CENTENA_FORMAT.format(CONNECTION_ID) + "...");
                Connection connection = new Connection();
                connection.start();
                use(connection);
                CONNECTION_COUNT++;
                return connection;
            } else {
                CONNECION_SEMAPHORE.acquire();
                return CONNECTION_POLL.poll();
            }
        } catch (InterruptedException ex) {
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
            Server.logInfo("listening P2P port " + PORT + ".");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
                    SERVER_SOCKET.receive(packet);
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
                } else {
                    connection.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        Server.logDebug("unbinding P2P socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
