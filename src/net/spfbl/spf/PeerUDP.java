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
package net.spfbl.spf;

import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;

/**
 * Servidor de recebimento de bloqueio por P2P.
 * 
 * Este serviço ouve todas as informações de bloqueio da rede P2P.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class PeerUDP extends Server {

    private final int PORT;
    private final int SIZE; // Tamanho máximo da mensagem do pacote UDP de reposta.
    private final DatagramSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta UDP a ser vinculada.
     * @param size o tamanho máximo do pacote UDP.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public PeerUDP(int port, int size) throws SocketException {
        super("ServerPEERUDP");
        PORT = port;
        SIZE = size - 20 - 8; // Tamanho máximo da mensagem já descontando os cabeçalhos de IP e UDP.
        setPriority(Thread.MIN_PRIORITY);
        // Criando conexões.
        Server.logDebug("Binding peer UDP socket on port " + port + "...");
        SERVER_SOCKET = new DatagramSocket(port);
    }
    
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
            super("PEERUDP" + (CONNECTION_COUNT+1));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
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
            Server.logDebug("Closing " + getName() + "...");
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
                try {
                    InetAddress ipAddress = PACKET.getAddress();
                    byte[] data = PACKET.getData();
                    String token = new String(data, "ISO-8859-1").trim();
                    String result;
                    try {
                        if (!isValid(token)) {
                            result = "INVALID";
                        } else if (SPF.isIgnore(token)) {
                            result = "IGNORED";
                        } else if (SPF.addBlock(token)) {
                            result = "ADDED";
                        } else {
                            result = "ALREADY EXISTS";
                        }
                    } catch (ProcessException ex) {
                        result = ex.getMessage();
                    }
                    // Log do bloqueio com o respectivo resultado.
                    Server.logQuery(
                            time,
                            "PEERB",
                            ipAddress,
                            token.replace("\n", "\\n"),
                            result
                            );
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
    
    private static boolean isValid(String token) {
        if (token == null || token.length() == 0) {
            return false;
        } else if (Subnet.isValidIP(token)) {
            return false;
        } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
            return true;
        } else if (token.contains("@") && Domain.isEmail(token)) {
            return true;
        } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Envia um pacote do resultado em UDP para o destino.
     * @param result o resultado que deve ser enviado.
     * @param ip o IP do destino.
     * @param port a porta de resposta do destino.
     * @throws Exception se houver falha no envio.
     */
    public void send(String token, String address, int port) throws ProcessException {
        try {
            byte[] sendData = token.getBytes("ISO-8859-1");
            if (sendData.length > SIZE) {
                throw new ProcessException("ERROR: TOKEN TOO BIG");
            } else {
                InetAddress inetAddress = InetAddress.getByName(address);
                DatagramPacket sendPacket = new DatagramPacket(
                        sendData, sendData.length, inetAddress, port);
                SERVER_SOCKET.send(sendPacket);
            }
        } catch (UnknownHostException ex) {
            throw new ProcessException("ERROR: UNKNOWN HOST", ex);
        } catch (IOException ex) {
            throw new ProcessException("ERROR: PEER UNREACHABLE", ex);
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
    
    private static final int CONNECTION_LIMIT = 10;
    
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
        try {
            if (CONNECION_SEMAPHORE.tryAcquire(10, TimeUnit.MILLISECONDS)) {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.release();
                }
                return connection;
            } else if (CONNECTION_COUNT < CONNECTION_LIMIT) {
                // Cria uma nova conexão se não houver conecxões ociosas.
                // O servidor aumenta a capacidade conforme a demanda.
                Server.logDebug("Creating PEERUDP" + (CONNECTION_COUNT + 1) + "...");
                Connection connection = new Connection();
                CONNECTION_COUNT++;
                return connection;
            } else {
                return null;
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
            Server.logDebug("Listening peers on UDP port " + PORT + "...");
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
                        connection.process(packet, time);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logDebug("Querie peer UDP server closed.");
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
        Server.logDebug("Unbinding peer UDP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
