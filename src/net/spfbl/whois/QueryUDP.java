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
package net.spfbl.whois;

import net.spfbl.core.Server;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.core.Core;

/**
 * Servidor de consulta em UDP.
 * 
 * Este serviço reponde apenas por um pacote UDP.
 * O cliente deve estar preparado para receber um pacote e finalizar.
 * 
 * Um tamanh máximo de pacote UDP deve ser definido de 
 * acordo com as limitações de roteamento de rede.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QueryUDP extends Server {

    private final int PORT;
    private final int SIZE; // Tamanho máximo da mensagem do pacote UDP de reposta.
    private final DatagramSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta UDP a ser vinculada.
     * @param size o tamanho máximo do pacote UDP.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public QueryUDP(int port, int size) throws SocketException {
        super("ServerWHOISUDP");
        PORT = port;
        SIZE = size - 20 - 8; // Tamanho máximo da mensagem já descontando os cabeçalhos de IP e UDP.
        setPriority(Thread.MIN_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding querie UDP socket on port " + port + "...");
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
            super("WHSUDP" + Core.formatCentena(CONNECTION_ID++));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
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
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("closing " + getName() + "...");
            PACKET = null;
            SEMAPHORE.release();
        }
        
        public DatagramPacket getPacket() {
            if (QueryUDP.this.continueListenning()) {
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
                    byte[] data = packet.getData();
                    String query = new String(data, "ISO-8859-1").trim();
                    String result = QueryUDP.this.processWHOIS(query);
                    // Enviando resposta.
                    InetAddress ipAddress = packet.getAddress();
                    int portDestiny = packet.getPort();
                    send(result, ipAddress, portDestiny);
                    // Log da consulta com o respectivo resultado.
                    Server.logQuery(
                            time,
                            "WHOQR",
                            ipAddress,
                            query, result);
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
     * @param result o resultado que deve ser enviado.
     * @param ip o IP do destino.
     * @param port a porta de resposta do destino.
     * @throws Exception se houver falha no envio.
     */
    private void send(String result, InetAddress ip, int port) throws Exception {
        byte[] sendData = result.getBytes("ISO-8859-1");
        if (sendData.length > SIZE) {
            result = "ERROR: RESULT TOO BIG\n";
            sendData = result.getBytes();
        }
        DatagramPacket sendPacket = new DatagramPacket(
                sendData, sendData.length, ip, port);
        SERVER_SOCKET.send(sendPacket);
    }
    
    /**
     * Pool de conexões ativas.
     */
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<>();
    
    /**
     * Semáforo que controla o pool de conexões.
     */
    private final Semaphore CONNECION_SEMAPHORE = new Semaphore(0);
    
    private synchronized Connection poll() {
        return CONNECTION_POLL.poll();
    }
    
    private synchronized void offer(Connection connection) {
        CONNECTION_POLL.offer(connection);
    }
    
    /**
     * Quantidade total de conexões intanciadas.
     */
    private int CONNECTION_COUNT = 0;
    
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
                }
                return connection;
//            } else if (Core.hasLowMemory()) {
//                return null;
            } else {
            // Cria uma nova conexão se não houver conecxões ociosas.
                // O servidor aumenta a capacidade conforme a demanda.
                Server.logDebug("creating WHSUDP" + Core.formatCentena(CONNECTION_ID) + "...");
                Connection connection = new Connection();
                connection.start();
                CONNECTION_COUNT++;
                return connection;
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
            Server.logInfo("listening queries on UDP port " + PORT + ".");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
                    SERVER_SOCKET.receive(packet);
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            InetAddress ipAddress = packet.getAddress();
                            int portDestiny = packet.getPort();
                            String result = "TOO MANY CONNECTIONS\n";
                            send(result, ipAddress, portDestiny);
                        } else {
                            connection.process(packet, time);
                        }
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie UDP server closed.");
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
                    CONNECION_SEMAPHORE.tryAcquire(500, TimeUnit.MILLISECONDS);
                } else if (connection.isAlive()) {
                    connection.close();
                    last = System.currentTimeMillis();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
            if ((System.currentTimeMillis() - last) > 60000) {
                Server.logError("querie UDP socket close timeout.");
                break;
            }
        }
        Server.logDebug("unbinding querie UDP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
