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
package br.com.allchemistry.whois;

import br.com.allchemistry.core.Server;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;

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
        // Criando conexões.
        Server.logDebug("Binding querie UDP socket on port " + port + "...");
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
        private final LinkedList<DatagramPacket> PACKET_LIST = new LinkedList<DatagramPacket>();
        
        /**
         * Semáforo que controla o pool de pacotes.
         */
        private final Semaphore PACKET_SEMAPHORE = new Semaphore(0);
        
        public Connection() {
            super("WHOISUDP" + (CONNECTION_COUNT+1));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
        }
        
        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private synchronized void process(DatagramPacket packet) {
            PACKET_LIST.offer(packet);
            if (isAlive()) {
                // Libera o próximo processamento.
                PACKET_SEMAPHORE.release();
            } else {
                // Inicia a thread pela primmeira vez.
                start();
            }
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("Closing " + getName() + "...");
            PACKET_SEMAPHORE.release();
        }
        
        /**
         * Aguarda nova chamada.
         */
        private void waitCall() {
            try {
                PACKET_SEMAPHORE.acquire();
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            while (!PACKET_LIST.isEmpty()) {
                try {
                    long time = System.currentTimeMillis();
                    DatagramPacket packet = PACKET_LIST.poll();
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
//                    // Atualiza registros quase expirando durante a consulta.
//                    Server.tryBackugroundRefresh();
//                    // Armazena todos os registros atualizados durante a consulta.
//                    Server.storeCache();
                    // Oferece a conexão ociosa na última posição da lista.
                    CONNECTION_POLL.offer(this);
                    CONNECION_SEMAPHORE.release();
                    // Aguarda nova chamada.
                    waitCall();
                }
            }
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
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<Connection>();
    
    /**
     * Semáforo que controla o pool de conexões.
     */
    private final Semaphore CONNECION_SEMAPHORE = new Semaphore(0);
    
    /**
     * Quantidade total de conexões intanciadas.
     */
    private int CONNECTION_COUNT = 0;
    
    /**
     * Coleta uma conexão ociosa ou inicia uma nova.
     * @return uma conexão ociosa ou nova se não houver ociosa.
     */
    private Connection pollConnection() {
        if (CONNECION_SEMAPHORE.tryAcquire()) {
            return CONNECTION_POLL.poll();
        } else {
            // Cria uma nova conexão se não houver conecxões ociosas.
            // O servidor aumenta a capacidade conforme a demanda.
            Server.logDebug("Creating WHOISUDP" + (CONNECTION_COUNT+1) + "...");
            Connection connection = new Connection();
            CONNECTION_COUNT++;
            return connection;
        }
    }
    
    /**
     * Inicialização do serviço.
     */
    @Override
    public synchronized void run() {
        try {
            Server.logDebug("Listening queries on UDP port " + PORT + "...");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
                    SERVER_SOCKET.receive(packet);
                    Connection connection = pollConnection();
                    if (connection == null) {
                        InetAddress ipAddress = packet.getAddress();
                        int portDestiny = packet.getPort();
                        String result = "ERROR: TOO MANY CONNECTIONS\n";
                        send(result, ipAddress, portDestiny);
                        System.out.print(result);
                    } else {
                        connection.process(packet);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logDebug("Querie UDP server closed.");
        }
    }
    
    /**
     * Fecha todas as conexões e finaliza o servidor UDP.
     * @throws Exception se houver falha em algum fechamento.
     */
    @Override
    protected void close() throws Exception {
        while (CONNECTION_COUNT > 0) {
            CONNECION_SEMAPHORE.acquire();
            Connection connection = CONNECTION_POLL.poll();
            connection.close();
            CONNECTION_COUNT--;
        }
        Server.logDebug("Unbinding querie UDP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
