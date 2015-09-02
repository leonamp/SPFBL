/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.spf;

import br.com.allchemistry.core.ProcessException;
import br.com.allchemistry.core.Server;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;

/**
 * Servidor de recebimento de bloqueio por P2P.
 * 
 * Este serviço ouve todas as informações de bloqueio da rede P2P.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
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
        private final LinkedList<DatagramPacket> PACKET_LIST = new LinkedList<DatagramPacket>();
        
        /**
         * Semáforo que controla o pool de pacotes.
         */
        private final Semaphore PACKET_SEMAPHORE = new Semaphore(0);
        
        public Connection() {
            super("PEERUDP" + (CONNECTION_COUNT+1));
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
                    InetAddress ipAddress = packet.getAddress();
                    byte[] data = packet.getData();
                    String token = new String(data, "ISO-8859-1").trim();
                    String result;
                    try {
                        if (SPF.addBlock(token)) {
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
                    // Armazena registros de bloqueio.
                    SPF.storeBlock();
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
    public void send(String token, InetAddress address, int port) throws ProcessException {
        try {
            byte[] sendData = token.getBytes("ISO-8859-1");
            if (sendData.length > SIZE) {
                throw new ProcessException("ERROR: TOKEN TOO BIG");
            } else {
                DatagramPacket sendPacket = new DatagramPacket(
                        sendData, sendData.length, address, port);
                SERVER_SOCKET.send(sendPacket);
            }
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
            Server.logDebug("Creating PEERUDP" + (CONNECTION_COUNT+1) + "...");
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
            Server.logDebug("Listening peers on UDP port " + PORT + "...");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
                    SERVER_SOCKET.receive(packet);
                    Connection connection = pollConnection();
                    if (connection == null) {
                        Server.logDebug("Too many peer conections.");
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
            Server.logDebug("Querie peer UDP server closed.");
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
        Server.logDebug("Unbinding peer UDP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
