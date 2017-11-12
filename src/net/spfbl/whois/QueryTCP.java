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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.core.Core;

/**
 * Servidor de consulta em TCP.
 * 
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QueryTCP extends Server {

    private final int PORT;
    private final ServerSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta TCP a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public QueryTCP(int port) throws IOException {
        super("WHOISTCPP");
        PORT = port;
        setPriority(Thread.MIN_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding TCP socket on port " + port + "...");
        SERVER_SOCKET = new ServerSocket(port);
        Server.logTrace(getName() + " thread allocation.");
    }
    
    private int CONNECTION_ID = 1;
    
    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {
        
        /**
         * O poll de sockets de consulta a serem processados.
         */
        private Socket SOCKET = null;
        
        private final Semaphore SEMAPHORE = new Semaphore(0);
        
        private long time = 0;
        
        
        public Connection() {
            super("WHSTCP" + Core.formatCentena(CONNECTION_ID++));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        /**
         * Processa um socket de consulta.
         * @param socket o socket de consulta a ser processado.
         */
        private void process(Socket socket, long time) {
            this.SOCKET = socket;
            this.time = time;
            this.SEMAPHORE.release();
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("closing " + getName() + "...");
            SOCKET = null;
            SEMAPHORE.release();
        }
        
        public Socket getSocket() {
            if (QueryTCP.this.continueListenning()) {
                try {
                    SEMAPHORE.acquire();
                    return SOCKET;
                } catch (InterruptedException ex) {
                    return null;
                }
            } else {
                return null;
            }
        }
        
        public void clearPacket() {
            time = 0;
            SOCKET = null;
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            Socket socket;
            while ((socket = getSocket()) != null) {
                try {
                    String query = null;
                    String result = "";
                    try {
                        InputStream inputStream = socket.getInputStream();
                        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                        query = bufferedReader.readLine();
                        if (query == null) {
                            result = "INVALID QUERY\n";
                        } else if (query.equals("DOMAIN SHOW")) {
                            TreeSet<String> domainSet = Domain.getDomainNameSet();
                            if (domainSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String domain : domainSet) {
                                    if (result == null || result.length() == 0) {
                                        result = domain + "\n";
                                    } else {
                                        result += domain + "\n";
                                    }
                                }
                            }
                        } else {
                            result = QueryTCP.this.processWHOIS(query);
                        }
                        // Enviando resposta.
                        OutputStream outputStream = socket.getOutputStream();
                        outputStream.write(result.getBytes("ISO-8859-1"));
                    } finally {
                        // Fecha conexão logo após resposta.
                        socket.close();
                        InetAddress address = SOCKET.getInetAddress();
                        // Log da consulta com o respectivo resultado.
                        Server.logQuery(
                                time,
                                "WHOQR",
                                address,
                                query, result);
                    }
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
    
    private synchronized Connection poll() {
        return CONNECTION_POLL.poll();
    }
    
    private synchronized void offer(Connection connection) {
        CONNECTION_POLL.offer(connection);
    }
    
    /**
     * Coleta uma conexão ociosa.
     * @return uma conexão ociosa ou nulo se exceder o tempo.
     */
    private Connection pollConnection() {
        try {
            if (!continueListenning()) {
                return null;
            } else if (CONNECION_SEMAPHORE.tryAcquire(1, TimeUnit.SECONDS)) {
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
                Server.logDebug("creating WHSTCP" + Core.formatCentena(CONNECTION_ID) + "...");
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
            Server.logInfo("listening queries on TCP port " + PORT + ".");
            while (continueListenning()) {
                try {
                    Socket socket = SERVER_SOCKET.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            String result = "TOO MANY CONNECTIONS\n";
                            try {
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            } finally {
                                socket.close();
                            }
                        } else {
                            connection.process(socket, time);
                        }
                    } else {
                        socket.close();
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie TCP server closed.");
        }
    }
    
    @Override
    protected void close() throws Exception {
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
                Server.logError("querie TCP socket close timeout.");
                break;
            }
        }
        Server.logDebug("unbinding querie TCP socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
