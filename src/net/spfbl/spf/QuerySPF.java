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
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Status;
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
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.core.Client;

/**
 * Servidor de consulta em SPF.
 * 
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QuerySPF extends Server {

    private final int PORT;
    private final ServerSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta SPF a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public QuerySPF(int port) throws IOException {
        super("ServerSPF");
        PORT = port;
        setPriority(Thread.MAX_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding SPF socket on port " + port + "...");
        SERVER_SOCKET = new ServerSocket(port);
    }
    
    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {
        
        /**
         * O poll de sockets de consulta a serem processados.
         */
        private Socket SOCKET = null;
        
        private long time = 0;
        
//        /**
//         * Semáforo que controla o pool de sockets.
//         */
//        private final Semaphore SOCKET_SEMAPHORE = new Semaphore(0);
        
        public Connection() {
            super("SPFTCP" + (CONNECTION_COUNT + 1));
            setPriority(Thread.MAX_PRIORITY);
        }
        
        /**
         * Processa um socket de consulta.
         * @param socket o socket de consulta a ser processado.
         */
        private synchronized void process(Socket socket, long time) {
            this.SOCKET = socket;
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
            SOCKET = null;
            notify();
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public synchronized void run() {
            while (continueListenning() && SOCKET != null) {
                try {
                    String type = "SPFBL";
                    String query = null;
                    String result = null;
                    try {
//                        String client = Server.getLogClient(SOCKET.getInetAddress());
                        InetAddress ipAddress = SOCKET.getInetAddress();
                        String client = Client.getIdentification(ipAddress);
                        InputStream inputStream = SOCKET.getInputStream();
                        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                        String line = bufferedReader.readLine();
                        if (line != null) {
                            if (line.equals("request=smtpd_access_policy")) {
                                // Entrada padrão do Postfix.
                                // Extrair os atributos necessários.
                                String ip = null;
                                String sender = null;
                                String helo = null;
                                String recipient = null;
                                query = "";
                                do {
                                    query += line + "\\n";
                                    if (line.startsWith("helo_name=")) {
                                        int index = line.indexOf('=') + 1;
                                        helo = line.substring(index);
                                    } else if (line.startsWith("sender=")) {
                                        int index = line.indexOf('=') + 1;
                                        sender = line.substring(index);
                                    } else if (line.startsWith("client_address=")) {
                                        int index = line.indexOf('=') + 1;
                                        ip = line.substring(index);
                                    } else if (line.startsWith("recipient=")) {
                                        int index = line.indexOf('=') + 1;
                                        recipient = line.substring(index);
                                    }
                                } while ((line = bufferedReader.readLine()).length() > 0);
                                query += "\\n";
                                result = SPF.processPostfixSPF(
                                        client, ip, sender, helo, recipient
                                        );
                            } else if (line.startsWith("BLOCK ADD ")) {
                                query = line.substring(6).trim();
                                type = "BLOCK";
                                // Mecanismo de adição bloqueio de remetente.
                                line = line.substring(10);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String sender = tokenizer.nextToken();
                                        boolean added = SPF.addBlock(client, sender);
                                        if (result == null) {
                                            result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        } else {
                                            result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.startsWith("BLOCK DROP ")) {
                                query = line.substring(6).trim();
                                type = "BLOCK";
                                // Mecanismo de remoção de bloqueio de remetente.
                                line = line.substring(11);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String sender = tokenizer.nextToken();
                                        boolean droped = SPF.dropBlock(client, sender);
                                        if (result == null) {
                                            result = (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        } else {
                                            result += (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.equals("BLOCK SHOW ALL")) {
                                query = line.substring(6).trim();
                                type = "BLOCK";
                                // Mecanismo de visualização de bloqueios de remetentes.
                                for (String sender : SPF.getAllBlockSet(client)) {
                                    if (result == null) {
                                        result = sender + "\n";
                                    } else {
                                        result += sender + "\n";
                                    }
                                }
                                if (result == null) {
                                    result = "EMPTY\n";
                                }
                            } else if (line.equals("BLOCK SHOW")) {
                                query = line.substring(6).trim();
                                type = "BLOCK";
                                // Mecanismo de visualização de bloqueios de remetentes.
                                for (String sender : SPF.getBlockSet(client)) {
                                    if (result == null) {
                                        result = sender + "\n";
                                    } else {
                                        result += sender + "\n";
                                    }
                                }
                                if (result == null) {
                                    result = "EMPTY\n";
                                }
                            } else if (line.startsWith("TRAP ADD ")) {
                                query = line.substring(5).trim();
                                type = "STRAP";
                                // Mecanismo de adição de spamtrap.
                                line = line.substring(9);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String recipient = tokenizer.nextToken();
                                        boolean added = SPF.addTrap(client, recipient);
                                        if (result == null) {
                                            result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        } else {
                                            result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.startsWith("TRAP DROP ")) {
                                query = line.substring(5).trim();
                                type = "STRAP";
                                // Mecanismo de remoção de spamtrap.
                                line = line.substring(10);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String recipient = tokenizer.nextToken();
                                        boolean droped = SPF.dropTrap(client, recipient);
                                        if (result == null) {
                                            result = (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        } else {
                                            result += (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.equals("TRAP SHOW")) {
                                query = line.substring(5).trim();
                                type = "STRAP";
                                // Mecanismo de visualização de bloqueios de remetentes.
                                for (String recipient : SPF.getTrapSet(client)) {
                                    if (result == null) {
                                        result = recipient + "\n";
                                    } else {
                                        result += recipient + "\n";
                                    }
                                }
                                if (result == null) {
                                    result = "EMPTY\n";
                                }
                            } else if (line.startsWith("WHITE ADD ")) {
                                query = line.substring(6).trim();
                                type = "WHITE";
                                // Mecanismo de adição de whitelist.
                                line = line.substring(10);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String recipient = tokenizer.nextToken();
                                        boolean added = SPF.addWhite(client, recipient);
                                        if (result == null) {
                                            result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        } else {
                                            result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.startsWith("WHITE DROP ")) {
                                query = line.substring(6).trim();
                                type = "WHITE";
                                // Mecanismo de remoção de whitelist.
                                line = line.substring(11);
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                while (tokenizer.hasMoreElements()) {
                                    try {
                                        String recipient = tokenizer.nextToken();
                                        boolean droped = SPF.dropWhite(client, recipient);
                                        if (result == null) {
                                            result = (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        } else {
                                            result += (droped ? "DROPED" : "NOT FOUND") + "\n";
                                        }
                                    } catch (ProcessException ex) {
                                        if (result == null) {
                                            result = ex.getMessage() + "\n";
                                        } else {
                                            result += ex.getMessage() + "\n";
                                        }
                                    }
                                }
                                if (result == null) {
                                    result = "ERROR: COMMAND";
                                }
                            } else if (line.equals("WHITE SHOW ALL")) {
                                query = line.substring(6).trim();
                                type = "WHITE";
                                // Mecanismo de visualização de bloqueios de remetentes.
                                for (String recipient : SPF.getAllWhiteSet(client)) {
                                    if (result == null) {
                                        result = recipient + "\n";
                                    } else {
                                        result += recipient + "\n";
                                    }
                                }
                                if (result == null) {
                                    result = "EMPTY\n";
                                }
                            } else if (line.equals("WHITE SHOW")) {
                                query = line.substring(6).trim();
                                type = "WHITE";
                                // Mecanismo de visualização de bloqueios de remetentes.
                                for (String recipient : SPF.getWhiteSet(client)) {
                                    if (result == null) {
                                        result = recipient + "\n";
                                    } else {
                                        result += recipient + "\n";
                                    }
                                }
                                if (result == null) {
                                    result = "EMPTY\n";
                                }
                            } else if (line.equals("REPUTATION")) {
                                // Comando para verificar a reputação dos tokens.
                                query = line.trim();
                                type = "REPTQ";
                                StringBuilder stringBuilder = new StringBuilder();
                                TreeMap<String,Distribution> distributionMap = SPF.getDistributionMap();
                                if (distributionMap.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String tokenReputation : distributionMap.keySet()) {
                                        Distribution distribution = distributionMap.get(tokenReputation);
                                        float probability = distribution.getMinSpamProbability();
                                        if (probability > 0.0f && distribution.hasFrequency()) {
                                            Status status = distribution.getStatus(tokenReputation);
                                            String frequency = distribution.getFrequencyLiteral();
                                            stringBuilder.append(tokenReputation);
                                            stringBuilder.append(' ');
                                            stringBuilder.append(frequency);
                                            stringBuilder.append(' ');
                                            stringBuilder.append(status);
                                            stringBuilder.append(' ');
                                            stringBuilder.append(Server.DECIMAL_FORMAT.format(probability));
                                            stringBuilder.append('\n');
                                        }
                                    }
                                    result = stringBuilder.toString();
                                }
                            } else {
                                query = line.trim();
                                result = SPF.processSPF(client, query);
                                if (query.startsWith("HAM ")) {
                                    type = "SPFHM";
                                } else if (query.startsWith("SPAM ")) {
                                    type = "SPFSP";
                                } else if (query.startsWith("CHECK ")) {
                                    type = "SPFCK";
                                }
                            }
                            // Enviando resposta.
                            OutputStream outputStream = SOCKET.getOutputStream();
                            outputStream.write(result.getBytes("UTF-8"));
                        }
                    } finally {
                        // Fecha conexão logo após resposta.
                        SOCKET.close();
                        InetAddress address = SOCKET.getInetAddress();
                        SOCKET = null;
                        // Log da consulta com o respectivo resultado.
                        String origin;
                        Client client = Client.get(address);
                        if (client == null) {
                            origin = address.getHostAddress();
                        } else if (client.hasEmail()) {
                            client.addQuery();
                            origin = address.getHostAddress()
                                    + ' ' + client.getDomain()
                                    + ' ' + client.getEmail();
                        } else {
                            client.addQuery();
                            origin = address.getHostAddress()
                                    + ' ' + client.getDomain();
                        }
                        Server.logQuery(
                                time, type,
                                origin,
                                query == null ? "DISCONNECTED" : query,
                                result
                                );
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    try {
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
    
    private static final int CONNECTION_LIMIT = 10;
    
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
            // Espera aceitável para conexão de 10ms.
            if (CONNECION_SEMAPHORE.tryAcquire(10, TimeUnit.MILLISECONDS)) {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.release();
                }
                return connection;
            } else if (CONNECTION_COUNT < CONNECTION_LIMIT) {
                // Cria uma nova conexão se não houver conexões ociosas.
                // O servidor aumenta a capacidade conforme a demanda.
                Server.logDebug("creating SPFTCP" + (CONNECTION_COUNT + 1) + "...");
                Connection connection = new Connection();
                CONNECTION_COUNT++;
                return connection;
            } else {
                // Se a quantidade de conexões atingir o limite,
                // Aguardar a próxima liberação de conexão 
                // independente de quanto tempo levar.
                CONNECION_SEMAPHORE.acquire();
                return CONNECTION_POLL.poll();
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
            Server.logDebug("listening queries on SPF port " + PORT + "...");
            while (continueListenning()) {
                try {
                    Socket socket = SERVER_SOCKET.accept();
                    long time = System.currentTimeMillis();
                    Connection connection = pollConnection();
                    if (connection == null) {
                        String result = "ERROR: TOO MANY CONNECTIONS\n";
                        try {
                            OutputStream outputStream = socket.getOutputStream();
                            outputStream.write(result.getBytes("ISO-8859-1"));
                        } finally {
                            socket.close();
                            Server.logQuery(
                                time, "SPFBL",
                                socket.getInetAddress(),
                                null, result
                                );
                        }
                    } else {
                        connection.process(socket, time);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logDebug("querie SPFBL server closed.");
        }
    }
    
    @Override
    protected void close() throws Exception {
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
        Server.logDebug("unbinding querie SPF socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
