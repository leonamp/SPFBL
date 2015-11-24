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
import net.spfbl.core.Core;

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
        super("SERVERSPF");
        PORT = port;
        setPriority(Thread.MAX_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding SPF socket on port " + port + "...");
        SERVER_SOCKET = new ServerSocket(port);
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
        
        private long time = 0;
       
        
        public Connection() {
            super("SPFTCP" + Server.CENTENA_FORMAT.format(CONNECTION_ID++));
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
        
        private boolean isDead() {
            if (time == 0) {
                return false;
            } else {
                int interval = (int) (System.currentTimeMillis() - time) / 1000;
                return interval > 600;
            }
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
         * Método perigoso porém necessário para encontrar falhas.
         */
        public synchronized void kill() {
            CONNECTION_COUNT--;
            super.stop();
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private synchronized void close() {
            Server.logDebug("closing " + getName() + "...");
            SOCKET = null;
            notify();
        }
        
        @Override
        public synchronized void interrupt() {
            try {
                SOCKET.close();
            } catch (NullPointerException ex) {
                // a conexão foi fechada antes da interrupção.
            } catch (IOException ex) {
                Server.logError(ex);
            }
        }
        
        public synchronized void waitCall() throws InterruptedException {
            wait();
        }
        
        public synchronized Socket getSocket() {
            return SOCKET;
        }
        
        public synchronized void clearSocket() throws IOException {
            SOCKET = null;
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            Socket socket;
            while (continueListenning() && (socket = getSocket()) != null) {
                try {
                    String type = "SPFBL";
                    String query = null;
                    String result = null;
                    try {
//                        String client = Server.getLogClient(SOCKET.getInetAddress());
                        InetAddress ipAddress = socket.getInetAddress();
                        String client = Client.getIdentification(ipAddress);
                        InputStream inputStream = socket.getInputStream();
                        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                        String line = bufferedReader.readLine();
                        if (line != null) {
                            if (line.equals("VERSION")) {
                                result = Core.getAplication() + "\n";
                            } else if (line.equals("request=smtpd_access_policy")) {
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
                                        float probability = distribution.getSpamProbability(tokenReputation);
                                        Status status = distribution.getStatus(tokenReputation);
                                        stringBuilder.append(tokenReputation);
                                        stringBuilder.append(' ');
                                        stringBuilder.append(status);
                                        stringBuilder.append(' ');
                                        stringBuilder.append(Server.DECIMAL_FORMAT.format(probability));
                                        stringBuilder.append('\n');
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
                            OutputStream outputStream = socket.getOutputStream();
                            outputStream.write(result.getBytes("UTF-8"));
                        }
                    } catch (SocketException ex) {
                        // Conexão interrompida.
                        Server.logDebug("interrupted " + getName() + " connection.");
                        result = "INTERRUPTED\n";
                    } finally {
                        // Fecha conexão logo após resposta.
                        socket.close();
                        InetAddress address = socket.getInetAddress();
                        clearSocket();
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
                        time = 0;
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    try {
                        // Oferece a conexão ociosa na última posição da lista.
                        offer(this);
                        CONNECION_SEMAPHORE.release();
                        // Aguarda nova chamada.
                        waitCall();
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
                Server.logError("invalid SPFBL connection limit '" + limit + "'.");
            }
        }
    }
    
    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid SPFBL connection limit '" + limit + "'.");
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
            if (connection.isDead()) {
                Server.logDebug("connection " + connection.getName() + " is deadlocked.");
                // Temporário até encontrar a deadlock.
                connection.kill();
            } else if (connection.isTimeout()) {
                offerUsing(connection);
                connection.interrupt();
            } else {
                offerUsing(connection);
            }
        }
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
                } else {
                    use(connection);
                }
                return connection;
            } else if (CONNECTION_COUNT < CONNECTION_LIMIT) {
                // Cria uma nova conexão se não houver conexões ociosas.
                // O servidor aumenta a capacidade conforme a demanda.
                Server.logDebug("creating SPFTCP" + Server.CENTENA_FORMAT.format(CONNECTION_ID) + "...");
                Connection connection = new Connection();
                use(connection);
                CONNECTION_COUNT++;
                return connection;
            } else {
                // Se a quantidade de conexões atingir o limite,
                // Aguardar a próxima liberação de conexão 
                // independente de quanto tempo levar.
                CONNECION_SEMAPHORE.acquire();
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.release();
                } else {
                    use(connection);
                }
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
                } else {
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
