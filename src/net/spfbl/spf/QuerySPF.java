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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.NormalDistribution;
import net.spfbl.core.User;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.whois.Domain;
import net.spfbl.whois.SubnetIPv6;

/**
 * Servidor de consulta em SPF.
 *
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class QuerySPF extends Server {

    private final int PORT;
    private final int PORTS;
    private final String HOSTNAME;
    private final ServerSocket SERVER;
    private SSLServerSocket SERVERS = null;

    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta SPFBL a ser vinculada.
     * @param ports a porta SPFBLS a ser vinculada.
     * @param hostname hostname do serviço SPFBLS.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public QuerySPF(int port, int ports, String hostname) throws IOException {
        super("SERVERSPF");
        PORT = port;
        PORTS = ports;
        HOSTNAME = hostname;
        setPriority(Thread.MAX_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding SPFBL socket on port " + port + "...");
        SERVER = new ServerSocket(port);
        Server.logTrace(getName() + " thread allocation.");
    }

    private int CONNECTION_ID = 0;
    private long CONNECTION_TIME = 0;

    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {

        /**
         * O poll de sockets de consulta a serem processados.
         */
        private Socket SOCKET = null;
        private int ID = 0;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        private long time = 0;

        public Connection() {
            String name = getNextName();
            Server.logDebug("creating " + name + "...");
            setName(name);
            setPriority(Thread.MAX_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        private synchronized String getNextName() {
            CONNECTION_TIME = System.currentTimeMillis();
            return "SPFTCP" + Core.formatCentena(ID = ++CONNECTION_ID);
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
         * Processa um socket de consulta.
         * @param socket o socket de consulta a ser processado.
         */
        private void process(Socket socket, long time) {
            this.SOCKET = socket;
            this.time = time;
            SEMAPHORE.release();
        }

        private boolean isTimeout() {
            if (time == 0) {
                return false;
            } else {
                int interval = (int) (System.currentTimeMillis() - time) / 1000;
                return interval > 60;
            }
        }

        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("closing " + getName() + "...");
            SOCKET = null;
            SEMAPHORE.release();
        }

        @Override
        public void interrupt() {
            try {
                SOCKET.close();
            } catch (NullPointerException ex) {
                // a conexão foi fechada antes da interrupção.
            } catch (IOException ex) {
                Server.logError(ex);
            }
        }

        public Socket getSocket() {
            if (QuerySPF.this.continueListenning()) {
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

        public void clearSocket() {
            time = 0;
            SOCKET = null;
        }
        
        private final NormalDistribution frequency = new NormalDistribution(100);
        private long last = 0;
        
        private boolean isIdle() {
            return frequency.getMinimum() > 200.f;
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
            try {
                Socket socket;
                while ((socket = getSocket()) != null) {
                    try {
                        String type = "SPFBL";
                        String query = null;
                        String result = null;
                        InetAddress ipAddress = socket.getInetAddress();
                        Client client = null;
                        User user = null;
                        try {
                            client = Client.get(ipAddress, "SPFBL");
                            user = client == null ? null : client.getUser();
                            InputStream inputStream = socket.getInputStream();
                            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
                            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                            String line = bufferedReader.readLine();
                            if (line == null) {
                                result = "EMPTY";
                            } else {
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
                                    Server.logTrace(query);
                                    query += "\\n";
                                    LinkedList<User> userResult = new LinkedList<>();
                                    result = SPF.processPostfixSPF(
                                            ipAddress, client, user, ip, 
                                            sender, helo, recipient, userResult
                                    );
                                    user = userResult.isEmpty() ? user : userResult.getLast();
                                } else {
                                    Server.logTrace(line);
                                    StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                    String token = tokenizer.nextToken();
                                    Integer otpCode = Core.getInteger(token);
                                    if (otpCode != null) {
                                        int index = line.indexOf(token) + token.length() + 1;
                                        line = line.substring(index).trim();
                                        token = tokenizer.nextToken();
                                        if (user == null) {
                                            result = "TOTP UNDEFINED USER\n";
                                        } else if (!user.isValidOTP(otpCode)) {
                                            result = "TOTP INVALID CODE\n";
                                        }
                                    }
                                    if (result != null) {
                                        // Houve erro de OTP.
                                    } else if (token.equals("VERSION")) {
                                        query = token;
                                        if (client == null) {
                                            result = Core.getAplication() + "\nClient: " + ipAddress.getHostAddress() + "\n";
                                        } else {
                                            result = Core.getAplication() + "\n" + client + "\n";
                                        }
                                    } else if (line.startsWith("BLOCK ADD ")) {
                                        query = line.substring(6).trim();
                                        type = "BLOCK";
                                        // Mecanismo de adição bloqueio de remetente.
                                        line = line.substring(10);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            String sender = tokenizer.nextToken();
                                            try {
                                                boolean added = Block.add(client, sender);
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("BLOCK DROP ")) {
                                        query = line.substring(6).trim();
                                        type = "BLOCK";
                                        // Mecanismo de remoção de bloqueio de remetente.
                                        line = line.substring(11);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String sender = tokenizer.nextToken();
                                                boolean droped = Block.drop(client, sender);
                                                if (result == null) {
                                                    result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                                                } else {
                                                    result += (droped ? "DROPPED" : "NOT FOUND") + "\n";
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.equals("BLOCK SHOW ALL")) {
                                        query = line.substring(6).trim();
                                        type = "BLOCK";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String sender : Block.getAll(client, user)) {
                                            builder.append(sender);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else if (line.equals("BLOCK SHOW")) {
                                        query = line.substring(6).trim();
                                        type = "BLOCK";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String sender : Block.get(client, user)) {
                                            builder.append(sender);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else if (line.startsWith("BLOCK FIND ")) {
                                        query = line.substring(6).trim();
                                        type = "BLOCK";
                                        // Mecanismo de remoção de bloqueio de remetente.
                                        line = line.substring(11);
                                        tokenizer = new StringTokenizer(line, " ");
                                        if (tokenizer.hasMoreTokens()) {
                                            token = tokenizer.nextToken();
                                            String ticket = null;
                                            String userEmail = SPF.getClientURLSafe(token);
                                            if (userEmail == null) {
                                                userEmail = client == null ? null : client.getEmail();
                                            } else if (tokenizer.hasMoreTokens()) {
                                                ticket = token;
                                                token = tokenizer.nextToken();
                                            } else {
                                                ticket = token;
                                                token = null;
                                            }
                                            user = User.get(userEmail);
                                            do {
                                                String block = Block.find(userEmail, token, true, true, true, false);
                                                if (block == null) {
                                                    result = "NONE\n";
                                                } else if (ticket == null) {
                                                    result = block + "\n";
                                                    break;
                                                } else {
                                                    try {
                                                        SPF.addComplainURLSafe(userEmail, ticket, "REJECT");
                                                        result = block + "\n";
                                                        break;
                                                    } catch (ProcessException ex) {
                                                        result = "INVALID TICKET\n";
                                                        break;
                                                    }
                                                }
                                            } while (tokenizer.hasMoreElements() && (token = tokenizer.nextToken()) != null);
                                        }
                                        if (result == null) {
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("TRAP ADD ")) {
                                        query = line.substring(5).trim();
                                        type = "STRAP";
                                        // Mecanismo de adição de spamtrap.
                                        line = line.substring(9);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String recipient = tokenizer.nextToken();
                                                boolean added = Trap.addTrap(client, recipient);
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("TRAP DROP ")) {
                                        query = line.substring(5).trim();
                                        type = "STRAP";
                                        // Mecanismo de remoção de spamtrap.
                                        line = line.substring(10);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String recipient = tokenizer.nextToken();
                                                boolean droped = Trap.drop(client, recipient);
                                                if (result == null) {
                                                    result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                                                } else {
                                                    result += (droped ? "DROPPED" : "NOT FOUND") + "\n";
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.equals("TRAP SHOW")) {
                                        query = line.substring(5).trim();
                                        type = "STRAP";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String recipient : Trap.getTrapSet(client)) {
                                            builder.append(recipient);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else if (line.startsWith("INEXISTENT ADD ")) {
                                        query = line.substring(11).trim();
                                        type = "INXST";
                                        // Mecanismo de adição de spamtrap.
                                        line = line.substring(15);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String recipient = tokenizer.nextToken();
                                                boolean added = Trap.addInexistent(client, recipient);
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("INEXISTENT DROP ")) {
                                        query = line.substring(11).trim();
                                        type = "INXST";
                                        // Mecanismo de remoção de spamtrap.
                                        line = line.substring(16);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String recipient = tokenizer.nextToken();
                                                boolean droped = Trap.drop(user, client, recipient);
                                                if (result == null) {
                                                    result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                                                } else {
                                                    result += (droped ? "DROPPED" : "NOT FOUND") + "\n";
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.equals("INEXISTENT SHOW")) {
                                        query = line.substring(11).trim();
                                        type = "INXST";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String recipient : Trap.getInexistentSet(client)) {
                                            builder.append(recipient);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else if (line.startsWith("INEXISTENT IS ")) {
                                        query = line.substring(11).trim();
                                        type = "INXST";
                                        String address = line.substring(14);
                                        if (Trap.containsAnything(client, user, address)) {
                                            result = "TRUE\n";
                                        } else {
                                            result = "FALSE\n";
                                        }
                                    } else if (line.startsWith("NOREPLY IS ")) {
                                        query = line.substring(8).trim();
                                        type = "NRPLY";
                                        String address = line.substring(11);
                                        if (NoReply.contains(address, true)) {
                                            result = "TRUE\n";
                                        } else if (Trap.containsAnything(client, user, address)) {
                                            result = "TRUE\n";
                                        } else {
                                            result = "FALSE\n";
                                        }
                                    } else if (line.startsWith("WHITE ADD ")) {
                                        query = line.substring(6).trim();
                                        type = "WHITE";
                                        // Mecanismo de adição de whitelist.
                                        line = line.substring(10);
                                        LinkedList<User> userResult = new LinkedList<>();
                                        result = White.byTicket(line, userResult);
                                        user = userResult.isEmpty() ? user : userResult.getLast();
                                        if (result == null) {
                                            tokenizer = new StringTokenizer(line, " ");
                                            while (tokenizer.hasMoreElements()) {
                                                try {
                                                    String whiteToken = tokenizer.nextToken();
                                                    int index = whiteToken.indexOf(':');
                                                    if (index == -1) {
                                                        boolean added = White.add(client, whiteToken);
                                                        if (result == null) {
                                                            result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                        } else {
                                                            result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                        }
                                                    } else {
                                                        String userEmail = whiteToken.substring(0, index);
                                                        whiteToken = whiteToken.substring(index + 1);
                                                        if (client == null || !client.isEmail(userEmail)) {
                                                            if (result == null) {
                                                                result = "INVALID USER\n";
                                                            } else {
                                                                result = "INVALID USER\n";
                                                            }
                                                        } else {
                                                            boolean added = White.add(client, whiteToken);
                                                            if (result == null) {
                                                                result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                            } else {
                                                                result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                            }
                                                        }
                                                    }
                                                } catch (ProcessException ex) {
                                                    if (result == null) {
                                                        result = ex.getMessage() + "\n";
                                                    } else {
                                                        result += ex.getMessage() + "\n";
                                                    }
                                                }
                                            }
                                        }
                                        if (result == null) {
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("WHITE DROP ")) {
                                        query = line.substring(6).trim();
                                        type = "WHITE";
                                        // Mecanismo de remoção de whitelist.
                                        line = line.substring(11);
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String recipient = tokenizer.nextToken();
                                                boolean droped = White.drop(client, recipient);
                                                if (result == null) {
                                                    result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                                                } else {
                                                    result += (droped ? "DROPPED" : "NOT FOUND") + "\n";
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
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.startsWith("WHITE SENDER ")) {
                                        query = line.substring(13).trim();
                                        type = "WHITE";
                                        if (query.startsWith("In-Reply-To:")) {
                                            int index = query.indexOf(':') + 1;
                                            String messageID = query.substring(index);
                                            if (user == null) {
                                                result = User.whiteAllByMessageID(messageID) + '\n';
                                            } else {
                                                result = "INVALID ID\n";
                                                index = messageID.indexOf('<');
                                                if (index >= 0) {
                                                    messageID = messageID.substring(index + 1);
                                                    index = messageID.indexOf('>');
                                                    if (index > 0) {
                                                        messageID = messageID.substring(0, index);
                                                        result = user.whiteByMessageID(messageID) + '\n';
                                                    }
                                                }
                                            }
                                        } else if (Domain.isMailFrom(query)) {
                                            try {
                                                String mx = Domain.extractHost(query, true);
                                                String domain = "." + Domain.extractDomain(query, false);
                                                if (client == null) {
                                                    result = "UNDEFINED CLIENT\n";
                                                } else if (!client.hasEmail()) {
                                                    result = "CLIENT WITHOUT EMAIL\n";
                                                } else if (Block.containsExact(client.getEmail() + ":" + query)) {
                                                    result = "BLOCKED AS " + query + "\n";
                                                } else if (Block.containsExact(client.getEmail() + ":" + mx)) {
                                                    result = "BLOCKED AS " + mx + "\n";
                                                } else if (Block.containsExact(client.getEmail() + ":" + domain)) {
                                                    result = "BLOCKED AS " + domain + "\n";
                                                } else {
                                                    if (Provider.containsExact(mx)) {
                                                        token = query;
                                                    } else {
                                                        token = mx;
                                                    }
                                                    if (White.add(client, token)) {
                                                        result = "ADDED " + token + ";PASS\n";
                                                    } else {
                                                        result = "ALREADY EXISTS " + token + ";PASS\n";
                                                    }
                                                }
                                            } catch (ProcessException ex) {
                                                result = ex.getErrorMessage() + "\n";
                                            }
                                        } else {
                                            result = "INVALID COMMAND\n";
                                        }
                                    } else if (line.equals("WHITE SHOW ALL")) {
                                        query = line.substring(6).trim();
                                        type = "WHITE";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String recipient : White.getAll(client, null)) {
                                            builder.append(recipient);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else if (line.equals("WHITE SHOW")) {
                                        query = line.substring(6).trim();
                                        type = "WHITE";
                                        // Mecanismo de visualização de bloqueios de remetentes.
                                        StringBuilder builder = new StringBuilder();
                                        for (String recipient : White.get(client, null)) {
                                            builder.append(recipient);
                                            builder.append('\n');
                                        }
                                        result = builder.toString();
                                        if (result.length() == 0) {
                                            result = "EMPTY\n";
                                        }
                                    } else {
                                        query = line.trim();
                                        LinkedList<User> userResult = new LinkedList<>();
                                        result = SPF.processSPF(ipAddress, client, user, query, userResult);
                                        user = userResult.isEmpty() ? user : userResult.getLast();
                                        if (query.startsWith("HAM ")) {
                                            type = "SPFHM";
                                        } else if (query.startsWith("SPAM ")) {
                                            type = "SPFSP";
                                        } else if (query.startsWith("LINK ")) {
                                            type = "LINKF";
                                        } else if (query.startsWith("MALWARE ")) {
                                            type = "SPFSP";
                                        } else if (query.startsWith("CHECK ")) {
                                            type = "SPFCK";
                                        }
                                    }
                                }
                                // Enviando resposta.
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(result.getBytes("UTF-8"));
                            }
                        } catch (SSLException ex) {
                            // Conexão SSL não reconhecida.
                            Server.logDebug("unrecognized SSL message.");
                            result = "UNRECOGNIZED\n";
                        } catch (SocketException ex) {
                            // Conexão interrompida.
                            Server.logDebug("interrupted " + getName() + " connection.");
                            result = "INTERRUPTED\n";
                        } finally {
                            // Fecha conexão logo após resposta.
                            socket.close();
                            // Log da consulta com o respectivo resultado.
                            String origin = ipAddress.getHostAddress();
                            if (client != null) {
                                client.addQuery();
                                origin += ' ' + client.getDomain();
                            }
                            if (user != null) {
                                origin += ' ' + user.getEmail();
                            } else if (client != null && client.hasEmail()) {
                                origin += ' ' + client.getEmail();
                            }
                            Server.logQuery(
                                    time, type,
                                    origin,
                                    (query == null ? "DISCONNECTED" : query),
                                    result
                            );
                            addQuery();
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    } finally {
                        clearSocket();
                        // Oferece a conexão ociosa na última posição da lista.
                        offer(this);
                        CONNECION_SEMAPHORE.release();
                        notifyConnection();
                    }
                }
            } finally {
                CONNECTION_COUNT--;
                Server.logTrace(getName() + " thread closed.");
            }
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
            if (connection.isTimeout()) {
                offerUsing(connection);
                connection.interrupt();
            } else {
                offerUsing(connection);
            }
        }
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
            wait(200);
            return poll();
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return null;
        }
    }

    /**
     * Coleta uma conexão ociosa.
     * @return uma conexão ociosa ou nulo se exceder o tempo.
     */
    private Connection pollConnection() {
        try {
            if (CONNECION_SEMAPHORE.tryAcquire(2, TimeUnit.SECONDS)) {
                // Espera aceitável para conexão de 2s.
                Connection connection = pollAndCloseIfLast();
                if (connection == null) {
                    connection = waitConnection();
                    if (connection == null) {
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
            Server.logInfo("listening queries on SPFBL port " + PORT + ".");
            CONNECION_SEMAPHORE = new Semaphore(CONNECTION_LIMIT);
            while (continueListenning()) {
                try {
                    Socket socket = SERVER.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "TOO MANY CONNECTIONS\n");
                        } else {
                            try {
                                connection.process(socket, time);
                            } catch (IllegalThreadStateException ex) {
                                // Houve problema na liberação do processo.
                                Server.logError(ex);
                                sendMessage(time, socket, "ERROR: FATAL\n");
                                offer(connection);
                            }
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
            Server.logInfo("querie SPFBL server closed.");
        }
    }
    
    private void startServiceSSL() {
        try {
            Server.logInfo("listening queries on SPFBLS port " + PORTS + ".");
            while (continueListenning()) {
                try {
                    Socket socket = SERVERS.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "TOO MANY CONNECTIONS\n");
                        } else {
                            try {
                                connection.process(socket, time);
                            } catch (IllegalThreadStateException ex) {
                                // Houve problema na liberação do processo.
                                Server.logError(ex);
                                sendMessage(time, socket, "ERROR: FATAL\n");
                                offer(connection);
                            }
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
            Server.logInfo("querie SPFBLS server closed.");
        }
    }

    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        if (PORTS == 0) {
            startService();
        } else if (HOSTNAME == null) {
            Server.logInfo("SPFBLS socket was not binded because no hostname defined.");
        } else {
            Core.waitStartHTTP();
            KeyStore keyStore = Core.loadKeyStore(HOSTNAME);
            if (keyStore == null) {
                Server.logError("SPFBLS socket was not binded because " + HOSTNAME + " keystore not exists.");
            } else {
                try {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(keyStore, HOSTNAME.toCharArray());
                    KeyManager[] km = kmf.getKeyManagers();
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(keyStore);
                    TrustManager[] tm = tmf.getTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(km, tm, null);
                    ///
                    SNIHostName serverName = new SNIHostName(HOSTNAME);
                    ArrayList<SNIServerName> serverNames = new ArrayList<>(1);
                    serverNames.add(serverName);
                    ///
                    try {
                        Server.logDebug("binding SPFBLS socket on port " + PORTS + "...");
                        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
                        SERVERS = (SSLServerSocket) socketFactory.createServerSocket(PORTS);
                        ///
                        SSLParameters params = SERVERS.getSSLParameters();
                        params.setServerNames(serverNames);
                        SERVERS.setSSLParameters(params);
                        ///
                        Thread sslService = new Thread() {
                            @Override
                            public void run() {
                                setName("SERVERSPF");
                                startServiceSSL();
                            }
                        };
                        sslService.start();
                    } catch (BindException ex) {
                        Server.logError("SPFBLS socket was not binded because TCP port " + PORTS + " is already in use.");
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            startService();
        }
    }

    private static void sendMessage(long time,
            Socket socket, String message
            ) throws IOException {
        InetAddress address = socket.getInetAddress();
        String origin = Client.getOrigin(address, "SPFBL");
        try {
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(message.getBytes("ISO-8859-1"));
            socket.close();
        } catch (SSLHandshakeException ex) {
            Server.logDebug(ex.getMessage());
        } finally {
            Server.logQuery(
                time, "SPFBL",
                origin,
                message, null
                );
        }
    }

    @Override
    protected void close() throws Exception {
        long last = System.currentTimeMillis();
        while (CONNECTION_COUNT > 0) {
            try {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.tryAcquire(2, TimeUnit.SECONDS);
                } else {
                    connection.close();
                    last = System.currentTimeMillis();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
            if ((System.currentTimeMillis() - last) > 60000) {
                Server.logError("querie SPFBL socket close timeout.");
                break;
            }
        }
        if (SERVERS != null) {
            Server.logDebug("unbinding querie SPFBLS socket on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logDebug("unbinding querie SPFBL socket on port " + PORT + "...");
        SERVER.close();
    }
}
