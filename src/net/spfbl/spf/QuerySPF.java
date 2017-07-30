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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.User;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.whois.Domain;

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
            super("SPFTCP" + Core.CENTENA_FORMAT.format(CONNECTION_ID++));
            setPriority(Thread.MAX_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
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
                                    LinkedList<User> userResult = new LinkedList<User>();
                                    result = SPF.processPostfixSPF(
                                            ipAddress, client, user, ip, sender, helo, recipient, userResult
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
                                        LinkedList<User> userResult = new LinkedList<User>();
                                        if ((result = White.byTicket(line, userResult)) == null) {
                                            tokenizer = new StringTokenizer(line, " ");
                                            while (tokenizer.hasMoreElements()) {
                                                try {
                                                    String recipient = tokenizer.nextToken();
                                                    boolean added = White.add(client, recipient);
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
                                        }
                                        user = userResult.isEmpty() ? user : userResult.getLast();
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
                                                result = "UNDEFINED USER\n";
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
                                        } else if (Domain.isEmail(query)) {
                                            try {
                                                String mx = Domain.extractHost(query, true);
                                                String domain = "." + Domain.extractDomain(query, false);
                                                if (client == null) {
                                                    result = "ERROR: UNDEFINED CLIENT\n";
                                                } else if (!client.hasEmail()) {
                                                    result = "ERROR: CLIENT WITHOUT EMAIL\n";
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
                                        LinkedList<User> userResult = new LinkedList<User>();
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
//                        if (client == null) {
//                            origin = ipAddress.getHostAddress();
//                        } else if (client.hasEmail()) {
//                            client.addQuery();
//                            origin = ipAddress.getHostAddress()
//                                    + ' ' + client.getDomain()
//                                    + ' ' + client.getEmail();
//                        } else {
//                            client.addQuery();
//                            origin = ipAddress.getHostAddress()
//                                    + ' ' + client.getDomain();
//                        }
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
                        clearSocket();
                        // Oferece a conexão ociosa na última posição da lista.
                        offer(this);
                        CONNECION_SEMAPHORE.release();
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
            if (connection.isTimeout()) {
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
            if (CONNECION_SEMAPHORE.tryAcquire(3, TimeUnit.SECONDS)) {
                // Espera aceitável para conexão de 3s.
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
                Server.logDebug("creating SPFTCP" + Core.CENTENA_FORMAT.format(CONNECTION_ID) + "...");
                Connection connection = new Connection();
                connection.start();
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
            Server.logInfo("listening queries on SPF port " + PORT + ".");
            while (continueListenning()) {
                try {
                    Socket socket = SERVER_SOCKET.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "ERROR: TOO MANY CONNECTIONS\n");
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

    private static void sendMessage(long time,
            Socket socket, String message
            ) throws IOException {
        try {
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(message.getBytes("ISO-8859-1"));
        } finally {
            socket.close();
            Server.logQuery(
                time, "SPFBL",
                socket.getInetAddress(),
                null, message
                );
        }
    }

    @Override
    protected void close() throws Exception {
        while (CONNECTION_COUNT > 0) {
            try {
                Connection connection = poll();
                if (connection == null) {
                    CONNECION_SEMAPHORE.tryAcquire(1, TimeUnit.SECONDS);
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
