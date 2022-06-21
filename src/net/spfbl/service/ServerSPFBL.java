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
package net.spfbl.service;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.internet.MimeMessage;
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
import net.spfbl.core.Action;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.Filterable;
import net.spfbl.core.Peer;
import net.spfbl.core.ProcessException;
import static net.spfbl.core.Regex.isValidEmail;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import static net.spfbl.core.User.storeDB;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.FQDN;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import static net.spfbl.service.ServerSMTP.extractContent;
import static net.spfbl.service.ServerSMTP.getQueryEntry;
import static net.spfbl.service.ServerSMTP.loadMimeMessage;
import static net.spfbl.service.ServerSMTP.newQuery;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;

/**
 * Servidor de consulta em SPF.
 *
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class ServerSPFBL extends Server {
    
    private final int PORT;
    private final int PORTS;
    private final String HOSTNAME;
    private final ServerSocket SERVER;
    private SSLServerSocket SERVERS = null;
    
    public ServerSPFBL(int port, int ports, String hostname) throws IOException {
        super("SERVERSPF");
        PORT = port;
        PORTS = ports;
        HOSTNAME = hostname;
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logInfo("binding SPFBL socket on port " + port + "...");
        SERVER = new ServerSocket(port);
        Server.logTrace(getName() + " thread allocation.");
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
                    SNIHostName serverName = new SNIHostName(HOSTNAME);
                    ArrayList<SNIServerName> serverNames = new ArrayList<>(1);
                    serverNames.add(serverName);
                    try {
                        Server.logInfo("binding SPFBLS socket on port " + PORTS + "...");
                        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
                        SERVERS = (SSLServerSocket) socketFactory.createServerSocket(PORTS);
                        SSLParameters params = SERVERS.getSSLParameters();
                        params.setServerNames(serverNames);
                        SERVERS.setSSLParameters(params);
                        Thread sslService = new Thread() {
                            @Override
                            public void run() {
                                startServiceSSL();
                            }
                        };
                        sslService.setName("SERVERSPF");
                        sslService.setPriority(Thread.NORM_PRIORITY);
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
    
    private void startService() {
        try {
            Server.logInfo("listening queries on SPFBL port " + PORT + ".");
            while (Core.isRunning()) {
                try {
                    Socket socket = SERVER.accept();
                    if (Core.isRunning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "TOO MANY CONNECTIONS\n");
                        } else {
                            connection.process(time, socket);
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
            while (Core.isRunning()) {
                try {
                    Socket socket = SERVERS.accept();
                    long time = System.currentTimeMillis();
                    if (Core.isRunning()) {
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "TOO MANY CONNECTIONS\n");
                        } else {
                            connection.process(time, socket);
                        }
                    } else {
                        sendMessage(time, socket, "SYSTEM SHUTDOWN\n");
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
    
    private static void sendMessage(
            long timeKey, Socket socket, String message
    ) throws IOException {
        InetAddress address = socket.getInetAddress();
        String origin = Client.getOrigin(address, "SPFBL");
        try {
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(message.getBytes("ISO-8859-1"));
            socket.close();
        } catch (SSLHandshakeException ex) {
            Server.logDebug(
                    timeKey, ex.getMessage()
            );
        } catch (SSLException ex) {
            Server.logDebug(
                    timeKey, ex.getMessage()
            );
        } finally {
            Server.logQuery(
                    timeKey, "SPFBL", origin,
                    timeKey, message, null
            );
        }
    }
    
    @Override
    protected void close() throws Exception {
        Connection connection;
        while ((connection = last()) != null) {
            connection.interrupt();
        }
        if (SERVERS != null) {
            Server.logInfo("unbinding querie SPFBLS socket on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logInfo("unbinding querie SPFBL socket on port " + PORT + "...");
        SERVER.close();
    }
    
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

    private static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid SPFBL connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }
    
    private static final HashMap<InetAddress,ClientCache> CLIENT_CACHE_MAP = new HashMap<>();
    
    private static class ClientCache {
        
        private final Client client;
        private final long ttl;
        
        private ClientCache(Client client) {
            this.client = client;
            this.ttl = System.currentTimeMillis() + 10 * Server.MINUTE_TIME;
        }
        
        public Client getClient() {
            return client;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > ttl;
        }
    }
    
    private synchronized static void putClientCache(
            InetAddress ipAddress, ClientCache clientCache
    ) {
        if (ipAddress != null && clientCache != null) {
            CLIENT_CACHE_MAP.put(ipAddress, clientCache);
        }
    }
    
    private static ClientCache getClientCache(InetAddress ipAddress) {
        if (ipAddress == null) {
            return null;
        } else {
            return CLIENT_CACHE_MAP.get(ipAddress);
        }
    }
    
    private static Client getClient(InetAddress ipAddress) throws ProcessException {
        if (ipAddress == null) {
            return null;
        } else if (Core.isTestingVersion() && ipAddress.isLoopbackAddress() && Core.isMyHostname("localhost")) {
            return Client.getByCIDR("52.67.41.212/32");
        } else {
            ClientCache clientCache = getClientCache(ipAddress);
            if (clientCache == null || clientCache.isExpired()) {
                Client client = Client.get(ipAddress, "SPFBL");
                clientCache = new ClientCache(client);
                putClientCache(ipAddress, clientCache);
                return client;
            } else {
                return clientCache.getClient();
            }
        }
    }
    
    private class Connection extends Thread {
        
        private long TIME = 0;
        private Socket SOCKET = null;
        private boolean QUERY = false;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        
        public Connection(int id) {
            String name = "SPFTCP" + Core.formatCentena(id);
            Server.logInfo("creating " + name + "...");
            setName(name);
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(name + " thread allocation.");
        }
        
        public void process(long time, Socket socket) {
            TIME = time;
            SOCKET = socket;
            QUERY = false;
            SEMAPHORE.release();
        }
        
        @Override
        public void interrupt() {
            Server.logInfo("closing " + getName() + "...");
            TIME = 0;
            SOCKET = null;
            QUERY = false;
            SEMAPHORE.release();
        }
        
        private void setQuery() {
            TIME = System.currentTimeMillis();
            QUERY = true;
        }
        
        private boolean drop() {
            if (TIME == 0) {
                return false;
            } else if (SOCKET == null) {
                return false;
            } else if (QUERY) {
                return false;
            } else if (SOCKET.isClosed()) {
                return false;
            } else if ((System.currentTimeMillis() - TIME) < Server.MINUTE_TIME) {
                return false;
            } else {
                try {
                    SOCKET.close();
                    return true;
                } catch (IOException ex) {
                    return false;
                }
            }
        }
        
        private long pauseTimeout() {
            long result = TIME;
            TIME = 0;
            return result;
        }
        
        private void setTimeout(long time) {
            this.TIME = time;
        }
        
        public Socket getSocket() {
            try {
                SEMAPHORE.acquire();
                return SOCKET;
            } catch (InterruptedException ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        @Override
        public void run() {
            try {
                Socket socket;
                while ((socket = getSocket()) != null) {
                    try {
                        String type = "SPFBL";
                        String query = null;
                        String result = null;
                        Long timeKey = null;
                        InetAddress ipAddress = socket.getInetAddress();
                        Client client = null;
                        User user = null;
                        try {
                            client = getClient(ipAddress);
                            user = client == null ? null : client.getUser();
                            InputStream inputStream = socket.getInputStream();
                            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
                            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                            String line = bufferedReader.readLine();
                            setQuery();
                            if (line == null) {
                                result = "EMPTY";
                            } else if (line.equals("FIREWALL")) {
                                long time = pauseTimeout();
                                try {
                                    try (OutputStream outputStream = socket.getOutputStream()) {
                                        OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
                                        writer.write("#!/bin/bash\n");
                                        writer.write("# \n");
                                        writer.write("# Firewall for SPFBL client.\n");
                                        writer.write("# Author: Leandro Carlos Rodrigues <leandro@spfbl.net>\n");
                                        if (client != null) {
                                            writer.write("# Client: ");
                                            writer.write(client.getDomain());
                                            writer.write(" ");
                                            writer.write(client.getCIDR());
                                            writer.write("\n");
                                        }
                                        writer.write("# \n\n");
                                        writer.flush();
                                        writer.write("COUNT=$(iptables -S | egrep -c \"^-N SPFBL$\")\n");
                                        writer.flush();
                                        writer.write("if [ \"$COUNT\" -eq \"0\" ]; then\n");
                                        writer.write("    iptables -N SPFBL\n");
                                        writer.write("    # Set static rules.\n");
                                        writer.write("    iptables -I SPFBL -p tcp ");
                                        writer.write("-m connlimit --connlimit-above 8 --connlimit-mask 24 ");
                                        writer.write("-j REJECT --reject-with tcp-reset\n");
                                        for (int mask = 32; mask >= 20; mask--) {
                                            writer.write("    iptables -I SPFBL -p tcp ");
                                            writer.write("-m recent --rcheck --seconds 600 --name SPFBL");
                                            writer.write(Integer.toString(mask));
                                            writer.write(" --mask ");
                                            writer.write(SubnetIPv4.getFirstIPv4("255.255.255.255/" + mask));
                                            writer.write(" -j DROP\n");
                                            writer.flush();
                                        }
                                        writer.write("    iptables -I INPUT -p tcp --dport 25 --syn ");
                                        writer.write("-m state --state NEW -j SPFBL\n");
                                        writer.write("else\n");
                                        writer.write("    # Remove all dynamic rules.\n");
                                        writer.write("    iptables -D SPFBL 15 2> /dev/null\n");
                                        writer.write("    while [ $? -eq 0 ]; do\n");
                                        writer.write("        iptables -D SPFBL 15 2> /dev/null\n");
                                        writer.write("    done\n");
                                        writer.write("fi\n\n");
                                        writer.flush();
                                        writer.write("COUNT=$(ip6tables -S | egrep -c \"^-N SPFBL$\")\n");
                                        writer.flush();
                                        writer.write("if [ \"$COUNT\" -eq \"0\" ]; then\n");
                                        writer.write("    ip6tables -N SPFBL\n");
                                        writer.write("    # Set static rules.\n");
                                        writer.write("    ip6tables -I SPFBL -p tcp ");
                                        writer.write("-m connlimit --connlimit-above 8 --connlimit-mask 48 ");
                                        writer.write("-j REJECT --reject-with tcp-reset\n");
                                        for (int mask = 64; mask >= 48; mask--) {
                                            writer.write("    ip6tables -I SPFBL -p tcp ");
                                            writer.write("-m recent --rcheck --seconds 600 --name SPFBL");
                                            writer.write(Integer.toString(mask));
                                            writer.write(" --mask ");
                                            writer.write(SubnetIPv6.getFirstIPv6("ffff:ffff:ffff:ffff::/" + mask));
                                            writer.write(" -j DROP\n");
                                            writer.flush();
                                        }
                                        writer.write("    ip6tables -I INPUT -p tcp --dport 25 --syn ");
                                        writer.write("-m state --state NEW -j SPFBL\n");
                                        writer.write("else\n");
                                        writer.write("    # Remove all dynamic rules.\n");
                                        writer.write("    ip6tables -D SPFBL 19 2> /dev/null\n");
                                        writer.write("    while [ $? -eq 0 ]; do\n");
                                        writer.write("        ip6tables -D SPFBL 19 2> /dev/null\n");
                                        writer.write("    done\n");
                                        writer.write("fi\n");
                                        writer.flush();
                                        if (client != null && client.hasPermission(Client.Permission.SPFBL)) {
                                            TreeMap<String, Byte> bannedMap = client.getBanMap();
                                            if (!bannedMap.isEmpty()) {
                                                writer.write("\n# Set dynamic rules.\n");
                                                writer.flush();
                                                for (String cidr : bannedMap.keySet()) {
                                                    byte mask = bannedMap.get(cidr);
                                                    if (cidr.contains(":")) {
                                                        writer.write("ip6tables -A SPFBL -p tcp -s ");
                                                    } else {
                                                        writer.write("iptables -A SPFBL -p tcp -s ");
                                                    }
                                                    writer.write(cidr);
                                                    writer.write(" -m recent --set --name SPFBL");
                                                    writer.write(Byte.toString(mask));
                                                    writer.write(" --mask ");
                                                    if (cidr.contains(":")) {
                                                        writer.write(SubnetIPv6.getFirstIPv6("ffff:ffff:ffff:ffff::/" + mask));
                                                    } else {
                                                        writer.write(SubnetIPv4.getFirstIPv4("255.255.255.255/" + mask));
                                                    }
                                                    writer.write(" -j RETURN\n");
                                                    writer.flush();
                                                }
                                            }
                                        }
                                        result = "SENT";
                                    }
                                } finally {
                                    setTimeout(time);
                                }
                            } else if (line.equals("request=smtpd_access_policy")) {
                                // Postfix SMTP APD protocol started.
                                String ip = null;
                                String sender = null;
                                String helo = null;
                                String recipient = null;
                                String instance = null;
                                String state = "";
                                StringBuilder queryBuilder = new StringBuilder();
                                do {
                                    queryBuilder.append(line);
                                    queryBuilder.append("\\n");
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
                                    } else if (line.startsWith("instance=")) {
                                        int index = line.indexOf('=') + 1;
                                        instance = line.substring(index);
                                    } else if (line.startsWith("protocol_state=")) {
                                        int index = line.indexOf('=') + 1;
                                        state = line.substring(index);
                                    }
                                } while ((line = bufferedReader.readLine()).length() > 0);
                                queryBuilder.append("\\n");
                                query = queryBuilder.toString();
                                if (state.equals("RCPT")) {
                                    LinkedList<User> userResult = new LinkedList<>();
                                    TreeSet<Long> timeKeySet = new TreeSet<>();
                                    result = SPF.processPostfixRCPT(
                                            ipAddress, client, user, ip,
                                            sender, helo, recipient,
                                            instance, userResult, timeKeySet
                                    );
                                    user = userResult.isEmpty() ? user : userResult.getLast();
                                    timeKey = timeKeySet.isEmpty() ? null : timeKeySet.first();
                                } else if (state.equals("DATA")) {
                                    result = SPF.processPostfixDATA(
                                            client, user, ip,
                                            sender, helo, instance
                                    );
                                } else if (state.equals("END-OF-MESSAGE")) {
                                    result = SPF.processPostfixDATA(
                                            client, user, ip,
                                            sender, helo, instance
                                    );
                                } else {
                                    result = "action=DUNNO\n\n";
                                }
                                // Enviando resposta.
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            } else if (line.startsWith("REPORT SPAMC/")) {
                                // Spamd protocol started.
                                try {
                                    MimeMessage message = null;
                                    String messageID = null;
                                    String queueID = null;
                                    Integer contentLength = null;
                                    StringBuilder queryBuilder = new StringBuilder();
                                    do {
                                        queryBuilder.append(line);
                                        queryBuilder.append("\\r\\n");
                                        if (line.startsWith("Content-length:")) {
                                            String value = line.substring(15).trim();
                                            contentLength = Core.getInteger(value);
                                        } else if (line.startsWith("User:")) {
                                            String value = line.substring(5).trim();
                                            if (isValidEmail(value)) {
                                                // User email pattern.
                                                user = User.getExact(value);
                                            } else if (value.matches("^[0-9a-zA-Z]{6}-[0-9a-zA-Z]{6}-[0-9a-zA-Z]{2}$")) {
                                                // Exim queue ID pattern.
                                                queueID = value;
                                            }
                                        }
                                        line = bufferedReader.readLine();
                                    } while (line != null && !line.isEmpty());
                                    query = queryBuilder.toString();
                                    if (line == null) {
                                        result = "SPAMD/1.0 76 EX_PROTOCOL\r\n";
                                    } else if (contentLength == null) {
                                        result = "SPAMD/1.0 76 EX_PROTOCOL\r\n";
                                    } else if (contentLength > ServerSMTP.SIZE) {
                                        // Message too big.
                                        result = "SPAMD/1.0 77 EX_NOPERM\r\n";
                                    } else if (contentLength > 0) {
                                        // Reading the message.
                                        ByteArrayOutputStream baOS = new ByteArrayOutputStream(contentLength);
                                        int code;
                                        while ((code = bufferedReader.read()) != -1) {
                                            baOS.write(code);
                                        }
                                        String fqdn = FQDN.getFQDN(ipAddress, false);
                                        if (fqdn == null && client != null) {
                                            fqdn = client.getDomain();
                                        }
                                        byte[] byteArray = baOS.toByteArray();
                                        if (user == null) {
                                            if (messageID == null) {
                                                if (message == null) {
                                                    message = loadMimeMessage(byteArray);
                                                }
                                                messageID = ServerSMTP.extractMessageID(
                                                        message.getHeader("Message-ID")
                                                );
                                            }
                                            user = User.getUserByIdentification(
                                                    messageID, queueID, fqdn
                                            );
                                        }
                                        if (user == null && client != null) {
                                            user = client.getUser();
                                        }
                                        if (queueID != null && fqdn != null) {
                                            // Storing the message.
                                            String information;
                                            if (ServerSMTP.storeIncomingMessage(queueID, fqdn, byteArray)) {
                                                information = "The message " + queueID + "@" + fqdn + " has been stored.";
                                            } else {
                                                information = "The message " + queueID + "@" + fqdn + " stored failed.";
                                            }
                                            byte score = 1;
                                            if (user != null) {
                                                information = user.getEmail() + ": " + information;
                                                Action actionRED = client == null ? Action.FLAG : client.getActionRED();
                                                boolean white = false;
                                                boolean accept = false;
                                                boolean block = false;
                                                boolean reject = false;
                                                boolean hold = false;
                                                boolean flag = false;
                                                TreeSet<String> contentSet = null;
                                                for (long timeKey2 : user.getTimeKeySet()) {
                                                    timeKey = timeKey2;
                                                    Query query2 = user.getQuery(timeKey2);
                                                    if (query2 != null && query2.isQueueID(fqdn, queueID)) {
                                                        if (contentSet == null) {
                                                            if (message == null) {
                                                                message = loadMimeMessage(byteArray);
                                                            }
                                                            boolean trusted = query2.isWhiteKey();
                                                            if ((contentSet = extractContent(message, trusted)) == null) {
                                                                continue;
                                                            }
                                                        }
                                                        Server.logDebug(timeKey2, "LINK " + contentSet);
                                                        String result2 = query2.setLinkSet(timeKey2, contentSet);
                                                        if (query2.isHolding()) {
                                                            hold = true;
                                                        } else if (query2.hasExecutableNotIgnored()) {
                                                            if (actionRED == Action.HOLD) {
                                                                if (!query2.isWhite()) {
                                                                    hold = true;
                                                                }
                                                            }
                                                        }
                                                        if (query2.hasMalwareNotIgnored()) {
                                                            String malware = query2.getMalware();
                                                            String filter = "MALWARE_NOT_IGNORED;" + malware;
                                                            query2.setResult("REJECT");
                                                            query2.setFilter(filter);
                                                            query2.banOrBlockForAdmin(timeKey2, filter);
                                                            query2.banOrBlock(timeKey2, filter);
                                                            query2.addHarmful(timeKey2);
                                                            storeDB(timeKey2, query2);
                                                            Abuse.offer(timeKey2, query2);
                                                            reject = true;
                                                        } else if (query2.hasExecutableBlocked()) {
                                                            String filter = "EXECUTABLE_BLOCKED";
                                                            query2.setResult("REJECT");
                                                            query2.setFilter(filter);
                                                            query2.banOrBlockForAdmin(timeKey2, filter);
                                                            query2.banOrBlock(timeKey2, filter);
                                                            query2.addHarmful(timeKey2);
                                                            storeDB(timeKey2, query2);
                                                            Abuse.offer(timeKey2, query2);
                                                            reject = true;
                                                        } else if ((result2 = query2.getAnyLinkSuspect(false)) == null) {
                                                            accept = true;
                                                        } else if (query2.isWhiteKey()) {
                                                            white = true;
                                                        } else if (query2.isUndesirable()) {
                                                            String filter = "HREF_UNDESIRABLE;" + result2;
                                                            query2.setResult("REJECT");
                                                            query2.setFilter(filter);
                                                            query2.banOrBlock(timeKey2, filter);
                                                            query2.addHarmful(timeKey2);
                                                            storeDB(timeKey2, query2);
                                                            Abuse.offer(timeKey2, query2);
                                                            reject = true;
                                                        } else if (actionRED == Action.REJECT)  {
                                                            String filter = "HREF_SUSPECT;" + result2;
                                                            query2.setResult("REJECT");
                                                            query2.setFilter(filter);
                                                            query2.blockKey(timeKey2, filter);
                                                            query2.addUndesirable(timeKey2);
                                                            storeDB(timeKey2, query2);
                                                            Abuse.offer(timeKey2, query2);
                                                            reject = true;
                                                        } else if (query2.isBlockKey()) {
                                                            block = true;
                                                        } else if (actionRED == Action.HOLD) {
                                                            hold = true;
                                                        } else if (actionRED == Action.FLAG) {
                                                            flag = true;
                                                        }
                                                    }
                                                }
                                                if (white) {
                                                    score = 4;
                                                    information = "WHITE " + contentSet;
                                                } else if (reject) {
                                                    score = -4;
                                                    information = "REJECT " + contentSet;
                                                } else if (block) {
                                                    score = -2;
                                                    information = "BLOCK " + contentSet;
                                                } else if (accept) {
                                                    score = 1;
                                                    information = "ACCEPT " + contentSet;
                                                } else if (hold) {
                                                    score = -1;
                                                    information = "HOLD " + contentSet;
                                                } else if (flag) {
                                                    score = 0;
                                                    information = "FLAG " + contentSet;
                                                }
                                            }
                                            // Return result.
                                            StringBuilder resultBuilder = new StringBuilder();
                                            resultBuilder.append("SPAMD/1.1 0 EX_OK\r\n");
                                            if (score < -1) {
                                                resultBuilder.append("Spam: True ; ");
                                            } else {
                                                resultBuilder.append("Spam: False ; ");
                                            }
                                            resultBuilder.append(-score);
                                            resultBuilder.append(" / 2\r\n");
                                            resultBuilder.append("\r\n");
                                            resultBuilder.append(information);
                                            result = resultBuilder.toString();
                                        } else {
                                            if (message == null) {
                                                message = loadMimeMessage(byteArray);
                                            }
                                            
                                            
                                            
                                            // TODO: DKIM validation.
                                            
                                            
                                            
                                            String[] headerArray = message.getHeader("Received-SPFBL");
                                            if (headerArray == null || headerArray.length == 0) {
                                                Server.logError("Received-SPFBL header not found.");
                                            }
                                            Map.Entry<Long,Query> entry = getQueryEntry(headerArray);
                                            Query userQuery = entry == null ? null : entry.getValue();
                                            user = userQuery == null ? user : userQuery.getUser();
                                            if (user == null) {
                                                // User not indentified.
                                                result = "SPAMD/1.0 67 EX_NOUSER\r\n";
                                            } else {
                                                if (entry == null) {
                                                    entry = newQuery(user, message);
                                                }
                                                if (entry == null) {
                                                    result = "SPAMD/1.0 65 EX_DATAERR\r\n";
                                                } else {
                                                    timeKey = entry.getKey();
                                                    userQuery = entry.getValue();
                                                    User.storeDB2(timeKey, userQuery);
                                                    if (userQuery.hasFQDN()) {
                                                        fqdn = userQuery.getFQDN();
                                                    }
                                                    if (userQuery.hasQueueID()) {
                                                        queueID = userQuery.getQueueID();
                                                    }
                                                    // Storing the message.
                                                    if (ServerSMTP.storeIncomingMessage(
                                                            queueID, fqdn, byteArray
                                                    )) {
                                                        Server.logTrace(
                                                                "The message " + queueID
                                                                + "@" + fqdn + " has been stored."
                                                        );
                                                    }
                                                    TreeSet<String> processedSet = new TreeSet<>();
                                                    ServerSMTP.processContent(
                                                            timeKey, userQuery,
                                                            message, processedSet
                                                    );
                                                    Action actionRED = client == null ? Action.FLAG : client.getActionRED();
                                                    Filterable.Filter filter = userQuery.processFilter();
                                                    boolean white = false;
                                                    boolean accept = false;
                                                    boolean block = false;
                                                    boolean reject = false;
                                                    boolean hold = false;
                                                    boolean flag = false;
                                                    if (filter == null) {
                                                        accept = true;
                                                    } else {
                                                        switch (filter) {
                                                            case IN_REPLY_TO_DESIRABLE: // 100,00%
                                                            case ORIGIN_WHITELISTED: // 99,88%
                                                            case RECIPIENT_BENEFICIAL: // 99,68%
                                                            case ENVELOPE_BENEFICIAL: // 99,90%
                                                                userQuery.whiteKeyForAdmin();
                                                            case IN_REPLY_TO_EXISTENT: // 99,71%
                                                            case ORIGIN_WHITE_KEY_ADMIN: // 99,68%
                                                            case BULK_BENEFICIAL: // 98,41%
                                                            case CIDR_BENEFICIAL: // 99,67%
                                                            case DKIM_BENEFICIAL: // 99,82%
                                                            case FQDN_BENEFICIAL: // 99,58%
                                                            case RECIPIENT_DESIRABLE: // 99,55%
                                                            case SUBJECT_BENEFICIAL: // 99,74%
                                                            case ABUSE_BENEFICIAL: // 99,64%
                                                            case SENDER_MAILER_DEAMON_TRUSTED: // 99,64%
                                                            case SPF_BENEFICIAL: // 99,53%
                                                            case ENVELOPE_DESIRABLE: // 50,00%
                                                                userQuery.whiteKey(timeKey);
                                                            case ORIGIN_WHITE_KEY_USER: // 50,00%
                                                                userQuery.addBeneficial(timeKey);
                                                                userQuery.setResult("WHTE");
                                                                userQuery.setFilter(filter.name());
                                                                white = true;
                                                                break;
                                                            case SPF_DESIRABLE: // 99,65%
                                                            case FQDN_DESIRABLE: // 99,38%
                                                            case BULK_BOUNCE: // 99,91%
                                                            case SENDER_MAILER_DEAMON: // 99,87%
                                                            case SUBJECT_DESIRABLE: // 91,89%
                                                            case FQDN_PROVIDER: // 96,65%
                                                            case DKIM_DESIRABLE: // 95,58%
                                                            case RECIPIENT_POSTMASTER: // 96,40%
                                                            case MALWARE_IGNORED: // 50,00%
                                                            case RECIPIENT_ABUSE: // 96,59%
                                                            case FROM_ESSENTIAL: // 20,09%
                                                            case SENDER_ESSENTIAL: // 90,75%
                                                            case FQDN_ESSENTIAL: // 60,59%
                                                            case RECIPIENT_HACKED: // 50,00%
                                                                userQuery.addAcceptable();
                                                                userQuery.setResult("ACCEPT");
                                                                userQuery.setFilter(filter.name());
                                                                accept = true;
                                                                break;
                                                            case FROM_SPOOFED_SENDER: // 99,88%
                                                            case IP_DYNAMIC: // 95,96%
                                                            case HELO_ANONYMOUS: // 75,00%
                                                            case SENDER_SPOOFING: // 75,00%
                                                                userQuery.ban(timeKey, Core.getAdminEmail(), filter.name());
                                                                userQuery.ban(timeKey, filter.name());
                                                                userQuery.addHarmful(timeKey);
                                                                userQuery.setResult("BLOCK");
                                                                userQuery.setFilter(filter.name());
                                                                Abuse.offer(timeKey, userQuery);
                                                                block = true;
                                                                break;
                                                            case ORIGIN_BANNED: // 50,00%
                                                                userQuery.addHarmful(timeKey);
                                                                userQuery.setResult("BLOCK");
                                                                userQuery.setFilter(filter.name());
                                                                Abuse.offer(timeKey, userQuery);
                                                                block = true;
                                                                break;
                                                            case MALWARE_NOT_IGNORED: // 99,99%
                                                            case FROM_UNROUTABLE: // 99,21%
                                                            case EXECUTABLE_UNDESIRABLE: // 99,60%
                                                            case PHISHING_BLOCKED: // 97,73%
                                                            case FROM_SPOOFED_RECIPIENT: // 99,13%
                                                            case EXECUTABLE_BLOCKED: // 97,96%
                                                                userQuery.banOrBlockForAdmin(timeKey, filter.name());
                                                                reject = true;
                                                            case HREF_UNDESIRABLE: // 99,69%
                                                            case ABUSE_HARMFUL: // 99,94%
                                                            case SUBJECT_HARMFUL: // 99,71%
                                                            case FROM_NOT_SIGNED: // 98,25%
                                                            case FROM_NXDOMAIN: // 50,00%
                                                            case SENDER_NXDOMAIN: // 50,00%
                                                            case ENVELOPE_HARMFUL: // 50,00%
                                                                userQuery.banOrBlock(timeKey, filter.name());
                                                                userQuery.addHarmful(timeKey);
                                                                userQuery.setResult("BLOCK");
                                                                userQuery.setFilter(filter.name());
                                                                Abuse.offer(timeKey, userQuery);
                                                                block = true;
                                                                break;
                                                            case RECIPIENT_SPOOFING: // 85,71%
                                                            case FQDN_SPOOFED: // 87,50%
                                                            case SUBJECT_UNDESIRABLE: // 99,82%
                                                            case ABUSE_BLOCKED: // 99,95%
                                                            case FROM_ABSENT: // 97,00%
                                                            case ORIGIN_BLOCK_KEY_ADMIN: // 99,38%
                                                            case FROM_BLOCKED: // 99,69%
                                                            case FROM_FORGED: // 99,40%
                                                            case RECIPIENT_HARMFUL: // 99,40%
                                                            case ORIGIN_HARMFUL: // 50,00%
                                                            case DKIM_HARMFUL: // 98,84%
                                                            case RECIPIENT_PRIVATE: // 98,31%
                                                            case DOMAIN_INEXISTENT: // 96,97%
                                                                userQuery.blockKey(timeKey, filter.name());
                                                            case ORIGIN_BLOCK_KEY_USER: // 50,00%
                                                                userQuery.addUndesirable(timeKey);
                                                                userQuery.setResult("BLOCK");
                                                                userQuery.setFilter(filter.name());
                                                                Abuse.offer(timeKey, userQuery);
                                                                block = true;
                                                                break;
                                                            case RECIPIENT_RESTRICT: // 66,34%
                                                            case ENVELOPE_BLOCKED: // 82,95%
                                                            case SENDER_RED: // 65,23%
                                                            case SPF_UNDESIRABLE: // 66,64%
                                                            case HREF_SUSPECT: // 47,96%
                                                            case FROM_SUSPECT: // 34,73%
                                                            case ORIGIN_BLOCKED: // 78,70%
                                                            case FQDN_UNDESIRABLE: // 57,38%
                                                            case ENVELOPE_INVALID: // 63,14%
                                                            case SPF_HARMFUL: // 83,24%
                                                            case SPF_FAIL: // 51,29%
                                                            case SPF_SPOOFING: // 50,00%
                                                            case SPF_SOFTFAIL: // 35,38%
                                                            case FQDN_RED: // 66,67%
                                                            case ENVELOPE_UNDESIRABLE: // 50,00%
                                                            case ORIGIN_UNDESIRABLE: // 50,00%
                                                            case CIDR_HARMFUL: // 50,00%
                                                            case FQDN_HARMFUL: // 50,00%
                                                            case SENDER_INVALID: // 50,00%
                                                            case DKIM_UNDESIRABLE: // 50,00%
                                                            case SPF_NXDOMAIN: // 50,00%
                                                            case DOMAIN_EMERGED: // 26,63%
                                                            case FROM_FREEMAIL: // 58,82%
                                                            case EXECUTABLE_NOT_IGNORED: // 67,79%
                                                            case RECIPIENT_UNDESIRABLE: // 50,00%
                                                                if (actionRED == Action.FLAG) {
                                                                    userQuery.setResult("FLAG");
                                                                    flag = true;
                                                                } else if (actionRED == Action.HOLD) {
                                                                    userQuery.setResult("HOLD");
                                                                    hold = true;
                                                                } else {
                                                                    userQuery.addUndesirable(timeKey);
                                                                    userQuery.setResult("REJECT");
                                                                    reject = true;
                                                                }
                                                                userQuery.setFilter(filter.name());
                                                                break;                            
                                                            default:
                                                                Server.logError("filter not defined: " + filter);
                                                                userQuery.addAcceptable();
                                                                userQuery.setResult("ACCEPT");
                                                                userQuery.setFilter(filter.name());
                                                                accept = true;
                                                        }
                                                    }
                                                    storeDB(timeKey, userQuery);
                                                    byte score;
                                                    String information;
                                                    if (white) {
                                                        score = 4;
                                                        information = "WHITE " + filter + " " + processedSet;
                                                    } else if (reject) {
                                                        score = -4;
                                                        information = "REJECT " + filter + " " + processedSet;
                                                    } else if (block) {
                                                        score = -2;
                                                        information = "BLOCK " + filter + " " + processedSet;
                                                    } else if (accept) {
                                                        score = 1;
                                                        information = "ACCEPT " + filter + " " + processedSet;
                                                    } else if (hold) {
                                                        score = -1;
                                                        information = "HOLD " + filter + " " + processedSet;
                                                    } else if (flag) {
                                                        score = 0;
                                                        information = "FLAG " + filter + " " + processedSet;
                                                    } else {
                                                        score = 1;
                                                        information = "ACCEPT " + filter + " " + processedSet;
                                                    }
                                                    // Return result.
                                                    StringBuilder resultBuilder = new StringBuilder();
                                                    resultBuilder.append("SPAMD/1.1 0 EX_OK\r\n");
                                                    if (score < -1) {
                                                        resultBuilder.append("Spam: True ; ");
                                                    } else {
                                                        resultBuilder.append("Spam: False ; ");
                                                    }
                                                    resultBuilder.append(-score);
                                                    resultBuilder.append(" / 2\r\n");
                                                    resultBuilder.append("\r\n");
                                                    resultBuilder.append(information);
                                                    result = resultBuilder.toString();
                                                }
                                            }
                                        }
                                    } else {
                                        result = "SPAMD/1.0 64 EX_USAGE\r\n";
                                    }
                                } catch (IOException ex) {
                                    Server.logError(ex);
                                    result = "SPAMD/1.0 74 EX_IOERR\r\n";
                                }
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            } else {
                                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                                if (tokenizer.hasMoreTokens()) {
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
                                            String token2 = tokenizer.nextToken();
                                            try {
                                                Map.Entry<Long,Query> queryEntry = User.getQueryEntrySafe(token2);
                                                if (queryEntry == null) {
                                                    if (Core.isValidURL(token2)) {
                                                        token2 = Core.getSignatureURL(token2);
                                                    }
                                                    if (Core.isExecutableSignature(token2) || Core.isSignatureURL(token2)) {
                                                        if (client == null) {
                                                            result = "NOT ADMIN\n";
                                                        } else if (!client.isAdministrator() && !client.isAdministratorEmail()) {
                                                            result = "NOT ADMIN\n";
                                                        } else if (Block.addExact(token2)) {
                                                            Peer.sendBlockToAll(token2);
                                                            result = "ADDED\n";
                                                        } else {
                                                            result = "ALREADY EXISTS\n";
                                                        }
                                                    } else {
                                                        boolean added = Block.add(client, token2);
                                                        if (result == null) {
                                                            result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                        } else {
                                                            result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                        }
                                                    }
                                                } else {
                                                    timeKey = queryEntry.getKey();
                                                    Query userQuery = queryEntry.getValue();
                                                    if (userQuery.hasRecipient()) {
                                                        if (userQuery.blockForRecipient(timeKey)) {
                                                            String userEmail = userQuery.getUserEmail();
                                                            String blockKey = userQuery.getBlockKey();
                                                            String recipient = userQuery.getRecipient();
                                                            result = "ADDED " + userEmail + ":" + blockKey + ">" + recipient + "\n";
                                                        } else {
                                                            result = "ALREADY EXISTS\n";
                                                        }
                                                    } else {
                                                        if (userQuery.blockKey(timeKey, "USER_COMPLAIN")) {
                                                            String userEmail = userQuery.getUserEmail();
                                                            String blockKey = userQuery.getBlockKey();
                                                            result = "ADDED " + userEmail + ":" + blockKey + "\n";
                                                        } else {
                                                            result = "ALREADY EXISTS\n";
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
                                                String token2 = tokenizer.nextToken();
                                                if (Core.isExecutableSignature(token2) || Core.isSignatureURL(token2)) {
                                                    if (client == null) {
                                                        result = "NOT ADMIN\n";
                                                    } else if (!client.isAdministrator() && !client.isAdministratorEmail()) {
                                                        result = "NOT ADMIN\n";
                                                    } else if (Block.dropExact(token2)) {
                                                        result = "DROPPED\n";
                                                    } else {
                                                        result = "NOT FOUND\n";
                                                    }
                                                } else {
                                                    boolean droped = Block.drop(client, token2);
                                                    if (result == null) {
                                                        result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                                                    } else {
                                                        result += (droped ? "DROPPED" : "NOT FOUND") + "\n";
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
                                                String recipient = tokenizer.nextToken().toLowerCase();
                                                if (recipient.startsWith("postmaster@")) {
                                                    if (result == null) {
                                                        result = "RESERVED ADDRESS\n";
                                                    } else {
                                                        result += "RESERVED ADDRESS\n";
                                                    }
                                                } else {
                                                    boolean added = Trap.addInexistent(client, recipient);
                                                    if (result == null) {
                                                        result = (added ? "ADDED" : "ALREADY EXISTS") + "\n";
                                                    } else {
                                                        result += (added ? "ADDED" : "ALREADY EXISTS") + "\n";
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
                                        tokenizer = new StringTokenizer(line, " ");
                                        while (tokenizer.hasMoreElements()) {
                                            try {
                                                String whiteToken = tokenizer.nextToken();
                                                Map.Entry<Long,Query> queryEntry = User.getQueryEntrySafe(whiteToken);
                                                if (queryEntry == null) {
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
                                                } else {
                                                    timeKey = queryEntry.getKey();
                                                    Query userQuery = queryEntry.getValue();
                                                    if (userQuery.hasRecipient()) {
                                                        if (userQuery.whiteKeyForRecipient(timeKey)) {
                                                            String userEmail = userQuery.getUserEmail();
                                                            String whiteKey = userQuery.getWhiteKey();
                                                            String recipient = userQuery.getRecipient();
                                                            result = "ADDED " + userEmail + ":" + whiteKey + ">" + recipient + "\n";
                                                        } else {
                                                            result = "ALREADY EXISTS\n";
                                                        }
                                                    } else {
                                                        if (userQuery.whiteKey(timeKey)) {
                                                            String userEmail = userQuery.getUserEmail();
                                                            String whiteKey = userQuery.getWhiteKey();
                                                            result = "ADDED " + userEmail + ":" + whiteKey + "\n";
                                                        } else {
                                                            result = "ALREADY EXISTS\n";
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
                                            index = messageID.indexOf('<');
                                            if (index >= 0) {
                                                messageID = messageID.substring(index + 1);
                                                index = messageID.indexOf('>');
                                                if (index > 0) {
                                                    messageID = messageID.substring(0, index);
                                                }
                                            }
                                            if (user == null) {
                                                result = User.whiteAllByMessageID(messageID) + '\n';
                                            } else {
                                                result = user.whiteByMessageID(messageID) + '\n';
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
                                                    boolean freemail = Provider.containsExact(mx);
                                                    if (freemail) {
                                                        token = query;
                                                    } else {
                                                        token = mx;
                                                    }
                                                    if (White.add(client, token)) {
                                                        result = "ADDED " + client.getEmail() + ":" + token + ";PASS\n";
                                                    } else {
                                                        result = "ALREADY EXISTS " + client.getEmail() + ":" + token + ";PASS\n";
                                                    }
                                                    if (!freemail) {
                                                        if (White.add(client, token + ";BULK")) {
                                                            result += "ADDED " + client.getEmail() + ":" + token + ";BULK\n";
                                                        } else {
                                                            result += "ALREADY EXISTS " + client.getEmail() + ":" + token + ";BULK\n";
                                                        }
                                                        if (White.add(client, token + ";" + domain.substring(1))) {
                                                            result += "ADDED " + client.getEmail() + ":" + token + ";" + domain.substring(1) + "\n";
                                                        } else {
                                                            result += "ALREADY EXISTS " + client.getEmail() + ":" + token + ";" + domain.substring(1) + "\n";
                                                        }
                                                    }
                                                }
                                            } catch (ProcessException ex) {
                                                if (ex.isErrorMessage("RESERVED")) {
                                                    result = "RESERVED\n";
                                                } else {
                                                    result = ex.getErrorMessage() + "\n";
                                                }
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
                                        TreeSet<Long> timeKeySet = new TreeSet<>();
                                        result = SPF.processSPF(ipAddress, client, user, query, userResult, timeKeySet);
                                        user = userResult.isEmpty() ? user : userResult.getLast();
                                        timeKey = timeKeySet.isEmpty() ? null : timeKeySet.first();
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
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                                // Enviando resposta.
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            }
                        } catch (SSLException ex) {
                            // Conexão SSL não reconhecida.
                            Server.logInfo("unrecognized SSL message.");
                            result = "UNRECOGNIZED\n";
                        } catch (SocketException ex) {
                            // Conexão interrompida.
                            Server.logInfo("interrupted " + getName() + " connection.");
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
                                    TIME, type,
                                    origin,
                                    timeKey,
                                    (query == null ? "DISCONNECTED" : query),
                                    result
                            );
                            dropConnections();
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    } finally {
                        offerConnection(this);
                    }
                }
            } finally {
                Server.logTrace(getName() + " thread closed.");
            }
        }
    }
    
    private final LinkedList<Connection> CONNECTION_QUEUE = new LinkedList<>();
    private final LinkedList<Connection> CONNECTION_LIST = new LinkedList<>();
    
    private synchronized Connection poll() {
        return CONNECTION_QUEUE.poll();
    }
    
    private synchronized Connection last() {
        return CONNECTION_LIST.pollLast();
    }
    
    private synchronized Connection create() {
        Connection connection = null;
        int id = CONNECTION_LIST.size();
        if (id < CONNECTION_LIMIT) {
            connection = new Connection(id+1);
            connection.start();
            CONNECTION_LIST.add(connection);
        }
        return connection;
    }
    
    private synchronized boolean offerConnection(Connection connection) {
        if (connection == null) {
            return false;
        } else {
            if (CONNECTION_LIST.isEmpty()) {
                CONNECTION_QUEUE.offer(connection);
                ServerSPFBL.this.notify();
                return true;
            } else if (CONNECTION_QUEUE.size() < 2) {
                CONNECTION_QUEUE.offer(connection);
                ServerSPFBL.this.notify();
                return true;
            } else if (connection == CONNECTION_LIST.getLast()) {
                connection.interrupt();
                CONNECTION_LIST.removeLast();
                return false;
            } else {
                CONNECTION_QUEUE.offer(connection);
                ServerSPFBL.this.notify();
                return true;
            }
        }
    }
    
    private Connection pollConnection() {
        Connection connection = poll();
        if (connection == null) {
            try {
                synchronized (ServerSPFBL.this) {
                    ServerSPFBL.this.wait(100);
                }
            } catch (InterruptedException ex) {
                // Do nothing.
            }
            if ((connection = poll()) == null) {
                connection = create();
            }
        }
        return connection;
    }
    
    private long LAST = System.currentTimeMillis();
    
    private synchronized void dropConnections() {
        if ((System.currentTimeMillis() - LAST) > 10000) {
            LAST = System.currentTimeMillis();
            for (Connection connection : CONNECTION_LIST) {
                connection.drop();
            }
        }
    }
}
