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
package net.spfbl.core;

import net.spfbl.dns.Zone;
import net.spfbl.spf.SPF;
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
import java.net.URL;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.PatternSyntaxException;
import javax.mail.internet.InternetAddress;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import net.spfbl.core.Client.Permission;
import net.spfbl.core.Peer.Receive;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidCIDRv4;
import static net.spfbl.core.Regex.isValidCIDRv6;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.User.Query;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.Dictionary;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.FQDN;
import net.spfbl.data.Licence;
import net.spfbl.data.Recipient;
import net.spfbl.data.Reputation;
import net.spfbl.data.Reputation.Flag;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.service.ServerDNS;
import net.spfbl.service.ServerHTTP;
import net.spfbl.service.ServerSMTP;
import net.spfbl.spf.SPF.Binomial;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Status;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;

/**
 * Servidor de commandos em TCP.
 * 
 * Este serviço responde o commando e finaliza a conexão logo em seguida.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class AdministrationTCP extends Server {

    private final int PORT;
    private final int PORTS;
    private final String HOSTNAME;
    private final ServerSocket SERVER;
    private SSLServerSocket SERVERS = null;
    
    /**
     * Configuração e intanciamento do servidor para comandos.
     * @param port a porta TCP a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public AdministrationTCP(int port, int ports, String hostname) throws IOException {
        super("SERVERADM");
        PORT = port;
        PORTS = ports;
        HOSTNAME = hostname;
        setPriority(Thread.MAX_PRIORITY);
        // Criando conexões.
        Server.logInfo("binding administration TCP socket on port " + port + "...");
        SERVER = new ServerSocket(port);
    }
    
    private void startService() {
        try {
            Server.logInfo("listening ADMIN on port " + PORT + ".");
            String command = null;
            String result = null;
            Socket socket;
            long time;
            while (continueListenning() && (socket = SERVER.accept()) != null) {
                time = System.currentTimeMillis();
                InetAddress ipAddress = socket.getInetAddress();
                try {
                    InputStream inputStream = socket.getInputStream();
                    InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    command = bufferedReader.readLine();
                    result = null;
                    if (command == null) {
                        command = "DISCONNECTED";
                    } else {
                        Server.logTrace(command);
                        Client client = Client.get(ipAddress);
                        if (result == null) {
                            OutputStream outputStream = socket.getOutputStream();
                            result = processCommand(ipAddress, client, command, outputStream);
                            if (result == null) {
                                result = "SENT\n";
                            } else {
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            }
                        }
                    }
                } catch (SocketException ex) {
                    // Conexão interrompida.
                    Server.logInfo("interrupted " + getName() + " connection.");
                    result = "INTERRUPTED\n";
                } finally {
                    // Fecha conexão logo após resposta.
                    socket.close();
                    InetAddress address = ipAddress;
                    // Log da consulta com o respectivo resultado.
                    Server.logAdministration(
                            time,
                            address,
                            command == null ? "DISCONNECTED" : command,
                            result
                            );
                    // Verificar se houve falha no fechamento dos processos.
                    if (result != null && result.equals("ERROR: SHUTDOWN\n")) {
                        // Fechar forçadamente o programa.
                        Server.logInfo("system killed.");
                        System.exit(1);
                    }
                }
            }
        } catch (SocketException ex) {
            // Conexão fechada externamente pelo método close().
            Server.logInfo("listening stoped.");
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            synchronized (AdministrationTCP.this) {
                AdministrationTCP.this.notify();
            }
            Server.logInfo("server closed.");
            System.exit(0);
        }
    }
    
    private void startServiceSSL() {
        try {
            Server.logInfo("listening ADMINS on port " + PORTS + ".");
            String command = null;
            String result = null;
            Socket socket;
            long time;
            while (continueListenning() && (socket = SERVERS.accept()) != null) {
                time = System.currentTimeMillis();
                InetAddress ipAddress = socket.getInetAddress();
                try {
                    InputStream inputStream = socket.getInputStream();
                    InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    command = bufferedReader.readLine();
                    result = null;
                    if (command == null) {
                        command = "DISCONNECTED";
                    } else {
                        Server.logTrace(command);
                        Client client = Client.get(ipAddress);
                        if (result == null) {
                            OutputStream outputStream = socket.getOutputStream();
                            result = processCommand(ipAddress, client, command, outputStream);
                            if (result == null) {
                                result = "SENT\n";
                            } else {
                                outputStream.write(result.getBytes("ISO-8859-1"));
                            }
                        }
                    }
                } catch (SocketException ex) {
                    // Conexão interrompida.
                    Server.logInfo("interrupted " + getName() + " connection.");
                    result = "INTERRUPTED\n";
                } finally {
                    // Fecha conexão logo após resposta.
                    socket.close();
                    InetAddress address = ipAddress;
                    // Log da consulta com o respectivo resultado.
                    Server.logAdministration(
                            time,
                            address,
                            command == null ? "DISCONNECTED" : command,
                            result
                            );
                    // Verificar se houve falha no fechamento dos processos.
                    if (result != null && result.equals("ERROR: SHUTDOWN\n")) {
                        // Fechar forçadamente o programa.
                        Server.logInfo("system killed.");
                        System.exit(1);
                    }
                }
            }
        } catch (SocketException ex) {
            // Conexão fechada externamente pelo método close().
            Server.logInfo("ADMINS listening stoped.");
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("ADMINS server closed.");
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
            Server.logInfo("ADMINS socket was not binded because no hostname defined.");
        } else {
            Core.waitStartHTTP();
            KeyStore keyStore = Core.loadKeyStore(HOSTNAME);
            if (keyStore == null) {
                Server.logError("ADMINS socket was not binded because " + HOSTNAME + " keystore not exists.");
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
                        Server.logInfo("binding ADMINS socket on port " + PORTS + "...");
                        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
                        SERVERS = (SSLServerSocket) socketFactory.createServerSocket(PORTS);
                        SSLParameters params = SERVERS.getSSLParameters();
                        params.setServerNames(serverNames);
                        SERVERS.setSSLParameters(params);
                        Thread sslService = new Thread() {
                            @Override
                            public void run() {
                                setName("SERVERADM");
                                startServiceSSL();
                            }
                        };
                        sslService.start();
                    } catch (BindException ex) {
                        Server.logError("ADMINS socket was not binded because TCP port " + PORTS + " is already in use.");
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            startService();
        }
    }
    
    /**
     * Processa o comando e retorna o resultado.
     * @param client o cliente do processo.
     * @param command a expressão do comando.
     * @return o resultado do processamento.
     */
    protected static String processCommand(
            InetAddress ipAddress,
            Client client,
            String command,
            OutputStream outputStream
    ) {
        try {
            String result = "";
            if (command.length() == 0) {
                result = "INVALID COMMAND\n";
            } else {
                StringTokenizer tokenizer = new StringTokenizer(command, " ");
                String token = tokenizer.nextToken();
                if (token.equals("VERSION") && !tokenizer.hasMoreTokens()) {
                    if (client == null) {
                        return Core.getAplication() + "\nClient: " + ipAddress.getHostAddress() + "\n";
                    } else {
                        return Core.getAplication() + "\n" + client + "\n";
                    }
                } else if (token.equals("THREAD") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("SHOW")) {
                        for (Thread thread : Thread.getAllStackTraces().keySet()) {
                            result += thread + "\n";
                        }
                    } else {
                        result = "INVALID PARAMETERS\n";
                    }
                } else if (token.equals("ANALISE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("SHOW")) {
                        TreeSet<Analise> queue = Analise.getAnaliseSet();
                        if (queue.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            StringBuilder builder = new StringBuilder();
                            for (Analise analise : queue) {
                                builder.append(analise);
                                builder.append('\n');
                            }
                            result = builder.toString();
                        }
                    } else if (token.equals("DUMP") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        StringBuilder builder = new StringBuilder();
                        if (token.equals("ALL")) {
                            Analise.dumpAll(builder);
                        } else {
                            Analise analise = Analise.get(token, false);
                            if (analise == null) {
                                builder.append("NOT FOUND\n");
                            } else {
                                analise.dump(builder);
                            }
                        }
                        if (builder.length() == 0) {
                            result = "EMPTY\n";
                        } else {
                            result = builder.toString();
                        }
                    } else if (token.equals("DROP") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        TreeSet<String> nameSet;
                        if (token.equals("ALL")) {
                            nameSet = Analise.getNameSet();
                        } else {
                            nameSet = new TreeSet<>();
                            nameSet.add(token);
                        }
                        StringBuilder builder = new StringBuilder();
                        for (String name : nameSet) {
                            Analise analise = Analise.drop(name);
                            if (analise == null) {
                                builder.append("NOT FOUND ");
                                builder.append(token);
                                builder.append("\n");
                            } else {
                                builder.append("DROPPED ");
                                builder.append(analise);
                                builder.append("\n");
                            }
                        }
                        if (builder.length() == 0) {
                            result = "EMPTY\n";
                        } else {
                            result = builder.toString();
                        }
                    } else if (isValidIP(token)) {
                        String ip = Subnet.normalizeIP(token);
                        if (tokenizer.hasMoreTokens()) {
                            String name = tokenizer.nextToken();
                            Analise analise = Analise.get(name, true);
                            if (analise.add(ip)) {
                                result = "QUEUED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } else {
                            StringBuilder builder = new StringBuilder();
                            builder.append(ip);
                            builder.append(' ');
                            Analise.process(ip, builder, 3000);
                            builder.append('\n');
                            result = builder.toString();
                        }
                    } else if (isValidCIDRv4(token)) {
                        String cidr = SubnetIPv4.normalizeCIDRv4(token);
                        short mask = SubnetIPv4.getMask(cidr);
                        if (mask < 18) {
                            result = "TOO BIG\n";
                        } else {
                            String name;
                            if (tokenizer.hasMoreTokens()) {
                                name = tokenizer.nextToken();
                            } else {
                                name = cidr.replace(':', '.');
                                name = name.replace('/', '-');
                            }
                            String last = SubnetIPv4.getLastIPv4(cidr);
                            String ip = SubnetIPv4.getFirstIPv4(cidr);
                            Analise analise = Analise.get(name, true);
                            analise.add(ip);
                            if (!ip.equals(last)) {
                                while (!last.equals(ip = SubnetIPv4.getNextIPv4(ip))) {
                                    analise.add(ip);
                                }
                                analise.add(last);
                            }
                            result = "QUEUED\n";
                        }
                    } else if (isValidCIDRv6(token)) {
                        String cidr = SubnetIPv6.normalizeCIDRv6(token);
                        short mask = SubnetIPv4.getMask(cidr);
                        if (mask < 114) {
                            result = "TOO BIG\n";
                        } else {
                            String name;
                            if (tokenizer.hasMoreTokens()) {
                                name = tokenizer.nextToken();
                            } else {
                                name = cidr.replace(':', '.');
                                name = name.replace('/', '-');
                            }
                            String last = SubnetIPv6.getLastIPv6(cidr);
                            String ip = SubnetIPv6.getFirstIPv6(cidr);
                            Analise analise = Analise.get(name, true);
                            analise.add(ip);
                            if (!ip.equals(last)) {
                                while (!last.equals(ip = SubnetIPv6.getNextIPv6(ip))) {
                                    analise.add(ip);
                                }
                                analise.add(last);
                            }
                            result = "QUEUED\n";
                        }
                    } else if (Core.isExecutableSignature(token)) {
                        result = "INVALID PARAMETERS\n";
                    } else if (Core.isSignatureURL(token)) {
                        result = "INVALID PARAMETERS\n";
                    } else if (isHostname(token)) {
                        String hostname =  Domain.normalizeHostname(token, false);
                        if (tokenizer.hasMoreTokens()) {
                            String name = tokenizer.nextToken();
                            Analise analise = Analise.get(name, true);
                            if (analise.add(hostname)) {
                                result = "QUEUED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } else if (Domain.isOfficialTLD(hostname)) {
                            result = "RESERVED DOMAIN\n";
                        } else if (Domain.isRootDomain(hostname)) {
                            String domain = "@" + hostname;
                            StringBuilder builder = new StringBuilder();
                            builder.append(domain);
                            builder.append(' ');
                            Analise.process(domain, builder, 3000);
                            builder.append('\n');
                            result = builder.toString();
                        } else {
                            StringBuilder builder = new StringBuilder();
                            TreeSet<String> ipSet = Analise.getIPSet(hostname);
                            if (ipSet == null) {
//                                if (Analise.isRunning() && Block.tryAdd(hostname)) {
//                                    Server.logInfo("new BLOCK '" + hostname + "' added by 'NXDOMAIN'.");
//                                }
                                result = "NXDOMAIN\n";
                            } else if (ipSet.isEmpty()) {
//                                if (Analise.isRunning() && Block.tryAdd(hostname)) {
//                                    Server.logInfo("new BLOCK '" + hostname + "' added by 'NONE'.");
//                                }
                                result = "NO ADDRESS\n";
                            } else {
                                for (String ip : ipSet) {
                                    builder.append(ip);
                                    builder.append(' ');
                                    Analise.process(ip, builder, 3000);
                                    builder.append('\n');
                                }
                                result = builder.toString();
                            }
                        }
                    } else if (token.startsWith("@") && isHostname(token.substring(1))) {
                        String address = "@" + Domain.normalizeHostname(token.substring(1), false);
                        if (tokenizer.hasMoreTokens()) {
                            String name = tokenizer.nextToken();
                            Analise analise = Analise.get(name, true);
                            if (analise.add(address)) {
                                result = "QUEUED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } else {
                            StringBuilder builder = new StringBuilder();
                            builder.append(address);
                            builder.append(' ');
                            Analise.process(address, builder, 3000);
                            builder.append('\n');
                            result = builder.toString();
                        }
                    } else {
                        result = "INVALID PARAMETERS\n";
                    }
                } else if (token.equals("STACK") && !tokenizer.hasMoreTokens()) {
                    result = Server.getThreadStack();
                } else if (token.equals("FIREWALL") && !tokenizer.hasMoreTokens()) {
                    String iface = Core.getInterface();
                    HashMap<Object,TreeSet<Client>> clientMap;
                    StringBuilder builder = new StringBuilder();
                    builder.append("#!/bin/bash\n");
                    builder.append("# \n");
                    builder.append("# Firewall for SPFBL service.\n");
                    builder.append("# Author: Leandro Carlos Rodrigues <leandro@spfbl.net>\n");
                    builder.append("# Author: Alexandre Pereira Buhler <alexandre@simaoebuhler.com.br>\n");
                    builder.append("# \n");
                    builder.append("\n");
                    builder.append("# Flush all rules and create the SPFBL chain.\n");
                    builder.append("COUNT=$(iptables -S | egrep -c \"^-N SPFBL$\")\n");
                    builder.append("if [ \"$COUNT\" -eq \"0\" ]; then\n");
                    builder.append("    iptables -t filter -N SPFBL\n");
                    builder.append("    iptables -t filter -I INPUT 1 -j SPFBL\n");
                    builder.append("else\n");
                    builder.append("    iptables -t filter -F SPFBL\n");
                    builder.append("fi\n");
                    builder.append("COUNT=$(ip6tables -S | egrep -c \"^-N SPFBL$\")\n");
                    builder.append("if [ \"$COUNT\" -eq \"0\" ]; then\n");
                    builder.append("    ip6tables -t filter -N SPFBL\n");
                    builder.append("    ip6tables -t filter -I INPUT 1 -j SPFBL\n");
                    builder.append("else\n");
                    builder.append("    ip6tables -t filter -F SPFBL\n");
                    builder.append("fi\n");
                    builder.append("\n");
                    builder.append("### SPFBL ADMIN\n\n");
                    builder.append("# Accept loopback connections.\n");
                    builder.append("iptables -t filter -A SPFBL -s 127.0.0.1 -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j ACCEPT\n");
                    builder.append("ip6tables -t filter -A SPFBL -s ::1 -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j ACCEPT\n");
                    if (Core.hasADMINS()) {
                        builder.append("iptables -t filter -A SPFBL -s 127.0.0.1 -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL -s ::1 -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j ACCEPT\n");
                    }
                    if (Core.hasSPFBL()) {
                        builder.append("iptables -t filter -A SPFBL -s 127.0.0.1 -p tcp --dport ");
                        builder.append(Core.getPortSPFBL());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL -s ::1 -p tcp --dport ");
                        builder.append(Core.getPortSPFBL());
                        builder.append(" -j ACCEPT\n");
                    }
                    if (Core.hasSPFBLS()) {
                        builder.append("iptables -t filter -A SPFBL -s 127.0.0.1 -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL -s ::1 -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j ACCEPT\n");
                    }
                    builder.append("\n");
                    clientMap = Client.getAdministratorMap();
                    for (Object key : clientMap.keySet()) {
                        if (key instanceof User) {
                            User user = (User) key;
                            builder.append("# Accept user ");
                            builder.append(user.getContact());
                            builder.append(".\n");
                        } else if (key.equals("NXDOMAIN")) {
                            builder.append("# Accept not identified networks.\n");
                        } else {
                            builder.append("# Accept domain ");
                            builder.append(key);
                            builder.append(".\n");
                        }
                        for (Client clientLocal : clientMap.get(key)) {
                            String cidr = clientLocal.getCIDR();
                            if (isValidCIDRv4(cidr)) {
                                builder.append("iptables -t filter -A SPFBL");
                                if (iface != null) {
                                    builder.append(" -i ");
                                    builder.append(iface);
                                }
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortADMIN());
                                builder.append(" -j ACCEPT\n");
                                if (Core.hasADMINS()) {
                                    builder.append("iptables -t filter -A SPFBL");
                                    if (iface != null) {
                                        builder.append(" -i ");
                                        builder.append(iface);
                                    }
                                    builder.append(" -s ");
                                    builder.append(cidr);
                                    builder.append(" -p tcp --dport ");
                                    builder.append(Core.getPortADMINS());
                                    builder.append(" -j ACCEPT\n");
                                }
                            } else if (isValidCIDRv6(cidr)) {
                                builder.append("ip6tables -t filter -A SPFBL");
                                if (iface != null) {
                                    builder.append(" -i ");
                                    builder.append(iface);
                                }
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortADMIN());
                                builder.append(" -j ACCEPT\n");
                                if (Core.hasADMINS()) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                    if (iface != null) {
                                        builder.append(" -i ");
                                        builder.append(iface);
                                    }
                                    builder.append(" -s ");
                                    builder.append(cidr);
                                    builder.append(" -p tcp --dport ");
                                    builder.append(Core.getPortADMINS());
                                    builder.append(" -j ACCEPT\n");
                                }
                            }
                        }
                        builder.append("\n");
                    }
                    builder.append("# Log and drop all others.\n");
                    builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j LOG --log-prefix \"ADMIN \"\n");
                    if (Core.hasADMINS()) {
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j LOG --log-prefix \"ADMIN \"\n");
                    }
                    builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j LOG --log-prefix \"ADMIN \"\n");
                    if (Core.hasADMINS()) {
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j LOG --log-prefix \"ADMIN \"\n");
                    }
                    builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j DROP\n");
                    if (Core.hasADMINS()) {
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j DROP\n");
                    }
                    builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortADMIN());
                    builder.append(" -j DROP\n");
                    if (Core.hasADMINS()) {
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortADMINS());
                        builder.append(" -j DROP\n");
                    }
                    builder.append("\n");
                    builder.append("### SPFBL BANNED\n\n");
                    clientMap = Client.getMap(Permission.NONE);
                    for (Object key : clientMap.keySet()) {
                        if (key instanceof User) {
                            User user = (User) key;
                            builder.append("# Drop user ");
                            builder.append(user.getContact());
                            builder.append(".\n");
                        } else if (key.equals("NXDOMAIN")) {
                            builder.append("# Drop not identified networks.\n");
                        } else {
                            builder.append("# Drop domain ");
                            builder.append(key);
                            builder.append(".\n");
                        }
                        for (Client clientLocal : clientMap.get(key)) {
                            String cidr = clientLocal.getCIDR();
                            if (isValidCIDRv4(cidr)) {
                                builder.append("iptables -t filter -A SPFBL");
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -j DROP\n");
                            } else if (isValidCIDRv6(cidr)) {
                                builder.append("ip6tables -t filter -A SPFBL");
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -j DROP\n");
                            }
                        }
                        builder.append("\n");
                    }
                    if (Core.hasPortHTTP()) {
                        builder.append("### SPFBL HTTP\n\n");
                        
                        TreeSet<String> highFrequencySet = ServerHTTP.getHighFrequencySet();
                        if (!highFrequencySet.isEmpty()) {
                            builder.append("# High frequency request.\n");
                            for (String cidr : highFrequencySet) {
                                if (cidr.contains(":")) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                } else {
                                    builder.append("iptables -t filter -A SPFBL");
                                }
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortHTTP());
                                builder.append(" -j ACCEPT\n");
                            }
                            builder.append("\n");
                        }
                        
                        builder.append("# Connection limit.\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --syn --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -m connlimit --connlimit-above ");
                        builder.append(ServerHTTP.getConnectionLimit());
                        builder.append(" --connlimit-mask 24 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --syn --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -m connlimit --connlimit-above ");
                        builder.append(ServerHTTP.getConnectionLimit());
                        builder.append(" --connlimit-mask 48 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW -m recent --set\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW -m recent --set\n");
                        
                        TreeSet<String> abusingSet = ServerHTTP.getAbusingSet();
                        for (String cidr : abusingSet) {
                            if (cidr.contains(":")) {
                                builder.append("ip6tables -t filter -A SPFBL");
                            } else {
                                builder.append("iptables -t filter -A SPFBL");
                            }
                            builder.append(" -s ");
                            builder.append(cidr);
                            builder.append(" -p tcp --dport ");
                            builder.append(Core.getPortHTTP());
                            builder.append(" -m state --state NEW ");
                            builder.append("-m recent --update --seconds 600 --hitcount 20 ");
                            if (cidr.contains(":")) {
                                builder.append("--mask ffff:ffff:ffff:: ");
                            } else {
                                builder.append("--mask 255.255.255.0 ");
                            }
                            builder.append("-j DROP\n");
                        }
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW ");
                        builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                        builder.append("--mask 255.255.255.0 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW ");
                        builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                        builder.append("--mask ffff:ffff:ffff:: ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("\n");
                        builder.append("# Accept all others.\n");
                        builder.append("iptables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -j ACCEPT\n\n");
                        if (Core.hasPortHTTPS()) {
                            builder.append("### SPFBL HTTPS\n\n");
                            if (!highFrequencySet.isEmpty()) {
                                builder.append("# High frequency request.\n");
                                for (String cidr : highFrequencySet) {
                                    if (cidr.contains(":")) {
                                        builder.append("ip6tables -t filter -A SPFBL");
                                    } else {
                                        builder.append("iptables -t filter -A SPFBL");
                                    }
                                    builder.append(" -s ");
                                    builder.append(cidr);
                                    builder.append(" -p tcp --dport ");
                                    builder.append(Core.getPortHTTPS());
                                    builder.append(" -j ACCEPT\n");
                                }
                                builder.append("\n");
                            }
                            builder.append("# Connection limit\n");
                            builder.append("iptables -t filter -A SPFBL -p tcp --syn --dport ");
                            builder.append(Core.getPortHTTPS());
                            builder.append(" -m connlimit --connlimit-above 16 --connlimit-mask 24 ");
                            builder.append("-j REJECT --reject-with tcp-reset\n");
                            builder.append("ip6tables -t filter -A SPFBL -p tcp --syn --dport ");
                            builder.append(Core.getPortHTTPS());
                            builder.append(" -m connlimit --connlimit-above 16 --connlimit-mask 48 ");
                            builder.append("-j REJECT --reject-with tcp-reset\n");
                            builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            if (iface != null) {
                                builder.append(" -i ");
                                builder.append(iface);
                            }
                            builder.append(" -m state --state NEW -m recent --set\n");
                            builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            if (iface != null) {
                                builder.append(" -i ");
                                builder.append(iface);
                            }
                            builder.append(" -m state --state NEW -m recent --set\n");
                            for (String cidr : abusingSet) {
                                if (cidr.contains(":")) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                } else {
                                    builder.append("iptables -t filter -A SPFBL");
                                }
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortHTTPS());
                                builder.append(" -m state --state NEW ");
                                builder.append("-m recent --update --seconds 600 --hitcount 20 ");
                                if (cidr.contains(":")) {
                                    builder.append("--mask ffff:ffff:ffff:: ");
                                } else {
                                    builder.append("--mask 255.255.255.0 ");
                                }
                                builder.append("-j DROP\n");
                            }
                            builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            if (iface != null) {
                                builder.append(" -i ");
                                builder.append(iface);
                            }
                            builder.append(" -m state --state NEW ");
                            builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                            builder.append("--mask 255.255.255.0 ");
                            builder.append("-j REJECT --reject-with tcp-reset\n");
                            builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            if (iface != null) {
                                builder.append(" -i ");
                                builder.append(iface);
                            }
                            builder.append(" -m state --state NEW ");
                            builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                            builder.append("--mask ffff:ffff:ffff:: ");
                            builder.append("-j REJECT --reject-with tcp-reset\n");
                            builder.append("\n");
                            builder.append("# Accept all others.\n");
                            builder.append("iptables -t filter -A SPFBL");
                            builder.append(" -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            builder.append(" -j ACCEPT\n");
                            builder.append("ip6tables -t filter -A SPFBL");
                            builder.append(" -p tcp --dport ");
                            builder.append(Core.getPortHTTPS());
                            builder.append(" -j ACCEPT\n\n");
                        }
                    }
                    if (Core.hasPortESMTP()) {
                        builder.append("### SPFBL ESMTP\n\n");
                        builder.append("# Simultaneous connection limit\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --syn --dport ");
                        builder.append(Core.getPortESMTP());
                        builder.append(" -m connlimit --connlimit-above 16 --connlimit-mask 25 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --syn --dport ");
                        builder.append(Core.getPortESMTP());
                        builder.append(" -m connlimit --connlimit-above 16 --connlimit-mask 52 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("\n");
                        builder.append("# Connection hate limit\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW -m recent --set\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW -m recent --set\n");
                        builder.append("\n");
                        TreeSet<String> abusingSet = ServerSMTP.getAbusingSet();
                        if (!abusingSet.isEmpty()) {
                            builder.append("# Limit rate for banned sources\n");
                            for (String cidr : abusingSet) {
                                if (cidr.contains(":")) {
                                    builder.append("ip6tables -t filter -A SPFBL ");
                                } else {
                                    builder.append("iptables -t filter -A SPFBL ");
                                }
                                builder.append("-s ");
                                builder.append(cidr);
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortESMTP());
                                builder.append(" -m state --state NEW ");
                                builder.append("-m recent --update --seconds 600 --hitcount 2 --mask ");
                                int index = cidr.lastIndexOf('/') + 1;
                                int mask = Integer.parseInt(cidr.substring(index));
                                if (cidr.contains(":")) {
                                    mask = mask < 52 ? 52 : mask;
                                    builder.append(SubnetIPv6.getFirstIPv6("ffff:ffff:ffff:ffff::/" + mask));
                                } else {
                                    mask = mask < 25 ? 25 : mask;
                                    builder.append(SubnetIPv4.getFirstIPv4("255.255.255.255/" + mask));
                                }
                                builder.append(" -j DROP\n");
                            }
                            builder.append("\n");
                        }
                        builder.append("# Default limit rate\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW ");
                        builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                        builder.append("--mask 255.255.255.128 ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -m state --state NEW ");
                        builder.append("-m recent --update --seconds 10 --hitcount 20 ");
                        builder.append("--mask ffff:ffff:ffff:f000:: ");
                        builder.append("-j REJECT --reject-with tcp-reset\n");
                        builder.append("\n");
                        builder.append("# Accept all others.\n");
                        builder.append("iptables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortESMTP());
                        builder.append(" -j ACCEPT\n\n");
                    }
                    builder.append("\n");
                    builder.append("### SPFBL P2P\n\n");
                    builder.append("iptables -t filter -A SPFBL");
                    if (iface != null) {
                        builder.append(" -i ");
                        builder.append(iface);
                    }
                    builder.append(" -p udp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j ACCEPT\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("iptables -t filter -A SPFBL");
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -p udp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j ACCEPT\n");
                    }
                    builder.append("ip6tables -t filter -A SPFBL");
                    if (iface != null) {
                        builder.append(" -i ");
                        builder.append(iface);
                    }
                    builder.append(" -p udp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j ACCEPT\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("ip6tables -t filter -A SPFBL");
                        if (iface != null) {
                            builder.append(" -i ");
                            builder.append(iface);
                        }
                        builder.append(" -p udp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j ACCEPT\n");
                    }
                    builder.append("\n");
                    builder.append("### SPFBL QUERY\n\n");
                    clientMap = Client.getMap(Permission.SPFBL);
                    for (Object key : clientMap.keySet()) {
                        if (key instanceof User) {
                            User user = (User) key;
                            builder.append("# Accept user ");
                            builder.append(user.getContact());
                            builder.append(".\n");
                        } else if (key.equals("NXDOMAIN")) {
                            builder.append("# Accept not identified networks.\n");
                        } else {
                            builder.append("# Accept domain ");
                            builder.append(key);
                            builder.append(".\n");
                        }
                        for (Client clientLocal : clientMap.get(key)) {
                            String cidr = clientLocal.getCIDR();
                            if (isValidCIDRv4(cidr)) {
                                builder.append("iptables -t filter -A SPFBL");
                                if (iface != null) {
                                    builder.append(" -i ");
                                    builder.append(iface);
                                }
                                builder.append(" -s ");
                                builder.append(clientLocal.getCIDR());
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortSPFBL());
                                builder.append(" -j ACCEPT\n");
                                if (Core.hasSPFBLS()) {
                                    builder.append("iptables -t filter -A SPFBL");
                                    if (iface != null) {
                                        builder.append(" -i ");
                                        builder.append(iface);
                                    }
                                    builder.append(" -s ");
                                    builder.append(clientLocal.getCIDR());
                                    builder.append(" -p tcp --dport ");
                                    builder.append(Core.getPortSPFBLS());
                                    builder.append(" -j ACCEPT\n");
                                }
                            } else if (isValidCIDRv6(cidr)) {
                                builder.append("ip6tables -t filter -A SPFBL");
                                if (iface != null) {
                                    builder.append(" -i ");
                                    builder.append(iface);
                                }
                                builder.append(" -s ");
                                builder.append(clientLocal.getCIDR());
                                builder.append(" -p tcp --dport ");
                                builder.append(Core.getPortSPFBL());
                                builder.append(" -j ACCEPT\n");
                                if (Core.hasSPFBLS()) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                    if (iface != null) {
                                        builder.append(" -i ");
                                        builder.append(iface);
                                    }
                                    builder.append(" -s ");
                                    builder.append(clientLocal.getCIDR());
                                    builder.append(" -p tcp --dport ");
                                    builder.append(Core.getPortSPFBLS());
                                    builder.append(" -j ACCEPT\n");
                                }
                            }
                        }
                        builder.append("\n");
                    }
                    builder.append("# Log and drop all others.\n");
                    builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j LOG --log-prefix \"SPFBL \"\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j LOG --log-prefix \"SPFBL \"\n");
                    }
                    builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j LOG --log-prefix \"SPFBL \"\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j LOG --log-prefix \"SPFBL \"\n");
                    }
                    builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j DROP\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j DROP\n");
                    }
                    builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                    builder.append(Core.getPortSPFBL());
                    builder.append(" -j DROP\n");
                    if (Core.hasSPFBLS()) {
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortSPFBLS());
                        builder.append(" -j DROP\n");
                    }
                    builder.append("\n");
                    if (Core.hasPortDNSBL()) {
                        builder.append("### DNSBL\n\n");
                        for (Client client2 : Client.getSet(Permission.DNSBL)) {
                            if (client2.getLimit() == 0) {
                                String cidr = client2.getCIDR();
                                if (cidr.contains(":")) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                    builder.append(" -s ");
                                    builder.append(cidr);
                                    builder.append(" -p udp --dport ");
                                    builder.append(Core.getPortDNSBL());
                                    builder.append(" -j ACCEPT\n");
                                } else {
                                    builder.append("iptables -t filter -A SPFBL");
                                    builder.append(" -s ");
                                    builder.append(cidr);
                                    builder.append(" -p udp --dport ");
                                    builder.append(Core.getPortDNSBL());
                                    builder.append(" -j ACCEPT\n");
                                }
                            }
                        }
                        builder.append("\n");
                        for (String cidr : ServerDNS.getBannedKeySet()) {
                            if (cidr.contains(":")) {
                                builder.append("ip6tables -t filter -A SPFBL");
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p udp --dport ");
                                builder.append(Core.getPortDNSBL());
                                builder.append(" -j DROP\n");
                            } else {
                                builder.append("iptables -t filter -A SPFBL");
                                builder.append(" -s ");
                                builder.append(cidr);
                                builder.append(" -p udp --dport ");
                                builder.append(Core.getPortDNSBL());
                                builder.append(" -j DROP\n");
                            }
                        }
                        builder.append("\n");
                        builder.append("# Accept all others.\n");
                        builder.append("iptables -t filter -A SPFBL");
                        builder.append(" -p udp --dport ");
                        builder.append(Core.getPortDNSBL());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL");
                        builder.append(" -p udp --dport ");
                        builder.append(Core.getPortDNSBL());
                        builder.append(" -j ACCEPT\n\n");
                    }
                    result = builder.toString();
                } else if (token.equals("SPLIT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (isValidCIDR(token)) {
                        String cidr = token;
                        if (Block.drop(cidr)) {
                            result += "DROPPED " + cidr + "\n";
                            result += Subnet.splitCIDR(cidr);
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("LOG") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("LEVEL") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        try {
                            Core.Level level = Core.Level.valueOf(token);
                            if (Core.setLevelLOG(level)) {
                                result += "CHANGED\n";
                            } else {
                                result += "SAME\n";
                            }
                        } catch (Exception ex) {
                            result = "INVALID COMMAND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("RELOAD") && !tokenizer.hasMoreTokens()) {
                    if (Core.loadConfiguration()) {
                        result = "RELOADED\n";
                    } else {
                        result = "FAILED\n";
                    }
                } else if (token.equals("QUEUE") && !tokenizer.hasMoreTokens()) {
                    if (Core.tryToProcessQueue()) {
                        result = "QUEUE PROCESSED\n";
                    } else {
                        result = "PROCESS BUSY\n";
                    }
                } else if (token.equals("SHUTDOWN") && !tokenizer.hasMoreTokens()) {
                    // Comando para finalizar o serviço.
//                    if (!tryAcquireTestCache()) {
//                        result = "INTERRUPTING TEST\n";
//                    } else
                    if (shutdown()) {
                        // Fechamento de processos realizado com sucesso.
                        result = "OK\n";
                    } else {
                        // Houve falha no fechamento dos processos.
                        result = "ERROR: SHUTDOWN\n";
                    }
                } else if (token.equals("STORE") && !tokenizer.hasMoreTokens()) {
                    // Comando para gravar o cache em disco.
                    if (tryStoreCache()) {
                        result = "STARTING STORE\n";
                    } else {
                        result = "ALREADY STORING\n";
                    }
                } else if (token.equals("DICTIONARY") && tokenizer.hasMoreTokens()) {
                    try {
                        token = tokenizer.nextToken();
                        if (token.equals("ADD") && tokenizer.countTokens() == 2) {
                            String lang = tokenizer.nextToken();
                            Locale locale = Locale.forLanguageTag(lang);
                            String word = Dictionary.normalizeCharset(tokenizer.nextToken());
                            if (locale.toLanguageTag().equals("und")) {
                                result = "INVALID LANGUAGE " + lang + "\n";
                            } else if (Dictionary.addWord(locale, word)) {
                                result = "ADDED " + locale.toLanguageTag() + " " + word + "\n";
                            } else {
                                result = "ALREADY EXISTS " + locale.toLanguageTag() + " " + word + "\n";
                            }
                        } else if (token.equals("PUT") && tokenizer.countTokens() == 3) {
                            Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                            String key = Dictionary.normalizeCharset(tokenizer.nextToken());
                            String word = Dictionary.normalizeCharset(tokenizer.nextToken());
                            if (Dictionary.addWord(locale, key, word)) {
                                result = "ADDED " + locale.toLanguageTag() + " " + key + " " + word + "\n";
                            } else {
                                result = "ALREADY EXISTS " + locale.toLanguageTag() + " " + key + "\n";
                            }
                        } else if (token.equals("COMPILE") && tokenizer.countTokens() == 3) {
                            Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                            String regex = Dictionary.normalizeCharset(tokenizer.nextToken());
                            String word = Dictionary.normalizeCharset(tokenizer.nextToken());
                            if (Dictionary.addRegex(locale, regex, word)) {
                                result = "ADDED " + locale.toLanguageTag() + " " + regex + " " + word + "\n";
                            } else {
                                result = "ALREADY EXISTS " + locale.toLanguageTag() + " " + regex + "\n";
                            }
                        } else if (token.equals("FLAG") && tokenizer.countTokens() == 2) {
                            String flag = tokenizer.nextToken();
                            String regex = Dictionary.normalizeCharset(tokenizer.nextToken());
                            if (Dictionary.putFlag(flag, regex)) {
                                result = "ADDED " + flag + " " + regex + "\n";
                            } else {
                                result = "ALREADY EXISTS " + regex + "\n";
                            }
                        } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("KEY") && tokenizer.countTokens() == 2) {
                                Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                String key = Dictionary.normalizeCharset(tokenizer.nextToken());
                                if (Dictionary.removeKey(locale, key)) {
                                    result = "DROPPED " + locale.toLanguageTag() + " " + key + "\n";
                                } else {
                                    result = "NOT FOUND " + locale.toLanguageTag() + " " + key + "\n";
                                }
                            } else if (token.equals("WORD") && tokenizer.countTokens() == 2) {
                                Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                String word = Dictionary.normalizeCharset(tokenizer.nextToken());
                                if (Dictionary.removeWord(locale, word)) {
                                    result = "DROPPED " + locale.toLanguageTag() + " " + word + "\n";
                                } else {
                                    result = "NOT FOUND " + locale.toLanguageTag() + " " + word + "\n";
                                }
                            } else if (token.equals("REGEX") && tokenizer.countTokens() == 2) {
                                Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                String regex = Dictionary.normalizeCharset(tokenizer.nextToken());
                                if (Dictionary.removeRegex(locale, regex)) {
                                    result = "DROPPED " + locale.toLanguageTag() + " " + regex + "\n";
                                } else {
                                    result = "NOT FOUND " + locale.toLanguageTag() + " " + regex + "\n";
                                }
                            } else if (token.equals("FLAG") && tokenizer.countTokens() == 1) {
                                String regex = Dictionary.normalizeCharset(tokenizer.nextToken());
                                if (Dictionary.dropFlag(regex)) {
                                    result = "DROPPED " + regex + "\n";
                                } else {
                                    result = "NOT FOUND " + regex + "\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else if (token.equals("SHOW") && tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("SET")) {
                                int count = Dictionary.writeWordSet(outputStream);
                                if (count == 0) {
                                    return "EMPTY\n";
                                } else {
                                    return null;
                                }
                            } else if (token.equals("MAP")) {
                                int count = Dictionary.writeWordMap(outputStream);
                                if (count == 0) {
                                    return "EMPTY\n";
                                } else {
                                    return null;
                                }
                            } else if (token.equals("REGEX")) {
                                int count = Dictionary.writeRegexMap(outputStream);
                                if (count == 0) {
                                    return "EMPTY\n";
                                } else {
                                    return null;
                                }
                            } else if (token.equals("FLAG")) {
                                int count = Dictionary.writeFlagMap(outputStream);
                                if (count == 0) {
                                    return "EMPTY\n";
                                } else {
                                    return null;
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } catch (PatternSyntaxException ex) {
                        result = "INVALID REGEX\n";
                    } catch (Exception ex) {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("TLD") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar TLDs.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String tld = tokenizer.nextToken();
                                if (Domain.addTLD(tld)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> tldSet = Domain.dropAllTLD();
                            if (tldSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String tld : tldSet) {
                                    result += "DROPPED " + tld + "\n";
                                }
                            }
                        } else {
                            try {
                                if (Domain.removeTLD(token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String tld : Domain.getTLDSet()) {
                            result += tld + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("DNSBL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addDNSBL(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllDNSBL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropDNSBL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getDNSBLMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("URIBL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addURIBL(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllURIBL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropURIBL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getURIBLMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("DNSWL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addDNSWL(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllDNSWL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropDNSWL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getDNSWLMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("SCORE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addSCORE(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllSCORE()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropSCORE(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getSCOREMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("DNSAL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addDNSAL(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllDNSAL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropDNSAL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getDNSALMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("SINCE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.addSINCE(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (ServerDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : ServerDNS.dropAllSINCE()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = ServerDNS.dropSINCE(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = ServerDNS.getSINCEMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                Zone zone = map.get(key);
                                result += zone + " " + zone.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("PROVIDER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String provider = tokenizer.nextToken();
                                if (Provider.add(provider)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> providerSet = Provider.dropAll();
                            if (providerSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String provider : providerSet) {
                                    result += "DROPPED " + provider + "\n";
                                }
                            }
                        } else {
                            try {
                                if (Provider.drop(token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        // Mecanismo de visualização de provedores.
                        for (String provider : Provider.getAll()) {
                            result += provider + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else if (token.equals("FIND") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (isValidEmail(token)) {
                            String domain = Domain.extractHost(token, true);
                            if (Provider.containsExact(domain)) {
                                result = domain + "\n";
                            } else {
                                result = "NOT FOUND " + domain + "\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("IGNORE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String ignore = tokenizer.nextToken();
                                if (Ignore.add(ignore)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> ignoreSet = Ignore.dropAll();
                            if (ignoreSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String ignore : ignoreSet) {
                                    result += "DROPPED " + ignore + "\n";
                                }
                            }
                        } else {
                            try {
                                if (Ignore.drop(token)) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        // Mecanismo de visualização de provedores.
                        StringBuilder builder = new StringBuilder();
                        TreeSet<String> ignoreSet = Ignore.getAll();
                        for (String ignore : ignoreSet) {
                            builder.append(ignore);
                            builder.append('\n');
                        }
                        result = builder.toString();
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("SUSPECT") && tokenizer.countTokens() == 1) {
                    token = tokenizer.nextToken();
                    Status status = SPF.getStatus(token);
                    if (status == Status.RED) {
                        if (Block.addExact(token)) {
                            result = "BLOCKED\n";
                            Server.logDebug(null, "new BLOCK '" + token + "' added by 'SUSPECT'.");
                        } else {
                            result = "RED\n";
                        }
                    } else if (status == Status.YELLOW) {
                        result = "YELLOW\n";
                    } else {
                        result = "GREEN\n";
                    }
                } else if (token.equals("BLOCK") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String blockToken = tokenizer.nextToken();
                                Map.Entry<Long,Query> queryEntry = User.getQueryEntrySafe(blockToken);
                                if (queryEntry == null) {
                                    int index = blockToken.indexOf(':');
                                    String clientLocal = null;
                                    if (index != -1) {
                                        String prefix = blockToken.substring(0, index);
                                        if (isValidEmail(prefix)) {
                                            clientLocal = prefix;
                                            blockToken = blockToken.substring(index+1);
                                        }
                                    }
                                    if (Core.isValidURL(blockToken)) {
                                        blockToken = Core.getSignatureURL(blockToken);
                                        clientLocal = null;
                                    }
                                    if (clientLocal == null && (blockToken = Block.add(blockToken)) != null) {
                                        Peer.sendBlockToAll(blockToken);
                                        result += "ADDED\n";
                                    } else if (clientLocal != null && Block.add(clientLocal, blockToken)) {
                                        result += "ADDED\n";
                                    } else {
                                        result += "ALREADY EXISTS\n";
                                    }
                                } else {
                                    long timeKey = queryEntry.getKey();
                                    Query userQuery = queryEntry.getValue();
                                    userQuery.blockKey(timeKey, "USER_COMPLAIN");
                                    String userEmail = userQuery.getUserEmail();
                                    String blockKey = userQuery.getBlockKey();
                                    result = "ADDED " + userEmail + ":" + blockKey + "\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            if (tokenizer.hasMoreTokens()) {
                                result = "INVALID COMMAND\n";
                            } else if (Block.dropAll()) {
                                result += "DROPPED\n";
                            } else {
                                result += "EMPTY\n";
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && Block.drop(token)) {
                                    result += "DROPPED\n";
                                } else if (clientLocal != null && Block.drop(clientLocal, token)) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                            if (result.length() == 0) {
                                result = "INVALID COMMAND\n";
                            }
                        }
                    } else if (token.equals("EXTRACT") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (isValidIP(token)) {
                            String ip = Subnet.normalizeIP(token);
                            int mask = isValidIPv4(ip) ? 32 : 128;
                            if ((token = Block.clearCIDR(ip, mask)) == null) {
                                result = "NOT FOUND\n";
                            } else {
                                int beginIndex = token.indexOf('=') + 1;
                                int endIndex = token.length();
                                token = token.substring(beginIndex, endIndex);
                                result = "EXTRACTED " + token + "\n";
                            }
                        } else{
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("FIND") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            token = tokenizer.nextToken();
                            int index = token.indexOf(':');
                            String clientLocal = null;
                            if (index != -1) {
                                String prefix = token.substring(0, index);
                                if (isValidEmail(prefix)) {
                                    clientLocal = prefix;
                                    token = token.substring(index+1);
                                }
                            }
                            String block = Block.find(clientLocal, token, true, true, true, false);
                            result = (block == null ? "NONE" : block) + "\n";
                        }
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de bloqueios de remetentes.
                            int count = Block.get(outputStream);
                            if (count == 0) {
                                return "EMPTY\n";
                            } else {
                                return null;
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os bloqueios de remetentes.
                                int count = Block.getAll(outputStream);
                                if (count == 0) {
                                    return "EMPTY\n";
                                } else {
                                    return null;
                                }
                            } else {
                                return "INVALID COMMAND\n";
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("GENERIC") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String genericToken = tokenizer.nextToken();
                                if ((genericToken = Generic.addGeneric(genericToken)) == null) {
                                    result += "ALREADY EXISTS\n";
                                 } else {
                                    result += "ADDED " + genericToken + "\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            if (tokenizer.hasMoreTokens()) {
                                result = "INVALID COMMAND\n";
                            } else {
                                if (Generic.dropGenericAll()) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "EMPTY\n";
                                }
                            }
                        } else {
                            try {
                                if (Generic.dropGeneric(token)) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                            if (result.length() == 0) {
                                result = "INVALID COMMAND\n";
                            }
                        }
                    } else if (token.equals("FIND") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        String generic = Generic.findGeneric(token);
                        result = (generic == null ? "NONE" : generic) + "\n";
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        StringBuilder builder = new StringBuilder();
                        for (String sender : Generic.getGeneric()) {
                            builder.append(sender);
                            builder.append('\n');
                        }
                        result = builder.toString();
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("DYNAMIC") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String genericToken = tokenizer.nextToken();
                                if ((genericToken = Generic.addDynamic(genericToken)) == null) {
                                    result += "ALREADY EXISTS\n";
                                 } else {
                                    result += "ADDED " + genericToken + "\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            if (tokenizer.hasMoreTokens()) {
                                result = "INVALID COMMAND\n";
                            } else {
                                if (Generic.dropDynamicAll()) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "EMPTY\n";
                                }
                            }
                        } else {
                            try {
                                if (Generic.dropDynamic(token)) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                            if (result.length() == 0) {
                                result = "INVALID COMMAND\n";
                            }
                        }
                    } else if (token.equals("FIND") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        String generic = Generic.findDynamic(token);
                        result = (generic == null ? "NONE" : generic) + "\n";
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        StringBuilder builder = new StringBuilder();
                        for (String sender : Generic.getDynamic()) {
                            builder.append(sender);
                            builder.append('\n');
                        }
                        result = builder.toString();
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("LICENCE") && tokenizer.countTokens() == 2) {
                    String userEmail = Domain.normalizeEmail(tokenizer.nextToken());
                    String clientMX = Domain.normalizeHostname(tokenizer.nextToken(), false);
                    if (userEmail == null) {
                        result = "INVALID EMAIL\n";
                    } else if (clientMX == null) {
                        result = "INVALID MX\n";
                    } else {
                        long expiration = System.currentTimeMillis() + Server.WEEK_TIME;
                        Licence licence = Licence.getLicence(userEmail);
                        String url = licence.getLicenceURL(expiration, clientMX);
                        if (url == null) {
                            result = "COULD NOT GENERATE A SECURE URL\n";
                        } else {
                            result = url + '\n';
                        }
                    }
                } else if (token.equals("INVITATION") && tokenizer.hasMoreTokens()) {
                    String userEmail = null;
                    String recipient = tokenizer.nextToken();
                    int index = recipient.indexOf(':');
                    if (index != -1) {
                        String prefix = recipient.substring(0, index);
                        if (isValidEmail(prefix)) {
                            userEmail = prefix;
                            recipient = recipient.substring(index+1);
                        }
                    }
                    User user;
                    if (userEmail == null) {
                        user = User.getUserFor(recipient);
                    } else {
                        user = User.get(userEmail);
                    }
                    if (!isValidEmail(recipient)) {
                        result = "INVALID COMMAND\n";
                    } else if (user == null) {
                        result = "UNDEFINED USER\n";
                    } else {
                        String invitation = user.getInvitation(recipient);
                        if (invitation == null) {
                            result = "INVALID COMMAND\n";
                        } else {
                            result = invitation + "\n";
                        }
                    }
                } else if (token.equals("WHITE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String whiteToken = tokenizer.nextToken();
                                Map.Entry<Long,Query> queryEntry = User.getQueryEntrySafe(whiteToken);
                                if (queryEntry == null) {
                                    int index = whiteToken.indexOf(':');
                                    String clientLocal = null;
                                    if (index != -1) {
                                        String prefix = whiteToken.substring(0, index);
                                        if (isValidEmail(prefix)) {
                                            clientLocal = prefix;
                                            whiteToken = whiteToken.substring(index+1);
                                        }
                                    }
                                    if (clientLocal == null) {
                                        if (White.add(whiteToken)) {
                                            result += "ADDED\n";
                                        } else {
                                            result += "ALREADY EXISTS\n";
                                        }
                                    } else if (White.add(clientLocal, whiteToken)) {
                                        result += "ADDED\n";
                                    } else {
                                        result += "ALREADY EXISTS\n";
                                    }
                                } else {
                                    long timeKey = queryEntry.getKey();
                                    Query userQuery = queryEntry.getValue();
                                    userQuery.whiteKey(timeKey);
                                    String userEmail = userQuery.getUserEmail();
                                    String whiteKey = userQuery.getWhiteKey();
                                    result = "ADDED " + userEmail + ":" + whiteKey + "\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SENDER") && tokenizer.hasMoreTokens()) {
                        String userEmail = null;
                        String sender = tokenizer.nextToken();
                        int index = sender.indexOf(':');
                        if (index != -1) {
                            String prefix = sender.substring(0, index);
                            if (isValidEmail(prefix)) {
                                userEmail = prefix;
                                sender = sender.substring(index+1);
                            }
                        }
                        if (Domain.isMailFrom(sender)) {
                            String mx = Domain.extractHost(sender, true);
                            String domain = "." + Domain.extractDomain(sender, false);
                            if (userEmail == null) {
                                result = "UNDEFINED USER\n";
                            } else if (Block.containsExact(userEmail + ":" + sender)) {
                                result = "BLOCKED AS " + sender + "\n";
                            } else if (Block.containsExact(userEmail + ":" + mx)) {
                                result = "BLOCKED AS " + mx + "\n";
                            } else if (Block.containsExact(userEmail + ":" + domain)) {
                                result = "BLOCKED AS " + domain + "\n";
                            } else {
                                boolean freemail = Provider.containsExact(mx);
                                if (freemail) {
                                    token = sender;
                                } else {
                                    token = mx;
                                }
                                if (White.add(userEmail, token + ";PASS")) {
                                    result = "ADDED " + userEmail + ":" + token + ";PASS\n";
                                } else {
                                    result = "ALREADY EXISTS " + userEmail + ":" + token + ";PASS\n";
                                }
                                if (!freemail) {
                                    if (White.add(userEmail, token + ";BULK")) {
                                        result += "ADDED " + userEmail + ":" + token + ";BULK\n";
                                    } else {
                                        result += "ALREADY EXISTS " + userEmail + ":" + token + ";BULK\n";
                                    }
                                    if (White.add(userEmail, token + ";" + domain.substring(1))) {
                                        result += "ADDED " + userEmail + ":" + token + ";" + domain.substring(1) + "\n";
                                    } else {
                                        result += "ALREADY EXISTS " + userEmail + ":" + token + ";" + domain.substring(1) + "\n";
                                    }
                                }
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            if (White.dropAll()) {
                                result += "DROPPED\n";
                            } else {
                                result += "EMPTY\n";
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && White.drop(token)) {
                                    result = "DROPPED\n";
                                } else if (clientLocal != null && White.drop(clientLocal, token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de liberação de remetentes.
                            StringBuilder builder = new StringBuilder();
                            for (String sender : White.get()) {
                                builder.append(sender);
                                builder.append('\n');
                            }
                            result = builder.toString();
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os liberação de remetentes.
                                StringBuilder builder = new StringBuilder();
                                for (String sender : White.getAll()) {
                                    builder.append(sender);
                                    builder.append('\n');
                                }
                                result = builder.toString();
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("TRAP") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        try {
                            String trapToken = tokenizer.nextToken();
                            String timeString = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                            int index = trapToken.indexOf(':');
                            String clientLocal = null;
                            if (index != -1) {
                                String prefix = trapToken.substring(0, index);
                                if (isValidEmail(prefix)) {
                                    clientLocal = prefix;
                                    trapToken = trapToken.substring(index+1);
                                }
                            }
                            if (clientLocal == null && Trap.putTrap(trapToken, timeString)) {
                                result = "ADDED\n";
                            } else if (clientLocal != null && Trap.putTrap(clientLocal, trapToken, timeString)) {
                                result = "ADDED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } catch (ProcessException ex) {
                            result += ex.getMessage() + "\n";
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> trapSet = Trap.dropTrapAll();
                            if (trapSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String trap : trapSet) {
                                    result += "DROPPED " + trap + "\n";
                                }
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && Trap.drop(token)) {
                                    result = "DROPPED\n";
                                } else if (clientLocal != null && Trap.drop(clientLocal, token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de liberação de remetentes.
                            for (String sender : Trap.getTrapSet()) {
                                result += sender + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os liberação de remetentes.
                                StringBuilder builder = new StringBuilder();
                                for (String sender : Trap.getTrapAllSet()) {
                                    builder.append(sender);
                                    builder.append('\n');
                                }
                                result = builder.toString();
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("TRANSPORT") && tokenizer.countTokens() > 1) {
                    User user = User.get(tokenizer.nextToken().toLowerCase());
                    String action = tokenizer.nextToken();
                    if (user == null) {
                        result = "USER NOT FOUND\n";
                    } else if (action.equals("ADD") && tokenizer.countTokens() > 2) {
                        Integer index = Core.getInteger(tokenizer.nextToken());
                        String protocol = tokenizer.nextToken();
                        if (index == null || index < 0) {
                            result = "INVALID INDEX\n";
                        } else if (protocol.equals("SMTP")) {
                            String hostname = tokenizer.nextToken();
                            Integer port = tokenizer.hasMoreTokens() ? Core.getInteger(tokenizer.nextToken()) : null;
                            String username = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                            String password = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                            Properties props = ServerSMTP.newProperties(hostname, port, username, password);
                            if (props == null) {
                                result = "INVALID COMMAND\n";
                            } else if (user.putTransport(index, props) == null) {
                                result = "ADDED\n";
                            } else {
                                result = "CHANGED\n";
                            }
                        } else {
                            result = "PROTOCOL NOT DEFINED\n";
                        }
                    } else if (action.equals("SET") && tokenizer.countTokens() == 3) {
                        Integer index = Core.getInteger(tokenizer.nextToken());
                        String name = tokenizer.nextToken();
                        String value = tokenizer.nextToken();
                        if (user.setTransport(index, name, value.equals("NULL") ? null : value) == null) {
                            result = "PARAMETER NOT FOUND\n";
                        } else {
                            result = "CHANGED\n";
                        }
                    } else if (action.equals("PUT") && tokenizer.countTokens() == 3) {
                        Integer index = Core.getInteger(tokenizer.nextToken());
                        String name = tokenizer.nextToken();
                        String value = tokenizer.nextToken();
                        if (user.putTransport(index, name, value)) {
                            result = "PUTTED\n";
                        } else {
                            result = "NOT PUTTED\n";
                        }
                    } else if (action.equals("DROP") && tokenizer.countTokens() == 1) {
                        Integer index = Core.getInteger(tokenizer.nextToken());
                        if (user.removeTransport(index) == null) {
                            result = "INDEX NOT FOUND\n";
                        } else {
                            result = "DROPPED\n";
                        }
                    } else if (action.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        TreeMap<Integer,Properties> resultMap = user.getTransportMap();
                        if (resultMap == null || resultMap.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            StringBuilder builder = new StringBuilder();
                            for (int index : resultMap.keySet()) {
                                Properties props = resultMap.get(index);
                                String protocol = props.getProperty("mail.transport.protocol", "smtp");
                                builder.append(index);
                                builder.append(':');
                                builder.append(protocol);
                                builder.append('\n');
                                for (String name : props.stringPropertyNames()) {
                                    if (!name.equals("mail.transport.protocol")) {
                                        String value = props.getProperty(name);
                                        builder.append('\t');
                                        builder.append(name);
                                        builder.append('=');
                                        builder.append(value);
                                        builder.append('\n');
                                    }
                                }
                            }
                            result = builder.toString();
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("FQDN") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() == 2) {
                        String ip = tokenizer.nextToken();
                        String fqdn = tokenizer.nextToken();
                        if (!isValidIP(ip)) {
                            result = "INVALID IP\n";
                        } else if (!isHostname(fqdn)) {
                            result = "INVALID FQDN\n";
                        } else if (Subnet.isReservedIP(ip)) {
                            result = "RESERVED IP\n";
                        } else if (Generic.containsGenericFQDN(fqdn)) {
                            result = "GENERIC FQDN\n";
                        } else if (FQDN.isFQDN(ip, fqdn)) {
                            result = "ALREADY EXISTS\n";
                        } else if (FQDN.addFQDN(ip, fqdn, true)) {
                            result = "ADDED\n";
                        } else {
                            result = "NOT MATCH\n";
                        }
                    } else if (token.equals("WHITE") && tokenizer.countTokens() == 2) {
                        String ip = tokenizer.nextToken();
                        String fqdn = tokenizer.nextToken();
                        if (!isValidIP(ip)) {
                            result = "INVALID IP\n";
                        } else if (!isHostname(fqdn)) {
                            result = "INVALID FQDN\n";
                        } else if (Subnet.isReservedIP(ip)) {
                            result = "RESERVED IP\n";
                        } else if (Generic.containsGenericFQDN(fqdn)) {
                            result = "GENERIC FQDN\n";
                        } else if (FQDN.addFQDN(ip, fqdn, true) || FQDN.isFQDN(ip, fqdn)) {
                            String abuse = Abuse.getEmail(ip, fqdn);
                            if (abuse == null) {
                                result = "NO ABUSE ADDRESS\n";
                            } else if (NoReply.isUnsubscribed(abuse)) {
                                result = "UNSUBSCRIBED ABUSE\n";
                            } else if (White.addFQDN(fqdn)) {
                                result = "ADDED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } else {
                            result = "NOT MATCH\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        if (isValidIP(token)) {
                            String ip = token;
                            String fqdn = FQDN.dropIP(ip);
                            if (fqdn == null) {
                                result += "NOT FOUND\n";
                            } else {
                                result += "DROPPED " + fqdn + "\n";
                            }
                        } else if (isHostname(token)) {
                            String fqdn = token;
                            if (White.dropFQDN(fqdn)) {
                                result += "WHITE NOT FOUND\n";
                            } else {
                                result += "WHITE DROPPED " + fqdn + "\n";
                            }
                        } else {
                            result = "INVALID IP\n";
                        }
                    } else if (token.equals("SHOW")) {
                        StringBuilder builder = new StringBuilder();
                        for (String ip : FQDN.getKeyList()) {
                            String fqdn = FQDN.getFQDN(ip, false);
                            if (fqdn != null) {
                                builder.append(ip);
                                builder.append(' ');
                                builder.append(fqdn);
                                builder.append('\n');
                            }
                        }
                        if (builder.length() == 0) {
                            result = "EMPTY\n";
                        } else {
                            result = builder.toString();
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("ABUSE") && tokenizer.hasMoreTokens()) {
                    if (Core.isMatrixDefence()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ADD") && tokenizer.countTokens() == 2) {
                            try {
                                String address = tokenizer.nextToken();
                                String email = Domain.normalizeEmail(tokenizer.nextToken());
                                if (Trap.containsAnythingExact(email)) {
                                    result = "INEXISTENT\n";
                                } else if (Abuse.put(address, email)) {
                                    result = "ADDED\n";
                                } else {
                                    result = "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                TreeSet<String> domainSet = Abuse.dropAll();
                                if (domainSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String domain : domainSet) {
                                        result += "DROPPED " + domain + "\n";
                                    }
                                }
                            } else {
                                try {
                                    if (Abuse.drop(token)) {
                                        result = "DROPPED\n";
                                    } else {
                                        result = "NOT FOUND\n";
                                    }
                                } catch (ProcessException ex) {
                                    result = ex.getMessage() + "\n";
                                }
                            }
                        } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                            StringBuilder builder = new StringBuilder();
                            for (String domain : Abuse.getKeySet()) {
                                String email = Abuse.getExact(domain);
                                if (email != null) {
                                    builder.append(domain);
                                    builder.append(' ');
                                    builder.append(email);
                                    builder.append('\n');
                                }
                            }
                            if (builder.length() == 0) {
                                result = "EMPTY\n";
                            } else {
                                result = builder.toString();
                            }
                        } else if (token.equals("CLEAR") && tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            token = Domain.normalizeEmail(token);
                            if (token == null) {
                                result = "INVALID EMAIL ADDRESS\n";
                            } else if (Abuse.clearReputation(token)) {
                                result = "REPUTATION CLEARED\n";
                            } else {
                                result = "REPUTATION NOT EXISTS\n";
                            }
                        } else if (token.equals("GET") && tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            String email = Abuse.getEmail(token);
                            if (email == null) {
                                result = "NONE\n";
                            } else {
                                result = email + "\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else {
                        result = "EXTERNAL DNSAL\n";
                    }
                } else if (token.equals("INEXISTENT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        try {
                            String inexistentToken = tokenizer.nextToken();
                            String timeString = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                            int index = inexistentToken.indexOf(':');
                            String clientLocal = null;
                            if (index != -1) {
                                String prefix = inexistentToken.substring(0, index);
                                if (isValidEmail(prefix)) {
                                    clientLocal = prefix;
                                    inexistentToken = inexistentToken.substring(index+1);
                                }
                            }
                            if (NoReply.contains(inexistentToken, false)) {
                                result = "NO REPLY\n";
                            } else if (timeString == null) {
                                if (Trap.addInexistentForever(inexistentToken)) {
                                    result = "ADDED\n";
                                } else {
                                    result = "ALREADY EXISTS\n";
                                }
                            } else if (clientLocal == null && Trap.putInexistent(inexistentToken, timeString)) {
                                result = "ADDED\n";
                            } else if (clientLocal != null && Trap.putInexistent(clientLocal, inexistentToken, timeString)) {
                                result = "ADDED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } catch (ProcessException ex) {
                            result += ex.getMessage() + "\n";
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> inexistentSet = Trap.dropInexistentAll();
                            if (inexistentSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String inexistent : inexistentSet) {
                                    result += "DROPPED " + inexistent + "\n";
                                }
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && Trap.drop(token)) {
                                    result = "DROPPED\n";
                                } else if (clientLocal != null && Trap.drop(clientLocal, token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de liberação de remetentes.
                            StringBuilder builder = new StringBuilder();
                            for (String sender : Trap.getInexistentSet()) {
                                builder.append(sender);
                                builder.append('\n');
                            }
                            result = builder.toString();
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os liberação de remetentes.
                                StringBuilder builder = new StringBuilder();
                                for (String sender : Trap.getInexistentAllSet()) {
                                    builder.append(sender);
                                    builder.append('\n');
                                }
                                result = builder.toString();
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("SPLIT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (isValidCIDR(token)) {
                        String cidr = token;
                        if (Block.drop(cidr)) {
                            result += "DROPPED " + cidr + "\n";
                            result += Subnet.splitCIDR(cidr);
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("NOREPLY") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                token = tokenizer.nextToken();
                                if (NoReply.add(token)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> noreplaySet = NoReply.dropAll();
                            if (noreplaySet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String noreplay : noreplaySet) {
                                    result += "DROPPED " + noreplay + "\n";
                                }
                            }
                        } else {
                            try {
                                if (NoReply.drop(token)) {
                                    result = "DROPPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String sender : NoReply.getSet()) {
                            result += sender + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("CLIENT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        if (tokenizer.hasMoreTokens()) {
                            String domain = tokenizer.nextToken();
                            if (tokenizer.hasMoreTokens()) {
                                String permission = tokenizer.nextToken();
                                String email = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                try {
                                    Client clientLocal = Client.create(
                                            cidr, domain, permission, email
                                    );
                                    if (clientLocal == null) {
                                        result = "ALREADY EXISTS\n";
                                    } else {
                                        result = "ADDED " + clientLocal + "\n";
                                    }
                                } catch (ProcessException ex) {
                                    result = ex.getMessage() + "\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<Client> clientSet = Client.dropAll();
                            if (clientSet.isEmpty()) {
                                result += "EMPTY\n";
                            } else {
                                for (Client clientLocal : clientSet) {
                                    result += "DROPPED " + clientLocal + "\n";
                                }
                            }
                        } else if (isValidCIDR(token)) {
                            Client clientLocal = Client.drop(token);
                            if (clientLocal == null) {
                                result += "NOT FOUND\n";
                            } else {
                                result += "DROPPED " + clientLocal + "\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                        
                    } else if (token.equals("SHOW")) {
                        if (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("DNSBL")) {
                                for (Client clientLocal : Client.getSet(Client.Permission.DNSBL)) {
                                    result += clientLocal + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("SPFBL")) {
                                for (Client clientLocal : Client.getSet(Client.Permission.SPFBL)) {
                                    result += clientLocal + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("NONE")) {
                                for (Client clientLocal : Client.getSet(Client.Permission.NONE)) {
                                    result += clientLocal + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("ADMIN")) {
                                for (Client clientLocal : Client.getAdministratorSet()) {
                                    result += clientLocal + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (isValidIP(token)) {
                                token = Subnet.normalizeIP(token);
                                Client clientLocal = Client.getByIP(token);
                                if (clientLocal == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += clientLocal + "\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            for (Client clientLocal : Client.getSet()) {
                                result += clientLocal + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        }
                    } else if (token.equals("SET") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (isValidCIDR(token) && tokenizer.hasMoreTokens()) {
                            String cidr = Subnet.normalizeCIDR(token);
                            token = tokenizer.nextToken();
                            Client clientLocal = Client.getByCIDR(cidr);
                            if (clientLocal == null) {
                                result = "NOT FOUND\n";
                            } else if (token.equals("LIMIT") && tokenizer.countTokens() == 1) {
                                String limit = tokenizer.nextToken();
                                if (clientLocal.setLimit(limit)) {
                                    result = "UPDATED " + clientLocal + "\n";
                                } else {
                                    result = "ALREADY THIS VALUE\n";
                                }
                            } else if (token.equals("ACTION") && tokenizer.hasMoreTokens()) {
                                token = tokenizer.nextToken();
                                if (token.equals("BLOCK") && tokenizer.countTokens() == 1) {
                                    token = tokenizer.nextToken();
                                    if (clientLocal.setActionBLOCK(token)) {
                                        result = "UPDATED " + clientLocal + "\n";
                                    } else {
                                        result = "ALREADY THIS VALUE\n";
                                    }
                                } else if (token.equals("RED") && tokenizer.countTokens() == 1) {
                                    token = tokenizer.nextToken();
                                    if (clientLocal.setActionRED(token)) {
                                        result = "UPDATED " + clientLocal + "\n";
                                    } else {
                                        result = "ALREADY THIS VALUE\n";
                                    }
                                } else if (token.equals("YELLOW") && tokenizer.countTokens() == 1) {
                                    token = tokenizer.nextToken();
                                    if (clientLocal.setActionYELLOW(token)) {
                                        result = "UPDATED " + clientLocal + "\n";
                                    } else {
                                        result = "ALREADY THIS VALUE\n";
                                    }
                                } else if (token.equals("SHOW") && tokenizer.countTokens() == 0) {
                                    result = "BLOCK=" + clientLocal.getActionNameBLOCK() + "\n";
                                    result += "RED=" + clientLocal.getActionNameRED() + "\n";
                                    result += "YELLOW=" + clientLocal.getActionNameYELLOW() + "\n";
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                            } else if (isHostname(token) && tokenizer.hasMoreTokens()) {
//                                String domain = Domain.extractDomain(token, false);
                                String domain = Domain.normalizeHostname(token, false);
                                String permission = tokenizer.nextToken();
                                String email = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                if (tokenizer.hasMoreTokens()) {
                                    result = "INVALID COMMAND\n";
                                } else if (email != null && !isValidEmail(email)) {
                                    result = "INVALID EMAIL\n";
                                } else {
                                    clientLocal.setPermission(permission);
                                    clientLocal.setDomain(domain);
                                    clientLocal.setEmail(email);
                                    result = "UPDATED " + clientLocal + "\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("USER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        String email = Domain.normalizeEmail(tokenizer.nextToken());
                        if (tokenizer.hasMoreTokens()) {
                            String name = tokenizer.nextToken();
                            while (tokenizer.hasMoreElements()) {
                                name += ' ' + tokenizer.nextToken();
                            }
                            try {
                                User userLocal = User.create(email, name);
                                if (userLocal == null) {
                                    result = "ALREADY EXISTS\n";
                                } else {
                                    result = "ADDED " + userLocal + "\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<Object> valueSet = User.dropAll();
                            if (valueSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (Object value : valueSet) {
                                    if (value instanceof User) {
                                        result += "DROPPED USER " + value + "\n";
                                    } else {
                                        result += "DROPPED ALIAS " + value + "\n";
                                    }
                                }
                            }
                        } else if ((token = Domain.normalizeEmail(token)) != null) {
                            Object value = User.drop(token);
                            if (value instanceof User) {
                                result = "DROPPED USER " + value + "\n";
                            } else if (value instanceof String) {
                                result = "DROPPED ALIAS " + token + " " + value + "\n";
                            } else {
                                result = "NOT FOUND\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("ALIAS") && tokenizer.countTokens() == 2) {
                        String key = tokenizer.nextToken();
                        String value = tokenizer.nextToken();
                        String key2 = Domain.normalizeEmail(key);
                        String value2 = Domain.normalizeEmail(value);
                        if (key2 != null && value2 != null && !key2.equals(value2)) {
                            if (User.alias(key, value)) {
                                result = "CHANGED\n";
                            } else {
                                result = "NOT CHANGED\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        TreeMap<String,Object> map = User.getMap();
                        for (String key : map.keySet()) {
                            Object value = map.get(key);
                            if (value instanceof User) {
                                User userLocal = (User) value;
                                result += userLocal + "\n";
                            } else if (value instanceof String) {
                                result += key + " => " + value + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else if (token.equals("SET") && tokenizer.hasMoreElements()) {
                        token = tokenizer.nextToken();
                        if (isValidEmail(token)) {
                            token = Domain.normalizeEmail(token);
                            User user = User.get(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else if (tokenizer.hasMoreElements()) {
                                token = tokenizer.nextToken();
                                if (token.equals("PASSWORD") && tokenizer.hasMoreElements()) {
                                    token = tokenizer.nextToken();
                                    if (token.equals("NULL")) {
                                        user.clearPassword();
                                        result = "DROPPED\n";
                                    } else if (user.isValidPassword(token)) {
                                        result = "NOT CHANGED\n";
                                    } else if (user.setPassword(token)) {
                                        result = "CHANGED TO " + token + "\n";
                                    } else {
                                        result = "INVALID PASSWORD\n";
                                    }
                                } else if (token.equals("LOCALE") && tokenizer.hasMoreElements()) {
                                    try {
                                        token = tokenizer.nextToken();
                                        if (user.setLocale(token)) {
                                            result = "CHANGED TO " + user.getLocale() + "\n";
                                        } else {
                                            result = "NOT CHANGED\n";
                                        }
                                    } catch (IllegalArgumentException ex) {
                                        result = "INVALID LOCALE\n";
                                    }
                                } else if (token.equals("TIMEZONE") && tokenizer.hasMoreElements()) {
                                    token = tokenizer.nextToken();
                                    if (user.setTimeZone(token)) {
                                        result = "CHANGED TO " + user.getTimeZone().getID() + "\n";
                                    } else {
                                        result = "NOT CHANGED\n";
                                    }
                                } else if (token.equals("BLOCKCLEAR") && tokenizer.hasMoreElements()) {
                                    token = tokenizer.nextToken();
                                    if (token.equals("FALSE")) {
                                        if (user.setSupressClearBLOCK(true)) {
                                            result = "CHANGED\n";
                                        } else {
                                            result = "NOT CHANGED\n";
                                        }
                                    } else if (token.equals("TRUE")) {
                                        if (user.setSupressClearBLOCK(false)) {
                                             result = "CHANGED\n";
                                        } else {
                                            result = "NOT CHANGED\n";
                                        }
                                    } else {
                                        result = "INVALID COMMAND\n";
                                    }
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID USER\n";
                        }
                    } else if (token.equals("SEND") && tokenizer.hasMoreElements()) {
                        token = tokenizer.nextToken();
                        if (isValidEmail(token)) {
                            token = Domain.normalizeEmail(token);
                            User user = User.get(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else if (tokenizer.hasMoreElements()) {
                                token = tokenizer.nextToken();
                                if (token.equals("TOTP") && !tokenizer.hasMoreElements()) {
                                    if (user.sendTOTP()) {
                                        result = "TOTP SENT TO " + user.getEmail() + "\n";
                                    } else {
                                        result = "TOTP NOT SENT\n";
                                    }
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID USER\n";
                        }
                    } else if (token.equals("RECIPIENT") && tokenizer.hasMoreElements()) {
                        token = tokenizer.nextToken();
                        if (isValidEmail(token)) {
                            token = Domain.normalizeEmail(token);
                            User user = User.get(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else if (tokenizer.hasMoreElements()) {
                                token = tokenizer.nextToken();
                                if (tokenizer.hasMoreElements()) {
                                    result = "INVALID COMMAND\n";
                                } else if (isValidEmail(token)) {
                                    if (user.addRecipient(null, token)) {
                                        result = "RECIPIENT ADDED\n";
                                    } else {
                                        result = "ALREADY EXISTS\n";
                                    }
                                } else if (token.equals("CLEAR")) {
                                    if (user.clearRecipient()) {
                                        result = "RECIPIENT CLEARED\n";
                                    } else {
                                        result = "ALREADY EMPTY\n";
                                    }
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                            } else {
                                result = "INVALID COMMAND\n";
                            }
                        } else {
                            result = "INVALID USER\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("RECIPIENT") && tokenizer.countTokens() > 2) {
                    token = tokenizer.nextToken();
                    String userEmail = tokenizer.nextToken();
                    String recipient = tokenizer.nextToken();
                    if (!isValidEmail(userEmail)) {
                        result = "INVALID COMMAND\n";
                    } else if (!isValidEmail(recipient)) {
                        result = "INVALID COMMAND\n";
                    } else if (token.equals("SET") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (!Recipient.isValidType(token)) {
                            result = "INVALID COMMAND\n";
                        } else if (Recipient.set(userEmail, recipient, token)) {
                            result = "CHANGED\n";
                        } else {
                            result = "NOT CHANGED\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("PEER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") &&  tokenizer.hasMoreTokens()) {
                        String service = tokenizer.nextToken();
                        String email = null;
                        if (tokenizer.hasMoreElements()) {
                            email = tokenizer.nextToken();
                        }
                        StringTokenizer addressTokenizer = new StringTokenizer(service, ":");
                        if (addressTokenizer.countTokens() < 2) {
                            result = "INVALID COMMAND\n";
                        } else if (email != null && !isValidEmail(email)) {
                            result = "INVALID EMAIL\n";
                        } else {
                            String address = addressTokenizer.nextToken();
                            String port = addressTokenizer.nextToken();
                            String ports = addressTokenizer.hasMoreTokens() ? addressTokenizer.nextToken() : null;
                            String https = addressTokenizer.hasMoreTokens() ? addressTokenizer.nextToken() : null;
                            Peer peer = Peer.create(address, port, ports, https);
                            if (peer == null) {
                                result = "ALREADY EXISTS\n";
                            } else {
                                peer.setReceiveStatus(Receive.ACCEPT);
                                peer.setEmail(email);
                                peer.sendHELO();
                                result = "ADDED " + peer + "\n";
                            }
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            ArrayList<Peer> peerSet = Peer.dropAll();
                            if (peerSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (Peer peer : peerSet) {
                                    result += "DROPPED " + peer + "\n";
                                }
                            }
                        } else {
                            Peer peer = Peer.drop(token);
                            result = (peer == null ? "NOT FOUND" : "DROPPED " + peer) + "\n";
                        }
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            ArrayList<Peer> peerList = Peer.getPeerList();
                            if (peerList.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (Peer peer : peerList) {
                                    result += peer + "\n";
                                }
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 3) {
                        String address = tokenizer.nextToken();
                        String send = tokenizer.nextToken();
                        String receive = tokenizer.nextToken();
                        String version = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                        Peer peer = Peer.get(address);
                        if (peer == null) {
                            result = "NOT FOUND " + address + "\n";
                        } else {
                            result = peer + "\n";
                            try {
                                result += (peer.setSendStatus(send) ? "UPDATED" : "ALREADY") + " SEND=" + send + "\n";
                            } catch (ProcessException ex) {
                                result += "NOT RECOGNIZED SEND '" + send + "'\n";
                            }
                            try {
                                result += (peer.setReceiveStatus(receive) ? "UPDATED" : "ALREADY") + " RECEIVE=" + receive + "\n";
                            } catch (ProcessException ex) {
                                result += "NOT RECOGNIZED RECEIVE '" + receive + "'\n";
                            }
                            if (version != null) {
                                try {
                                    result += (peer.setVersion(version) ? "UPDATED" : "ALREADY") + " VERSION=" + version + "\n";
                                } catch (ProcessException ex) {
                                    result += "NOT RECOGNIZED VERSION '" + version + "'\n";
                                }
                            }
                            peer.sendHELO();
                        }
                    } else if (token.equals("PING") && tokenizer.countTokens() == 1) {
                        String address = tokenizer.nextToken();
                        Peer peer = Peer.get(address);
                        if (peer == null) {
                            result = "NOT FOUND " + address + "\n";
                        } else if (peer.sendHELO()) {
                            result = "HELO SENT TO " + address + "\n";
                        } else {
                            result = "HELO NOT SENT local hostname is invalid\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("GUESS") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") &&  tokenizer.hasMoreTokens()) {
                        // Comando para adicionar um palpite SPF.
                        String domain = tokenizer.nextToken();
                        int beginIndex = command.indexOf('"') + 1;
                        int endIndex = command.lastIndexOf('"');
                        if (beginIndex > 0 && endIndex > beginIndex) {
                            String spf = command.substring(beginIndex, endIndex);
                            boolean added = SPF.addGuess(domain, spf);
                            result = (added ? "ADDED" : "REPLACED") + "\n";
                            SPF.storeGuess();
                            SPF.storeSPF();
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> guessSet = SPF.dropAllGuess();
                            if (guessSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String guess : guessSet) {
                                    result += "DROPPED " + guess + "\n";
                                }
                            }
                        } else {
                            boolean droped = SPF.dropGuess(token);
                            result = (droped ? "DROPPED" : "NOT FOUND") + "\n";
                        }
                        SPF.storeGuess();
                        SPF.storeSPF();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String guess : SPF.getGuessSet()) {
                            result += guess + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("REPUTATION")) {
                    // Comando para verificar a reputação dos tokens.
                    StringBuilder stringBuilder = new StringBuilder();
                    TreeMap<String,Distribution> distributionMap;
                    TreeMap<String,Binomial> binomialMap;
                    if (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            distributionMap = SPF.getDistributionMap();
                            binomialMap = null;
                        } else if (token.equals("IPV4")) {
                            distributionMap = SPF.getDistributionMapIPv4();
                            binomialMap = null;
                        } else if (token.equals("IPV6")) {
                            distributionMap = SPF.getDistributionMapIPv6();
                            binomialMap = null;
//                        } else if (token.equals("CIDR")) {
//                            distributionMap = null;
//                            binomialMap = SPF.getDistributionMapExtendedCIDR();
                        } else {
                            distributionMap = null;
                            binomialMap = null;
                        }
                    } else {
                        distributionMap = SPF.getDistributionMap();
                        binomialMap = null;
                    }
                    if (distributionMap != null) {
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
                                stringBuilder.append(Core.DECIMAL_FORMAT.format(probability));
                                stringBuilder.append(' ');
                                stringBuilder.append(distribution.getFrequencyLiteral());
                                stringBuilder.append('\n');
                            }
                            result = stringBuilder.toString();
                        }
                    } else if (binomialMap != null) {
                        if (binomialMap.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String tokenReputation : binomialMap.keySet()) {
                                Binomial binomial = binomialMap.get(tokenReputation);
                                float probability = binomial.getSpamProbability();
                                Status status = binomial.getStatus();
                                stringBuilder.append(tokenReputation);
                                stringBuilder.append(' ');
                                stringBuilder.append(status);
                                stringBuilder.append(' ');
                                stringBuilder.append(Core.DECIMAL_FORMAT.format(probability));
                                stringBuilder.append(' ');
                                stringBuilder.append(binomial.getFrequencyLiteral());
                                stringBuilder.append('\n');
                            }
                            result = stringBuilder.toString();
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (token.equals("CLEAR") && tokenizer.countTokens() == 1) {
                    try {
                        token = tokenizer.nextToken();
                        TreeSet<String> clearSet = SPF.clear(token);
                        if (clearSet.isEmpty()) {
                            result += "NONE\n";
                        } else {
                            for (String value : clearSet) {
                                if (Ignore.contains(value)) {
                                    Peer.clearReputation(value);
                                }
                                result += value + '\n';
                            }
                        }
                        if (isValidIP(token)) {
                            InetAddress address = InetAddress.getByName(token);
                            Period period = ServerHTTP.removePeriod(address.getHostAddress());
                            if (period != null) {
                                result += "HTTP " + period + '\n';
                            }
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                        result += ex.getMessage() + "\n";
                    }
                } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                    // Comando para apagar registro em cache.
                    while (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Owner.isOwnerID(token)) {
                            Owner.removeOwner(token);
                            result += "OK\n";
                        } else if (isValidIPv4(token)) {
                            SubnetIPv4.removeSubnet(token);
                            result += "OK\n";
                        } else if (isValidIPv6(token)) {
                            SubnetIPv6.removeSubnet(token);
                            result += "OK\n";
                        } else if (Domain.containsDomain(token)) {
                            Domain.removeDomain(token);
                            result += "OK\n";
                        } else {
                            result += "UNDEFINED\n";
                        }
                    }
                } else if (token.equals("REFRESH") && tokenizer.hasMoreTokens()) {
                    // Comando para atualizar registro em cache.
                    while (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Owner.isOwnerID(token)) {
                            Owner.refreshOwner(token);
                            result += "OK\n";
                        } else if (isValidIPv4(token)) {
                            SubnetIPv4.refreshSubnet(token);
                            result += "OK\n";
                        } else if (isValidIPv6(token)) {
                            SubnetIPv6.refreshSubnet(token);
                        } else if (Domain.containsDomain(token)) {
                            Domain.refreshDomain(token);
                            result += "OK\n";
                        } else {
                            result += "UNDEFINED\n";
                        }
                    }
                } else {
                    result = "INVALID COMMAND\n";
                }
            }
            return result;
        } catch (ProcessException ex) {
            Server.logError(ex.getCause());
            return ex.getMessage() + "\n";
        } catch (SocketException ex) {
            return "INTERRUPTED\n";
        } catch (Exception ex) {
            Server.logError(ex);
            return "ERROR: FATAL\n";
        }
    }
    
    @Override
    protected void close() throws Exception {
        if (SERVERS != null) {
            Server.logInfo("unbinding ADMINS on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logInfo("unbinding ADMIN on port " + PORT + "...");
        SERVER.close();
    }
}
