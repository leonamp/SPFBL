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
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
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
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.dns.QueryDNS;
import net.spfbl.dns.Zone;
import net.spfbl.spf.SPF;
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
        setPriority(Thread.MIN_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding administration TCP socket on port " + port + "...");
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
                    Server.logDebug("interrupted " + getName() + " connection.");
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
                        Server.logDebug("system killed.");
                        System.exit(1);
                    }
                }
            }
        } catch (SocketException ex) {
            // Conexão fechada externamente pelo método close().
            Server.logDebug("listening stoped.");
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
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
                    Server.logDebug("interrupted " + getName() + " connection.");
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
                        Server.logDebug("system killed.");
                        System.exit(1);
                    }
                }
            }
        } catch (SocketException ex) {
            // Conexão fechada externamente pelo método close().
            Server.logDebug("ADMINS listening stoped.");
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
                    ///
                    SNIHostName serverName = new SNIHostName(HOSTNAME);
                    ArrayList<SNIServerName> serverNames = new ArrayList<>(1);
                    serverNames.add(serverName);
                    ///
                    try {
                        Server.logDebug("binding ADMINS socket on port " + PORTS + "...");
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
                    } else if (Subnet.isValidIP(token)) {
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
                    } else if (SubnetIPv4.isValidCIDRv4(token)) {
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
                    } else if (SubnetIPv6.isValidCIDRv6(token)) {
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
                    } else if (Domain.isHostname(token)) {
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
                        } else if (Domain.isDomain(hostname)) {
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
                                if (Analise.isRunning() && Block.tryAdd(hostname)) {
                                    Server.logDebug("new BLOCK '" + hostname + "' added by 'NXDOMAIN'.");
                                }
                                result = "NXDOMAIN\n";
                            } else if (ipSet.isEmpty()) {
                                if (Analise.isRunning() && Block.tryAdd(hostname)) {
                                    Server.logDebug("new BLOCK '" + hostname + "' added by 'NONE'.");
                                }
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
                    } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
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
                } else if (token.equals("DUMP") && !tokenizer.hasMoreTokens()) {
                    StringBuilder builder = new StringBuilder();
                    builder.append("BLOCK DROP ALL\n");
                    for (String block : Block.getAll()) {
                        builder.append("BLOCK ADD ");
                        builder.append(block);
                        builder.append('\n');
                    }
                    builder.append("CLIENT DROP ALL\n");
                    for (Client clientLocal : Client.getSet()) {
                        builder.append("CLIENT ADD ");
                        builder.append(clientLocal.getCIDR());
                        builder.append(' ');
                        builder.append(clientLocal.getDomain());
                        builder.append(' ');
                        builder.append(clientLocal.getPermission().name());
                        if (clientLocal.hasEmail()) {
                            builder.append(' ');
                            builder.append(clientLocal.getEmail());
                        }
                        builder.append('\n');
                    }
                    builder.append("DNSBL DROP ALL\n");
                    builder.append("DNSWL DROP ALL\n");
                    for (Zone zone : QueryDNS.getValues()) {
                        if (zone.isDNSBL()) {
                            builder.append("DNSBL ADD ");
                        } else if (zone.isURIBL()) {
                            builder.append("URIBL ADD ");
                        } else if (zone.isDNSWL()) {
                            builder.append("DNSWL ADD ");
                        }
                        builder.append(zone.getHostName());
                        builder.append(' ');
                        builder.append(zone.getMessage());
                        builder.append('\n');
                    }
                    builder.append("GUESS DROP ALL\n");
                    HashMap<String,String> guessMap = SPF.getGuessMap();
                    for (String domain : guessMap.keySet()) {
                        String guess = guessMap.get(domain);
                        builder.append("GUESS ADD ");
                        builder.append(domain);
                        builder.append(" \"");
                        builder.append(guess);
                        builder.append("\"\n");
                    }
                    builder.append("IGNORE DROP ALL\n");
                    for (String ignore : Ignore.getAll()) {
                        builder.append("IGNORE ADD ");
                        builder.append(ignore);
                        builder.append('\n');
                    }
                    builder.append("PEER DROP ALL\n");
                    for (Peer peer : Peer.getSet()) {
                        builder.append("PEER ADD ");
                        builder.append(peer.getAddress());
                        builder.append(':');
                        builder.append(peer.getPort());
                        builder.append(' ');
                        builder.append(peer.getSendStatus().name());
                        builder.append(' ');
                        builder.append(peer.getReceiveStatus().name());
                        if (peer.hasEmail()) {
                            builder.append(' ');
                            builder.append(peer.getEmail());
                        }
                        builder.append('\n');
                    }
                    builder.append("PROVIDER DROP ALL\n");
                    for (String provider : Provider.getAll()) {
                        builder.append("PROVIDER ADD ");
                        builder.append(provider);
                        builder.append('\n');
                    }
                    builder.append("TLD DROP ALL\n");
                    for (String tld : Domain.getTLDSet()) {
                        builder.append("TLD ADD ");
                        builder.append(tld);
                        builder.append('\n');
                    }
                    builder.append("TRAP DROP ALL\n");
                    for (String trap : Trap.getTrapAllSet()) {
                        Long time = Trap.getTime(trap);
                        builder.append("TRAP ADD ");
                        builder.append(trap);
                        builder.append(' ');
                        builder.append(time);
                        builder.append('\n');
                    }
                    builder.append("USER DROP ALL\n");
                    for (User userLocal : User.getSet()) {
                        builder.append("USER ADD ");
                        builder.append(userLocal.getEmail());
                        builder.append(' ');
                        builder.append(userLocal.getName());
                        builder.append('\n');
                    }
                    builder.append("WHITE DROP ALL\n");
                    for (String white : White.getAll()) {
                        builder.append("WHITE ADD ");
                        builder.append(white);
                        builder.append('\n');
                    }
                    builder.append("STORE\n");
                    result = builder.toString();
                } else if (token.equals("FIREWALL") && !tokenizer.hasMoreTokens()) {
                    String iface = Core.getInterface();
                    HashMap<Object,TreeSet<Client>> clientMap;
                    StringBuilder builder = new StringBuilder();
                    builder.append("#!/bin/bash\n");
                    builder.append("# \n");
                    builder.append("# Firewall for SPFBL service.\n");
                    builder.append("# Author: Leandro Carlos Rodrigues <leandro@spfbl.net>\n");
                    builder.append("# Author: Alexandre Pereira Bühler <alexandre@simaoebuhler.com.br>\n");
                    builder.append("# \n");
                    builder.append("\n");
                    builder.append("# Flush all rules and create the SPFBL chain.\n");
                    builder.append("iptables -t filter -F SPFBL\n");
                    builder.append("ip6tables -t filter -F SPFBL\n");
                    builder.append("\n");
                    builder.append("iptables -t filter -D INPUT -j SPFBL\n");
                    builder.append("ip6tables -t filter -D INPUT -j SPFBL\n");
                    builder.append("\n");
                    builder.append("iptables -t filter -X SPFBL\n");
                    builder.append("ip6tables -t filter -X SPFBL\n");
                    builder.append("\n");
                    builder.append("iptables -t filter -N SPFBL\n");
                    builder.append("ip6tables -t filter -N SPFBL\n");
                    builder.append("\n");
                    builder.append("iptables -t filter -I INPUT 1 -j SPFBL\n");
                    builder.append("ip6tables -t filter -I INPUT 1 -j SPFBL\n");
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
                            if (SubnetIPv4.isValidCIDRv4(cidr)) {
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
                            } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
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
                    if (Core.hasPortWHOIS()) {
                        builder.append("### SPFBL WHOIS\n\n");
                        builder.append("# Log and drop all others.\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport \n");
                        builder.append(Core.getPortWHOIS());
                        builder.append(" -j LOG --log-prefix \"WHOIS \"\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport \n");
                        builder.append(Core.getPortWHOIS());
                        builder.append(" -j LOG --log-prefix \"WHOIS \"\n");
                        builder.append("iptables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortWHOIS());
                        builder.append(" -j DROP\n");
                        builder.append("ip6tables -t filter -A SPFBL -p tcp --dport ");
                        builder.append(Core.getPortWHOIS());
                        builder.append(" -j DROP\n\n");
                    }
                    if (Core.hasPortHTTP()) {
                        builder.append("### SPFBL HTTP\n\n");
                        builder.append("iptables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTP());
                        builder.append(" -j ACCEPT\n");
                    }
                    if (Core.hasPortHTTPS()) {
                        builder.append("iptables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTPS());
                        builder.append(" -j ACCEPT\n");
                        builder.append("ip6tables -t filter -A SPFBL");
                        builder.append(" -p tcp --dport ");
                        builder.append(Core.getPortHTTPS());
                        builder.append(" -j ACCEPT\n");
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
                            if (SubnetIPv4.isValidCIDRv4(cidr)) {
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
                            } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
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
                                if (SubnetIPv4.isValidCIDRv4(cidr)) {
                                    builder.append("iptables -t filter -A SPFBL");
                                    builder.append(" -s ");
                                    builder.append(clientLocal.getCIDR());
                                    builder.append(" -p udp --dport ");
                                    builder.append(Core.getPortDNSBL());
                                    builder.append(" -j DROP\n");
                                } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
                                    builder.append("ip6tables -t filter -A SPFBL");
                                    builder.append(" -s ");
                                    builder.append(clientLocal.getCIDR());
                                    builder.append(" -p udp --dport ");
                                    builder.append(Core.getPortDNSBL());
                                    builder.append(" -j DROP\n");
                                }
                            }
                            builder.append("\n");
                        }
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
                    if (Subnet.isValidCIDR(token)) {
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
                } else if (token.equals("SHUTDOWN") && !tokenizer.hasMoreTokens()) {
                    // Comando para finalizar o serviço.
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
                        if (QueryDNS.addDNSBL(hostname, message)) {
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
                        if (QueryDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : QueryDNS.dropAllDNSBL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = QueryDNS.dropDNSBL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = QueryDNS.getDNSBLMap();
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
                        if (QueryDNS.addURIBL(hostname, message)) {
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
                        if (QueryDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : QueryDNS.dropAllURIBL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = QueryDNS.dropURIBL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = QueryDNS.getURIBLMap();
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
                        if (QueryDNS.addDNSWL(hostname, message)) {
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
                        if (QueryDNS.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (Zone zone : QueryDNS.dropAllDNSWL()) {
                                    result += "DROPPED " + zone + "\n";
                                }
                            } else {
                                Zone zone = QueryDNS.dropDNSWL(token);
                                if (zone == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPPED " + zone + "\n";
                                }
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,Zone> map = QueryDNS.getDNSWLMap();
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
                        if (Domain.isValidEmail(token)) {
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
                            Server.logDebug("new BLOCK '" + token + "' added by 'SUSPECT'.");
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
                                String blockedToken = tokenizer.nextToken();
                                int index = blockedToken.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = blockedToken.substring(0, index);
                                    if (Domain.isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        blockedToken = blockedToken.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && (blockedToken = Block.add(blockedToken)) != null) {
                                    Peer.sendBlockToAll(blockedToken);
                                    result += "ADDED\n";
                                } else if (clientLocal != null && Block.add(clientLocal, blockedToken)) {
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
                            if (tokenizer.hasMoreTokens()) {
                                result = "INVALID COMMAND\n";
                            } else {
                                if (Block.dropAll()) {
                                    result += "DROPPED\n";
                                } else {
                                    result += "EMPTY\n";
                                }
                            }
                        } else {
                            do {
                                try {
                                    int index = token.indexOf(':');
                                    String clientLocal = null;
                                    if (index != -1) {
                                        String prefix = token.substring(0, index);
                                        if (Domain.isValidEmail(prefix)) {
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
                            } while (tokenizer.hasMoreElements());
                            if (result.length() == 0) {
                                result = "INVALID COMMAND\n";
                            }
                        }
                    } else if (token.equals("OVERLAP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Subnet.isValidCIDR(token)) {
                            String cidr = token;
                            if (Block.overlap(cidr)) {
                                result = "ADDED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("EXTRACT") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Subnet.isValidIP(token)) {
                            String ip = Subnet.normalizeIP(token);
                            int mask = SubnetIPv4.isValidIPv4(ip) ? 32 : 128;
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
                                if (Domain.isValidEmail(prefix)) {
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
                            do {
                                try {
                                    if (Generic.dropGeneric(token)) {
                                        result += "DROPPED\n";
                                    } else {
                                        result += "NOT FOUND\n";
                                    }
                                } catch (ProcessException ex) {
                                    result += ex.getMessage() + "\n";
                                }
                            } while (tokenizer.hasMoreElements());
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
                            do {
                                try {
                                    if (Generic.dropDynamic(token)) {
                                        result += "DROPPED\n";
                                    } else {
                                        result += "NOT FOUND\n";
                                    }
                                } catch (ProcessException ex) {
                                    result += ex.getMessage() + "\n";
                                }
                            } while (tokenizer.hasMoreElements());
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
                } else if (token.equals("WHITE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String whiteToken = tokenizer.nextToken();
                                int index = whiteToken.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = whiteToken.substring(0, index);
                                    if (Domain.isValidEmail(prefix)) {
                                        clientLocal = prefix;
                                        whiteToken = whiteToken.substring(index+1);
                                    }
                                }
                                if (clientLocal == null && White.add(whiteToken)) {
                                    result += "ADDED\n";
                                } else if (clientLocal != null && White.add(clientLocal, whiteToken)) {
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
                    } else if (token.equals("SENDER") && tokenizer.hasMoreTokens()) {
                        String userEmail = null;
                        String sender = tokenizer.nextToken();
                        int index = sender.indexOf(':');
                        if (index != -1) {
                            String prefix = sender.substring(0, index);
                            if (Domain.isValidEmail(prefix)) {
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
                                if (Provider.containsExact(mx)) {
                                    token = sender;
                                } else {
                                    token = mx;
                                }
                                if (White.add(userEmail, token)) {
                                    result = "ADDED " + userEmail + ":" + token + ";PASS\n";
                                } else {
                                    result = "ALREADY EXISTS " + userEmail + ":" + token + ";PASS\n";
                                }
                            }
                        } else {
                            result = "INVALID COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> whiteSet = White.dropAll();
                            if (whiteSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String white : whiteSet) {
                                    result += "DROPPED " + white + "\n";
                                }
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String clientLocal = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (Domain.isValidEmail(prefix)) {
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
                                if (Domain.isValidEmail(prefix)) {
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
                                    if (Domain.isValidEmail(prefix)) {
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
                                if (Domain.isValidEmail(prefix)) {
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
                                    if (Domain.isValidEmail(prefix)) {
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
                            for (String sender : Trap.getInexistentSet()) {
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
                                for (String sender : Trap.getInexistentAllSet()) {
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
                } else if (token.equals("SPLIT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (Subnet.isValidCIDR(token)) {
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
                        } else if (Subnet.isValidCIDR(token)) {
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
                            } else if (Subnet.isValidIP(token)) {
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
                        if (Subnet.isValidCIDR(token) && tokenizer.hasMoreTokens()) {
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
                            } else if (token.equals("PERSONALITY") && tokenizer.countTokens() == 1) {
                                String personality = tokenizer.nextToken();
                                if (clientLocal.setPersonality(personality)) {
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
                                } else if (token.equals("GRACE") && tokenizer.countTokens() == 1) {
                                    token = tokenizer.nextToken();
                                    if (clientLocal.setActionGRACE(token)) {
                                        result = "UPDATED " + clientLocal + "\n";
                                    } else {
                                        result = "ALREADY THIS VALUE\n";
                                    }
                                } else {
                                    result = "INVALID COMMAND\n";
                                }
                            } else if (Domain.isHostname(token) && tokenizer.hasMoreTokens()) {
                                String domain = Domain.extractDomain(token, false);
                                String permission = tokenizer.nextToken();
                                String email = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                if (tokenizer.hasMoreTokens()) {
                                    result = "INVALID COMMAND\n";
                                } else if (email != null && !Domain.isValidEmail(email)) {
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
                        String email = tokenizer.nextToken();
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
                            TreeSet<User> userSet = User.dropAll();
                            if (userSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (User userLocal : userSet) {
                                    result += "DROPPED " + userLocal + "\n";
                                }
                            }
                        } else {
                            User userLocal = User.drop(token);
                            if (userLocal == null) {
                                result = "NOT FOUND\n";
                            } else {
                                result = "DROPPED " + userLocal + "\n";
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (User userLocal : User.getSet()) {
                            result += userLocal + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else if (token.equals("SET") && tokenizer.hasMoreElements()) {
                        token = tokenizer.nextToken();
                        if (Domain.isValidEmail(token)) {
                            User user = User.get(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else if (tokenizer.hasMoreElements()) {
                                token = tokenizer.nextToken();
                                if (token.equals("LOCALE") && tokenizer.hasMoreElements()) {
                                    token = tokenizer.nextToken();
                                    if (user.setLocale(token)) {
                                        result = "CHANGED TO " + user.getLocale() + "\n";
                                    } else {
                                        result = "NOT CHANGED\n";
                                    }
//                                } else if (token.equals("LOCAL") && tokenizer.hasMoreElements()) {
//                                    token = tokenizer.nextToken();
//                                    if (token.equals("TRUE")) {
//                                        user.setLocal(true);
//                                        result = "OK\n";
//                                    } else if (token.equals("FALSE")) {
//                                        user.setLocal(false);
//                                        result = "OK\n";
//                                    } else {
//                                        result = "INVALID COMMAND\n";
//                                    }
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
                        if (Domain.isValidEmail(token)) {
                            User user = User.get(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else if (tokenizer.hasMoreElements()) {
                                token = tokenizer.nextToken();
                                if (token.equals("TOTP") && !tokenizer.hasMoreElements()) {
                                    if (user.sendTOTP()) {
                                        result = "TOTP SENT\n";
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
                        } else if (email != null && !Domain.isValidEmail(email)) {
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
                            TreeSet<Peer> peerSet = Peer.dropAll();
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
                            TreeSet<Peer> peerSet = Peer.getSet();
                            if (peerSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (Peer peer : peerSet) {
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
                        } else if (token.equals("CIDR")) {
                            distributionMap = null;
                            binomialMap = SPF.getDistributionMapExtendedCIDR();
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
                    } catch (Exception ex) {
                        result += ex.getMessage() + "\n";
                    }
                } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                    // Comando para apagar registro em cache.
                    while (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Owner.isOwnerID(token)) {
                            Owner.removeOwner(token);
                            result += "OK\n";
                        } else if (SubnetIPv4.isValidIPv4(token)) {
                            SubnetIPv4.removeSubnet(token);
                            result += "OK\n";
                        } else if (SubnetIPv6.isValidIPv6(token)) {
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
                        } else if (SubnetIPv4.isValidIPv4(token)) {
                            SubnetIPv4.refreshSubnet(token);
                            result += "OK\n";
                        } else if (SubnetIPv6.isValidIPv6(token)) {
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
            Server.logDebug("unbinding ADMINS on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logDebug("unbinding ADMIN on port " + PORT + "...");
        SERVER.close();
    }
}
