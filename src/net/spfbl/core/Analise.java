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

import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import net.spfbl.data.Block;
import net.spfbl.data.Ignore;
import net.spfbl.data.Provider;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;

/**
 * Análise de listas de IP.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Analise implements Comparable<Analise> {

    private final String name; // Nome do processo.
    private final TreeSet<String> ipSet = new TreeSet<String>(); // Lista dos IPs a serem analisados.
    private final TreeSet<String> processSet = new TreeSet<String>(); // Lista dos IPs em processamento.
    private final TreeMap<String,String> resultMap = new TreeMap<String,String>(); // Lista dos resultados das anaises.
    
    private Analise(String name) {
        this.name = name;
    }
    
    public synchronized boolean contains(String token) {
        if (Subnet.isValidIP(token)) {
            token = Subnet.normalizeIP(token);
        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        if (ipSet.contains(token)) {
            return true;
        } else if (processSet.contains(token)) {
            return true;
        } else if (resultMap.containsKey(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    public synchronized boolean add(String token) {
        if (Subnet.isValidIP(token)) {
            token = Subnet.normalizeIP(token);
        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        if (ipSet.contains(token)) {
            return false;
        } else if (processSet.contains(token)) {
            return false;
        } else if (resultMap.containsKey(token)) {
            return false;
        } else {
            ipSet.add(token);
            if (SEMAPHORE.tryAcquire()) {
                Process process = new Process();
                process.start();
            }
            return true;
        }
    }
    
    public synchronized TreeSet<String> getResultSet() {
        TreeSet<String> set = new TreeSet<String>();
        for (String ip: ipSet) {
            set.add(ip + " WAITING");
        }
        for (String ip: processSet) {
            set.add(ip + " PROCESSING");
        }
        for (String ip : resultMap.keySet()) {
            String result = resultMap.get(ip);
            set.add(ip + " " + result);
        }
        return set;
    }
    
    public static void dumpAll(StringBuilder builder) {
        for (Analise analise : getAnaliseSet()) {
            analise.dump(builder);
        }
    }
    
    public void dump(StringBuilder builder) {
        for (String line : getResultSet()) {
            builder.append(line);
            builder.append('\n');
        }
    }
    
    private synchronized String pollFirst() {
        String ip = ipSet.pollFirst();
        if (ip == null) {
            return null;
        } else {
            processSet.add(ip);
            return ip;
        }
    }
    
    private boolean isWait() {
        return !ipSet.isEmpty();
    }
    
    private synchronized boolean addResult(String ip, String result) {
        processSet.remove(ip);
        return resultMap.put(ip, result) == null;
    }
    
    private boolean process() {
        String token = pollFirst();
        if (token == null) {
            return false;
        } else {
            StringBuilder builder = new StringBuilder();
            Analise.process(token, builder, 10000);
            String result = builder.toString();
            if (addResult(token, result)) {
                Server.logTrace(token + ' ' + result);
            }
            return true;
        }
    }
    
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof Analise) {
            Analise other = (Analise) o;
            return this.name.equals(other.name);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
    
    @Override
    public int compareTo(Analise other) {
        return this.name.compareTo(other.name);
    }
    
    @Override
    public synchronized String toString() {
        return name + " "
                + ipSet.size() + " "
                + processSet.size() + " "
                + resultMap.size();
    }
    
    /**
     * Fila de processos.
     */
    private static final LinkedList<Analise> QUEUE = new LinkedList<Analise>();
    /**
     * Mapa de processos.
     */
    private static final HashMap<String,Analise> MAP = new HashMap<String,Analise>();
    
    public synchronized static TreeSet<Analise> getAnaliseSet() {
        TreeSet<Analise> queue = new TreeSet<Analise>();
        queue.addAll(QUEUE);
        return queue;
    }
    
    public synchronized static TreeSet<String> getNameSet() {
        TreeSet<String> queue = new TreeSet<String>();
        queue.addAll(MAP.keySet());
        return queue;
    }
    
    public synchronized static Analise get(String name, boolean create) {
        Analise analise = MAP.get(name);
        if (analise == null && create) {
            analise = new Analise(name);
            MAP.put(name, analise);
            QUEUE.addLast(analise);
        }
        return analise;
    }
    
    public synchronized static Analise drop(String name) {
        Analise analise;
        if ((analise = MAP.remove(name)) != null) {
            QUEUE.remove(analise);
        }
        return analise;
    }
    
    private synchronized static Analise getNextWait() {
        // Rotaciona para distribuir os processos.
        Analise analise = QUEUE.poll();
        if (analise == null) {
            return null;
        } else {
            QUEUE.offer(analise);
            for (Analise analise2 : QUEUE) {
                if (analise2.isWait()) {
                    return analise2;
                }
            }
            return null;
        }
    }
    
    public static void processToday(String ip) {
        GregorianCalendar calendar = new GregorianCalendar();
        Date today = calendar.getTime();
        calendar.add(Calendar.DAY_OF_YEAR, -1);
        Date yesterday = calendar.getTime();
        String name = Core.SQL_FORMAT.format(yesterday);
        Analise analise = Analise.get(name, false);
        if (analise == null || !analise.contains(ip)) {
            name = Core.SQL_FORMAT.format(today);
            analise = Analise.get(name, true);
            analise.add(ip);
        }
    }
    
    /**
     * Enumeração do status da analise.
     */
    public enum Status {

        WHITE, // Whitelisted
        GRAY, // Graylisted
        BLACK, // Blacklisted
        BLOCK, // Blocked
        DNSBL, // DNS blacklist
        PROVIDER, // Provedor
        IGNORE, // Ignored
        CLOSED, // Closed
//        NOTLS, // Sem TLS
        TIMEOUT, // Timeout
        UNAVAILABLE, // Indisponível
        INVALID, // Reverso inválido
        NXDOMAIN, // Domínio inexistente
        ERROR, // Erro de processamento
        NONE, // Nenhum reverso
        RESERVED, // Domínio reservado
        ;
        
    }
    
    private static Object getResponseSMTP(String host, int port, int timeout) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.starttls.enable", "false");
            props.put("mail.smtp.auth", "false");
            props.put("mail.smtp.timeout", timeout);
            Session session = Session.getInstance(props, null);
            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
            try {
                transport.setLocalHost(Core.getHostname());
                transport.connect(host, port, null, null);
                String response = transport.getLastServerResponse();
                int beginIndex = 4;
                int endIndex;
                for (endIndex = beginIndex; endIndex < response.length(); endIndex++) {
                    if (response.charAt(endIndex) == ' ') {
                        break;
                    } else if (response.charAt(endIndex) == '\n') {
                        break;
                    }
                }
                String helo = response.substring(beginIndex, endIndex);
                if (Domain.isHostname(helo)) {
                    return Domain.normalizeHostname(helo, true);
                } else {
                    return null;
                }
            } finally {
                if (transport.isConnected()) {
                    transport.close();
                }
            }
        } catch (MailConnectException ex) {
            if (ex.getMessage().contains("timeout -1")) {
                return Status.CLOSED;
            } else {
                return Status.TIMEOUT;
            }
        } catch (MessagingException ex) {
//            if (ex.getMessage().contains("TLS")) {
//                return Status.NOTLS;
//            } else {
                return Status.UNAVAILABLE;
//            }
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static void process(
            String token,
            StringBuilder builder,
            int timeout
            ) {
        if (Subnet.isValidIP(token)) {
            processIP(token, builder, timeout);
        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
            processMX(token, builder, timeout);
        }
    }
    
    public static void processMX(
            String address,
            StringBuilder builder,
            int timeout
            ) {
        String host = address.substring(1);
        String tokenAddress = '@' + Domain.normalizeHostname(host, false);
        String tokenMX = Domain.normalizeHostname(host, true);
        Status statusAddress = Status.ERROR;
        Status statusMX = Status.NONE;
        float probability = 0.0f;
        String frequency = "UNDEFINED";
        try {
            Distribution dist;
            Object response;
            for (String mx : Reverse.getMXSet(host)) {
                if (Subnet.isValidIP(mx)) {
                    tokenMX = mx;
                    if (Block.containsCIDR(mx)) {
                        statusMX = Status.BLOCK;
                        break;
                    } else if (Provider.containsCIDR(mx)) {
                        statusMX = Status.PROVIDER;
                        break;
                    } else if (Ignore.containsCIDR(mx)) {
                        statusMX = Status.IGNORE;
                        break;
                    } else if ((response = getResponseSMTP(mx, 25, timeout)) instanceof Status) {
                        statusMX = (Status) response;
                    } else if ((dist = SPF.getDistribution(mx, false)) == null) {
                        tokenMX = (String) response;
                        statusMX = Status.WHITE;
                        break;
                    } else {
                        tokenMX = (String) response;
                        statusMX = Status.valueOf(dist.getStatus(mx).name());
                        break;
                    }
                } else if (Domain.isHostname(mx)) {
                    tokenMX = mx;
                    if (Block.containsDomain(mx)) {
                        statusMX = Status.BLOCK;
                        break;
                    } else if (Provider.containsDomain(mx)) {
                        statusMX = Status.PROVIDER;
                        break;
                    } else if (Ignore.contains(mx)) {
                        statusMX = Status.IGNORE;
                        break;
                    } else if ((response = getResponseSMTP(mx.substring(1), 25, timeout)) instanceof Status) {
                        statusMX = (Status) response;
                    } else if ((dist = SPF.getDistribution(mx, false)) == null) {
                        statusMX = Status.WHITE;
                        break;
                    } else {
                        statusMX = Status.valueOf(dist.getStatus(mx).name());
                        break;
                    }
                }
            }
            if (Block.containsExact(tokenAddress)) {
                statusAddress = Status.BLOCK;
            } else if (Block.containsDomain(host)) {
                statusAddress = Status.BLOCK;
            } else if (Provider.containsExact(tokenAddress)) {
                statusAddress = Status.PROVIDER;
            } else if (Ignore.contains(tokenAddress)) {
                statusAddress = Status.IGNORE;
            } else if ((dist = SPF.getDistribution(tokenAddress, false)) == null) {
                probability = 0.0f;
                statusAddress = Status.WHITE;
                frequency = "UNDEFINED";
            } else {
                probability = dist.getSpamProbability(tokenAddress);
                statusAddress = Status.valueOf(dist.getStatus().name());
                frequency = dist.getFrequencyLiteral();
            }
        } catch (CommunicationException ex) {
            statusAddress = Status.TIMEOUT;
        } catch (ServiceUnavailableException ex) {
            statusAddress = Status.UNAVAILABLE;
        } catch (NameNotFoundException ex) {
            statusAddress = Status.NXDOMAIN;
        } catch (NamingException ex) {
            Server.logError(ex);
        } finally {
            builder.append(statusAddress);
            builder.append(' ');
            builder.append(tokenMX);
            builder.append(' ');
            builder.append(statusMX);
            builder.append(' ');
            builder.append(Core.DECIMAL_FORMAT.format(probability));
            builder.append(' ');
            builder.append(frequency);
            builder.append(' ');
            if (Subnet.isValidIP(tokenMX)) {
                builder.append(Subnet.expandIP(tokenMX));
            } else {
                builder.append(Domain.revert(tokenMX));
            }
        }
    }
    
    public static void processIP(
            String ip,
            StringBuilder builder,
            int timeout
            ) {
        try {
            ip = Subnet.normalizeIP(ip);
            Distribution dist = SPF.getDistribution(ip, false);
            float probability = dist == null ? 0.0f : dist.getSpamProbability(ip);
            Object response = null;
            Status statusIP;
            if (Block.containsCIDR(ip)) {
                statusIP = Status.BLOCK;
            } else if (Provider.containsCIDR(ip)) {
                statusIP = Status.PROVIDER;
            } else if (Ignore.containsCIDR(ip)) {
                statusIP = Status.IGNORE;
            } else if (Block.containsDNSBL(ip)) {
                statusIP = Status.DNSBL;
            } else if ((response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                statusIP = (Status) response;
            } else if (dist == null) {
                statusIP = Status.WHITE;
            } else {
                statusIP = Status.valueOf(dist.getStatus(ip).name());
            }
            LinkedList<String> nameList = new LinkedList<String>();
            try {
                nameList.addAll(Reverse.getPointerSet(ip));
            } catch (NamingException ex) {
                // Fazer nada.
            }
            String tokenName;
            Status statusName;
            if (nameList.isEmpty()) {
                if (response instanceof String) {
                    tokenName = (String) response;
                    statusName = Status.INVALID;
                    nameList.addLast(tokenName);
                } else{
                    tokenName = ip;
                    statusName = Status.NONE;
                }
            } else {
                tokenName = nameList.getFirst();
                statusName = Status.INVALID;
            }
            for (String name : nameList) {
                if (Block.containsDomain(name)) {
                    tokenName = name;
                    statusName = Status.BLOCK;
                    break;
                } else if (Block.containsREGEX(name)) {
                    tokenName = name;
                    statusName = Status.BLOCK;
                    break;
                } else if (Block.containsWHOIS(name)) {
                    tokenName = name;
                    statusName = Status.BLOCK;
                    break;
                } else {
                    try {
                        if (Reverse.getAddressSet(name).contains(ip)) {
                            if (Provider.containsDomain(name)) {
                                tokenName = name;
                                statusName = Status.PROVIDER;
                                break;
                            } else if (Ignore.contains(name)) {
                                tokenName = name;
                                statusName = Status.IGNORE;
                                break;
                            } else {
                                tokenName = name;
                                Distribution distribution2 = SPF.getDistribution(name, false);
                                if (distribution2 == null) {
                                    statusName = Status.WHITE;
                                } else {
                                    statusName = Status.valueOf(distribution2.getStatus(name).name());
                                    statusName = statusName == Status.BLOCK ? Status.BLACK : statusName;
                                }
                            }
                        }
                    } catch (NamingException ex) {
                        // Fazer nada.
                    }
                }
            }
            if (statusName == Status.INVALID) {
                try {
                    String domain = Domain.extractDomain(tokenName, true);
                    if (!Reverse.hasValidNameServers(domain)) {
                        if (Block.addExact(domain)) {
                            statusName = Status.BLOCK;
                            Server.logDebug("new BLOCK '" + domain + "' added by NXDOMAIN.");
                        }
                    }
                } catch (NamingException ex) {
                    // Fazer nada.
                } catch (ProcessException ex) {
                    if (ex.isErrorMessage("RESERVED")) {
                        statusName = Status.RESERVED;
                    } else {
                        Server.logError(ex);
                    }
                }
            }
            if (statusIP != Status.BLOCK && statusIP != Status.DNSBL && (statusName == Status.BLOCK || statusName == Status.NONE || statusName == Status.RESERVED)) {
                String block;
                if ((block = Block.add(ip)) != null) {
                    statusIP = Status.BLOCK;
                    Server.logDebug("new BLOCK '" + block + "' added by '" + tokenName + ";" + statusName + "'.");
                }
            } else if (statusIP == Status.BLOCK && (statusName == Status.PROVIDER || statusName == Status.IGNORE)) {
                String cidr;
                int mask = SubnetIPv4.isValidIPv4(ip) ? 32 : 64;
                if ((cidr = Block.clearCIDR(ip, mask)) != null) {
                    Server.logDebug("false positive BLOCK '" + cidr + "' detected by '" + tokenName + ";" + statusName + "'.");
                }
                if (Provider.containsCIDR(ip)) {
                    statusIP = Status.PROVIDER;
                } else if (Ignore.containsCIDR(ip)) {
                    statusIP = Status.IGNORE;
                } else if (Block.containsDNSBL(ip)) {
                    statusIP = Status.DNSBL;
                } else if ((response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (dist == null) {
                    statusIP = Status.WHITE;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
                }
            } else if (statusIP == Status.BLOCK && statusName == Status.WHITE && probability == 0.0f) {
                String result = Reverse.getResult(ip, "list.dnswl.org");
                if (result != null && !result.equals("127.0.0.255")) {
                    String cidr;
                    int mask = SubnetIPv4.isValidIPv4(ip) ? 32 : 64;
                    if ((cidr = Block.clearCIDR(ip, mask)) != null) {
                        Server.logDebug("false positive BLOCK '" + cidr + "' detected by 'list.dnswl.org;" + result + "'.");
                    }
                    if (Provider.containsCIDR(ip)) {
                        statusIP = Status.PROVIDER;
                    } else if (Ignore.containsCIDR(ip)) {
                        statusIP = Status.IGNORE;
                    } else if (Block.containsDNSBL(ip)) {
                        statusIP = Status.DNSBL;
                    } else if ((response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                        statusIP = (Status) response;
                    } else {
                        statusIP = Status.WHITE;
                    }
                }
            }
            builder.append(statusIP);
            builder.append(' ');
            builder.append(tokenName);
            builder.append(' ');
            builder.append(statusName);
            builder.append(' ');
            builder.append(Core.DECIMAL_FORMAT.format(probability));
            builder.append(' ');
            builder.append(dist == null ? "UNDEFINED" : dist.getFrequencyLiteral());
            builder.append(' ');
            if (Subnet.isValidIP(tokenName)) {
                builder.append(Subnet.expandIP(tokenName));
            } else {
                builder.append(Domain.revert(tokenName));
            }
        } catch (Exception ex) {
            builder.append("ERROR");
            Server.logError(ex);
        }
    }

    private static final int MAX = 256;
    private static final Semaphore SEMAPHORE = new Semaphore(MAX);
    private static boolean run = true;
    
    public static void interrupt() {
        run = false;
        int count = MAX;
        while (count > 0) {
            try {
                SEMAPHORE.acquire();
                count--;
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
    }

    private class Process extends Thread {
        private Process() {
            super("ANALISEPS");
            super.setPriority(MIN_PRIORITY);
        }
        @Override
        public void run() {
            try {
                Analise analise;
                while (run && (analise = getNextWait()) != null) {
                    analise.process();
                }
            } finally {
                SEMAPHORE.release();
            }
        }
    }
}
