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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
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
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.Provider;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Análise de listas de IP.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Analise implements Serializable, Comparable<Analise> {
    
    private static final long serialVersionUID = 1L;

    private static byte ANALISE_EXPIRES = 0;
    private static boolean ANALISE_IP = false;
    private static boolean ANALISE_MX = false;
    private static boolean CHANGED = false;
    
    public static synchronized void setAnaliseExpires(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setAnaliseExpires(Integer.parseInt(expires));
            } catch (Exception ex) {
                setAnaliseExpires(-1);
            }
        }
    }
    
    public static synchronized void setAnaliseExpires(int expires) {
        if (expires < 0 || expires > Byte.MAX_VALUE) {
            Server.logError("invalid analise expires integer value '" + expires + "'.");
        } else {
            ANALISE_EXPIRES = (byte) expires;
        }
    }
    
    public static synchronized void setAnaliseIP(String analise) {
        try {
            ANALISE_IP = Boolean.parseBoolean(analise);
        } catch (Exception ex) {
            Server.logError("invalid analise IP boolean set '" + analise + "'.");
        }
    }
    
    public static synchronized void setAnaliseMX(String analise) {
        try {
            ANALISE_MX = Boolean.parseBoolean(analise);
        } catch (Exception ex) {
            Server.logError("invalid analise MX boolean set '" + analise + "'.");
        }
    }
    
    private final String name; // Nome do processo.
    private final TreeSet<String> ipSet = new TreeSet<String>(); // Lista dos IPs a serem analisados.
    private final TreeSet<String> processSet = new TreeSet<String>(); // Lista dos IPs em processamento.
    
    private TreeMap<String,String> resultMap = null; // Obsoleto.
    private TreeSet<String> resultSet = new TreeSet<String>(); // Lista dos resultados das analises.
    private transient FileWriter resultWriter = null;
    
    private long last = System.currentTimeMillis();
    
    private Analise(String name) {
        this.name = normalizeName(name);
    }
    
    private synchronized Analise duplicate() {
        Analise clone = new Analise(this.name);
        clone.ipSet.addAll(this.ipSet);
        clone.processSet.addAll(this.processSet);
        clone.resultSet.addAll(this.resultSet);
        clone.last = this.last;
        return clone;
    }
    
    public String getName(){
        try {
            return URLDecoder.decode(name, "UTF-8");
        } catch (Exception ex) {
            Server.logError(ex);
            return name;
        }
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
        } else if (resultSet.contains(token)) {
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
        } else if (resultSet.contains(token)) {
            return false;
        } else if (run && ipSet.add(token)) {
            if (SEMAPHORE.tryAcquire()) {
                Process process = new Process();
                process.start();
            }
            last = System.currentTimeMillis();
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    public static void initProcess() {
        while (SEMAPHORE.tryAcquire()) {
            Process process = new Process();
            process.start();
        }
    }
    
    private File getResultFile() {
        return new File("./data/" + name + ".csv");
    }
    
    public synchronized TreeSet<String> getResultSet() {
        TreeMap<String,String> map = new TreeMap<String,String>();
        for (String ip: ipSet) {
            map.put(ip, "WAITING");
        }
        for (String ip: processSet) {
            map.put(ip, "PROCESSING");
        }
        for (String ip: resultSet) {
            map.put(ip, "LOST");
        }
        File resultFile = getResultFile();
        if (resultFile.exists()) {
            try {
                FileReader fileReader = new FileReader(resultFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                try {
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        int index = line.indexOf(' ');
                        String ip = line.substring(0, index);
                        if (resultSet.contains(ip)) {
                            String result = line.substring(index+1);
                            map.put(ip, result);
                        }
                    }
                } finally {
                    bufferedReader.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        TreeSet<String> set = new TreeSet<String>();
        for (String ip : map.keySet()) {
            String result = map.get(ip);
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
            CHANGED = true;
            return ip;
        }
    }
    
    private synchronized boolean dropProcess(String token) {
        return processSet.remove(token);
    }
    
    public static void dropExpired() {
        for (String name : getNameSet()) {
            Analise analise = get(name, false);
            if (analise != null && analise.isExpired() && drop(name) != null) {
                Server.logDebug("analise list '" + name + "' was dropped by expiration.");
            }
        }
    }
    
    /**
     * Verifica se o registro atual expirou.
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isExpired() {
        int time = (int) (System.currentTimeMillis() - last) / Server.DAY_TIME;
        return time >= ANALISE_EXPIRES;
    }
    
    private boolean isWait() {
        return !ipSet.isEmpty();
    }
    
    private synchronized boolean addResult(String ip, String result) {
        try {
            if (processSet.remove(ip) && resultSet.add(ip)) {
                CHANGED = true;
                if (resultWriter == null) {
                    File resultFile = getResultFile();
                    resultWriter = new FileWriter(resultFile, true);
                }
                resultWriter.write(ip + " " + result + "\n");
                resultWriter.flush();
                if (ipSet.isEmpty() && processSet.isEmpty()) {
                    resultWriter.close();
                    resultWriter = null;
                }
                return true;
            } else {
                return false;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
//        return resultMap.put(ip, result) == null;
    }
    
    private boolean process() {
        if (run) {
            String token = pollFirst();
            if (token == null) {
                return false;
            } else if (Subnet.isValidIP(token) && Subnet.isReservedIP(token)) {
                dropProcess(token);
                return false;
            } else {
                StringBuilder builder = new StringBuilder();
                Analise.process(token, builder, 20000);
                String result = builder.toString();
                if (addResult(token, result)) {
//                    Server.logTrace(token + ' ' + result);
                }
                return true;
            }
        } else {
            return false;
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
        return this.getName().compareTo(other.getName());
    }
    
    @Override
    public synchronized String toString() {
        return getName() + " "
                + ipSet.size() + " "
                + processSet.size() + " "
                + resultSet.size();
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
    
    public static TreeSet<Analise> getAnaliseCloneSet() {
        TreeSet<Analise> queue = new TreeSet<Analise>();
        for (String name : getNameSet()) {
            Analise analise = get(name, false);
            if (analise != null) {
                queue.add(analise.duplicate());
            }
        }
        return queue;
    }
    
    public synchronized static TreeSet<String> getNameSet() {
        TreeSet<String> queue = new TreeSet<String>();
        for (String name : MAP.keySet()) {
            try {
                name = URLDecoder.decode(name, "UTF-8");
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                queue.add(name);
            }
        }
        return queue;
    }
    
    private static String normalizeName(String name) {
        if (name == null) {
            return null;
        } else {
            try {
                name = name.trim();
                name = name.replace(' ', '_');
                name = URLEncoder.encode(name, "UTF-8");
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                return name;
            }
        }
    }
    
    public synchronized static Analise get(String name, boolean create) {
        name = normalizeName(name);
        Analise analise = MAP.get(name);
        if (analise == null && create) {
            analise = new Analise(name);
            MAP.put(name, analise);
            QUEUE.addLast(analise);
        }
        return analise;
    }
    
    public synchronized static void add(Analise analise) {
        Analise analiseDropped = MAP.put(analise.name, analise);
        if (analiseDropped != null) {
            QUEUE.remove(analiseDropped);
        }
        QUEUE.add(analise);
    }
    
    public synchronized static Analise drop(String name) {
        name = normalizeName(name);
        Analise analise;
        if ((analise = MAP.remove(name)) != null) {
            analise.ipSet.clear();
            analise.processSet.clear();
            if (analise.resultWriter != null) {
                try {
                    analise.resultWriter.close();
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            File resultFile = analise.getResultFile();
            if (!resultFile.delete()) {
                resultFile.deleteOnExit();
            }
            QUEUE.remove(analise);
            CHANGED = true;
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
    
    public static void processToday(String token) {
        if (ANALISE_EXPIRES > 0) {
            boolean process;
            if (token == null) {
                process = false;
            } else if (ANALISE_IP && Subnet.isValidIP(token)) {
                process = true;
            } else if (ANALISE_MX && token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                process = true;
            } else {
                process = false;
            }
            if (process) {
                boolean contains = false;
                for (Analise analise : Analise.getAnaliseSet()) {
                    if (analise.contains(token)) {
                        contains = true;
                        break;
                    }
                }
                if (!contains) {
                    Date today = new Date();
                    String name = Core.SQL_FORMAT.format(today);
                    Analise analise = Analise.get(name, true);
                    analise.add(token);
                }
            }
        }
    }
    
    /**
     * Enumeração do status da analise.
     */
    public enum Status {

        WHITE, // Obsoleto.
        GRAY, // Obsoleto.
        BLACK, // Obsoleto.
        GREEN,
        YELLOW,
        RED,
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
        GENERIC, //Reverso genérico
        ;
        
    }
    
    private static Object getResponseSMTP(String host, int port, int timeout, int retries) {
        Object response = Status.ERROR;
        while (retries-- > 0) {
            response = getResponseSMTP(host, port, timeout);
            if (response instanceof String) {
                return response;
            }
        }
        return response;
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
                if (helo.contains(".") && Domain.isHostname(helo)) {
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
//            if (ex.getMessage().containsExact("TLS")) {
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
            ArrayList<String> mxSet = Reverse.getMXSet(host);
            for (int index = 0; index < mxSet.size(); index++) {
                String mx = mxSet.get(index);
                if (Subnet.isValidIP(mx)) {
                    String ip = Subnet.normalizeIP(mx);
                    tokenMX = ip;
                    if (Block.containsCIDR(ip)) {
                        statusMX = Status.BLOCK;
                        addBlock(tokenAddress, "'" + ip + ";BLOCK'");
                        break;
                    } else if ((response = getResponseSMTP(ip, 25, timeout, 3)) instanceof Status) {
                        statusMX = (Status) response;
                    } else if ((dist = SPF.getDistribution(ip, false)) == null) {
                        statusMX = Status.GREEN;
                    } else {
                        statusMX = Status.valueOf(dist.getStatus(ip).name());
                    }
                    for (String ptr : Reverse.getPointerSet(ip)) {
                        if (!mxSet.contains(ptr)) {
                            try {
                                if (Reverse.getAddressSet(ptr).contains(ip)) {
                                    mxSet.add(ptr);
                                }
                            } catch (NamingException ex) {
                                tokenMX = ptr;
                                throw ex;
                            }
                        }
                    }
                } else if (Domain.isHostname(mx)) {
                    tokenMX = mx;
                    if (Block.containsDomain(mx)) {
                        statusMX = Status.BLOCK;
                        break;
                    } else if (Generic.contains(tokenMX)) {
                        statusMX = Status.GENERIC;
                        break;
                    } else if (Provider.containsDomain(mx)) {
                        statusMX = Status.PROVIDER;
                        break;
                    } else if (Ignore.containsHost(mx)) {
                        statusMX = Status.IGNORE;
                        break;
                    } else if ((response = getResponseSMTP(mx.substring(1), 25, timeout, 3)) instanceof Status) {
                        statusMX = (Status) response;
                    } else if ((dist = SPF.getDistribution(mx, false)) == null) {
                        statusMX = Status.GREEN;
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
            } else if (Generic.contains(host)) {
                statusAddress = Status.GENERIC;
            } else if (Provider.containsExact(tokenAddress)) {
                statusAddress = Status.PROVIDER;
            } else if (Ignore.contains(tokenAddress)) {
                statusAddress = Status.IGNORE;
            } else if (statusMX == Status.GENERIC && addBlock(tokenAddress, "'" + tokenMX + ";GENERIC'")) {
                statusAddress = Status.BLOCK;
            } else if (statusMX == Status.CLOSED && addBlock(tokenAddress, "'" + tokenMX + ";CLOSED'")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.UNAVAILABLE && addBlock(tokenAddress, "'" + tokenMX + ";UNAVAILABLE'")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.RED && addBlock(tokenAddress, "'" + tokenMX + ";RED'")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.BLOCK && addBlock(tokenAddress, "'" + tokenMX + ";BLOCK'")) {
                statusAddress = Status.BLOCK;
            } else if ((dist = SPF.getDistribution(tokenAddress, false)) == null) {
                probability = 0.0f;
                statusAddress = Status.GREEN;
                frequency = "UNDEFINED";
            } else {
                probability = dist.getSpamProbability(tokenAddress);
                statusAddress = Status.valueOf(dist.getStatus().name());
                frequency = dist.getFrequencyLiteral();
            }
        } catch (CommunicationException ex) {
            if (Block.containsExact(tokenAddress)) {
                statusAddress = Status.BLOCK;
            } else if (Block.containsDomain(host)) {
                statusAddress = Status.BLOCK;
            } else if (Provider.containsExact(tokenAddress)) {
                statusAddress = Status.PROVIDER;
            } else if (Ignore.contains(tokenAddress)) {
                statusAddress = Status.IGNORE;
            } else {
                statusAddress = Status.TIMEOUT;
            }
        } catch (ServiceUnavailableException ex) {
            statusAddress = Status.UNAVAILABLE;
        } catch (NameNotFoundException ex) {
            try {
                if (Block.containsExact(tokenAddress)) {
                    statusAddress = Status.BLOCK;
                } else if (Block.containsDomain(host)) {
                    statusAddress = Status.BLOCK;
                } else if (Subnet.isValidIP(tokenMX)) {
                    addBlock(tokenAddress, "NXDOMAIN");
                    statusAddress = Status.BLOCK;
                    if (Block.tryAdd(tokenMX)) {
                        Server.logDebug("new BLOCK '" + tokenMX + "' added by NXDOMAIN.");
                        Peer.sendBlockToAll(tokenMX);
                    }
                } else {
                    statusAddress = Status.NXDOMAIN;
                    String domain = Domain.extractDomain(tokenMX, true);
                    try {
                        if (Reverse.hasValidNameServers(domain)) {
                            domain = tokenMX;
                        }
                    } catch (CommunicationException ex2) {
                        // Fazer nada.
                    }
                    if (Block.addExact(domain)) {
                        Server.logDebug("new BLOCK '" + domain + "' added by NXDOMAIN.");
                        Peer.sendBlockToAll(domain);
                    }
                    statusAddress = Status.BLOCK;
                }
            } catch (Exception ex2) {
                Server.logError(ex2);
            }
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
    
    private static boolean addBlock(String token, String by) {
        try {
            if (Block.addExact(token)) {
                Server.logDebug("new BLOCK '" + token + "' added by " + by + ".");
                Peer.sendBlockToAll(token);
            }
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
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
            String tokenName;
            Status statusName = Status.NONE;
            LinkedList<String> nameList = new LinkedList<String>();
            try {
                for (String ptr : Reverse.getPointerSet(ip)) {
                    nameList.add(ptr);
                    if (Block.containsDomain(ptr)) {
                        statusName = Status.BLOCK;
                    } else if (Block.containsREGEX(ptr)) {
                        statusName = Status.BLOCK;
                    } else if (Block.containsWHOIS(ptr)) {
                        statusName = Status.BLOCK;
                    } else if (Generic.contains(ptr)) {
                        statusName = Status.GENERIC;
                    } else {
                        try {
                            if (Provider.containsDomain(ptr)) {
                                if (Reverse.getAddressSet(ptr).contains(ip)) {
                                    statusName = Status.PROVIDER;
                                }
                            } else if (Ignore.contains(ptr)) {
                                if (Reverse.getAddressSet(ptr).contains(ip)) {
                                    statusName = Status.IGNORE;
                                }
                            }
                        } catch (NamingException ex) {
                            // Fazer nada.
                        }
                    }
                }
            } catch (CommunicationException ex) {
                statusName = Status.TIMEOUT;
            } catch (ServiceUnavailableException ex) {
                statusName = Status.UNAVAILABLE;
            } catch (NamingException ex) {
                statusName = Status.NONE;
            }
            if (Block.containsCIDR(ip)) {
                statusIP = Status.BLOCK;
            } else if (Provider.containsCIDR(ip)) {
                statusIP = Status.PROVIDER;
            } else if (Ignore.containsCIDR(ip)) {
                statusIP = Status.IGNORE;
            } else if (Block.containsDNSBL(ip)) {
                statusIP = Status.DNSBL;
            } else if (statusName == Status.TIMEOUT && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                statusIP = (Status) response;
            } else if (statusName == Status.UNAVAILABLE && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                statusIP = (Status) response;
            } else if (statusName == Status.NONE && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                statusIP = (Status) response;
            } else if (dist == null) {
                statusIP = Status.GREEN;
            } else {
                statusIP = Status.valueOf(dist.getStatus(ip).name());
            }
            if (response instanceof String) {
                nameList.addLast((String) response);
            }
            if (statusName == Status.TIMEOUT) {
                tokenName = ip;
            } else if (statusName == Status.UNAVAILABLE) {
                tokenName = ip;
            } else if (nameList.isEmpty()) {
                tokenName = ip;
                statusName = Status.NONE;
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
                } else if (Generic.contains(name)) {
                    tokenName = name;
                    statusName = Status.GENERIC;
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
                                    statusName = Status.GREEN;
                                } else {
                                    statusName = Status.valueOf(distribution2.getStatus(name).name());
                                    statusName = statusName == Status.BLOCK ? Status.RED : statusName;
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
                            Peer.sendBlockToAll(domain);
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
            if (statusIP != Status.BLOCK && (statusName == Status.BLOCK || statusName == Status.NONE || statusName == Status.RESERVED)) {
                String block;
                if ((block = Block.add(ip)) != null) {
                    Server.logDebug("new BLOCK '" + block + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP == Status.DNSBL && statusName != Status.GREEN) {
                String block;
                if ((block = Block.add(ip)) != null) {
                    Server.logDebug("new BLOCK '" + block + "' added by '" + tokenName + ";" + statusIP + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP == Status.CLOSED && statusName == Status.RED) {
                String block;
                if ((block = Block.add(ip)) != null) {
                    Server.logDebug("new BLOCK '" + block + "' added by '" + tokenName + ";" + statusIP + "'.");
                }
                statusIP = Status.BLOCK;
            } else if ((statusName == Status.INVALID || statusName == Status.GENERIC) && (statusIP == Status.CLOSED || statusIP == Status.RED || statusIP == Status.YELLOW)) {
                String block;
                if ((block = Block.add(ip)) != null) {
                    Server.logDebug("new BLOCK '" + block + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusIP = Status.BLOCK;
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
                    statusIP = Status.GREEN;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
                }
            } else if (statusIP == Status.DNSBL && (statusName == Status.PROVIDER || statusName == Status.IGNORE)) {
                if ((response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (dist == null) {
                    statusIP = Status.GREEN;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
                }
            } else if (statusIP == Status.BLOCK && statusName == Status.GREEN && probability == 0.0f) {
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
                        statusIP = Status.GREEN;
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

    private static class Process extends Thread {
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
    
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                TreeSet<Analise> set = getAnaliseCloneSet();
                File file = new File("./data/analise.set");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(set, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/analise.set");
        if (file.exists()) {
            try {
                TreeSet<Analise> set;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    set = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (Analise analise : set) {
                    try {
                        analise.ipSet.addAll(analise.processSet);
                        analise.processSet.clear();
                        if (analise.resultMap != null) {
                            // Conversão para o modo de gravação em disco.
                            analise.resultSet = new TreeSet<String>();
                            File resultFile = analise.getResultFile();
                            analise.resultWriter = new FileWriter(resultFile, false);
                            for (String ip : analise.resultMap.keySet()) {
                                String result = analise.resultMap.get(ip);
                                analise.resultSet.add(ip);
                                analise.resultWriter.write(ip + " " + result + "\n");
                            }
                            if (analise.ipSet.isEmpty()) {
                                analise.resultWriter.close();
                                analise.resultWriter = null;
                            }
                            analise.resultMap.clear();
                            analise.resultMap = null;
                        }
                        add(analise);
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
