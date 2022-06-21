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

import net.spfbl.spf.SPF;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
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
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.Provider;
import net.spfbl.data.FQDN;
import net.spfbl.data.White;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Análise de listas de IP.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Analise implements Serializable, Comparable<Analise> {
    
    private static final long serialVersionUID = 1L;

//    private static byte ANALISE_EXPIRES = 0;
//    private static boolean ANALISE_IP = false;
//    private static boolean ANALISE_MX = false;
    private static boolean CHANGED = false;
    
//    public static synchronized void setAnaliseExpires(String expires) {
//        if (expires != null && expires.length() > 0) {
//            try {
//                setAnaliseExpires(Integer.parseInt(expires));
//            } catch (Exception ex) {
//                setAnaliseExpires(-1);
//            }
//        }
//    }
    
//    public static synchronized void setAnaliseExpires(int expires) {
//        if (expires < 0 || expires > Byte.MAX_VALUE) {
//            Server.logError("invalid analise expires integer value '" + expires + "'.");
//        } else {
//            ANALISE_EXPIRES = (byte) expires;
//        }
//    }
//    
//    public static boolean isRunning() {
//        return ANALISE_EXPIRES > 0;
//    }
    
//    public static synchronized void setAnaliseIP(String analise) {
//        try {
//            ANALISE_IP = Boolean.parseBoolean(analise);
//        } catch (Exception ex) {
//            Server.logError("invalid analise IP boolean set '" + analise + "'.");
//        }
//    }
//    
//    public static synchronized void setAnaliseMX(String analise) {
//        try {
//            ANALISE_MX = Boolean.parseBoolean(analise);
//        } catch (Exception ex) {
//            Server.logError("invalid analise MX boolean set '" + analise + "'.");
//        }
//    }
    
    private final String name; // Nome do processo.
    private Semaphore semaphoreSet = new Semaphore(1);
    private final TreeSet<String> ipSet = new TreeSet<>(); // Lista dos IPs a serem analisados.
    private final TreeSet<String> processSet = new TreeSet<>(); // Lista dos IPs em processamento.
    private final TreeSet<String> resultSet = new TreeSet<>(); // Lista dos resultados das analises.
    private transient FileWriter resultWriter = null;
    
    private long last = System.currentTimeMillis();
    
    private Analise(String name) {
        this.name = name;
    }
    
    private Analise duplicate() throws InterruptedException {
        Analise clone = new Analise(this.name);
        semaphoreSet.acquire();
        clone.ipSet.addAll(this.ipSet);
        clone.processSet.addAll(this.processSet);
        clone.resultSet.addAll(this.resultSet);
        semaphoreSet.release();
        clone.last = this.last;
        return clone;
    }
    
    public String getRealName() {
        return name;
    }
    
    public String getName() {
        try {
            return URLDecoder.decode(name, "UTF-8");
        } catch (Exception ex) {
            Server.logError(ex);
            return name;
        }
    }
    
    private boolean containsFullSet(String ip) {
        if (!semaphoreSet.tryAcquire()) {
            return true;
        } else if (ipSet.contains(ip)) {
            semaphoreSet.release();
            return true;
        } else if (processSet.contains(ip)) {
            semaphoreSet.release();
            return true;
        } else if (resultSet.contains(ip)) {
            semaphoreSet.release();
            return true;
        } else {
            semaphoreSet.release();
            return false;
        }
    }
    
    private boolean containsResultSet(String ip) throws InterruptedException {
        semaphoreSet.acquire();
        boolean contains = resultSet.contains(ip);
        semaphoreSet.release();
        return contains;
    }
    
    public boolean contains(String token) {
        if (isValidIP(token)) {
            token = Subnet.normalizeIP(token);
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
        } else if (token.startsWith("@") && isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        return containsFullSet(token);
    }
    
    public boolean add(String token) {
        if (!token.startsWith(".") && Core.isExecutableSignature(token)) {
            return false;
        } else if (token.startsWith(".") && Core.isExecutableSignature(token.substring(1))) {
            return false;
        } else if (!token.startsWith(".") && Core.isSignatureURL(token)) {
            return false;
        } else if (token.startsWith(".") && Core.isSignatureURL(token.substring(1))) {
            return false;
        } else if (isValidIP(token)) {
            token = Subnet.normalizeIP(token);
            token = SubnetIPv6.tryTransformToIPv4(token);
        } else if (!token.startsWith("@") && Domain.isRootDomain(token)) {
            token = "@" + Domain.normalizeHostname(token, false);
        } else if (isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
        } else if (token.startsWith("@") && isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        return addNew(token);
    }
    
    private boolean addNew(String token) {
        try {
            semaphoreSet.acquire();
            if (ipSet.contains(token)) {
                semaphoreSet.release();
                return false;
            } else if (processSet.contains(token)) {
                semaphoreSet.release();
                return false;
            } else if (resultSet.contains(token)) {
                semaphoreSet.release();
                return false;
            } else if (ipSet.add(token)) {
                semaphoreSet.release();
                if (SEMAPHORE.tryAcquire()) {
                    Process process = new Process();
                    process.start();
                }
                last = System.currentTimeMillis();
                return CHANGED = true;
            } else {
                semaphoreSet.release();
                return false;
            }
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static void initProcess() {
        checkAccessSMTP();
        int count = 0;
        while (count++ < MAX && getProcessTotal() > 0 && SEMAPHORE.tryAcquire()) {
            Process process = new Process();
            process.start();
        }
    }
    
    private File getResultFile() {
        return new File("./data/" + name + ".csv");
    }
    
    private void whiteFullSet(TreeMap<String,String> map) throws InterruptedException {
        semaphoreSet.acquire();
        for (String ip: ipSet) {
            map.put(ip, "WAITING");
        }
        for (String ip: processSet) {
            map.put(ip, "PROCESSING");
        }
        for (String ip: resultSet) {
            map.put(ip, "LOST");
        }
        semaphoreSet.release();
    }
    
    public TreeSet<String> getResultFullSet() throws InterruptedException {
        TreeMap<String,String> map = new TreeMap<>();
        whiteFullSet(map);
        File resultFile = getResultFile();
        if (resultFile.exists()) {
            try {
                FileReader fileReader = new FileReader(resultFile);
                try (BufferedReader bufferedReader = new BufferedReader(fileReader)) {
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        int index = line.indexOf(' ');
                        if (index > 0) {
                            String ip = line.substring(0, index);
                            try {
                                if (containsResultSet(ip)) {
                                    String result = line.substring(index + 1);
                                    map.put(ip, result);
                                }
                            } catch (InterruptedException ex) {
                                Server.logError(ex);
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        TreeSet<String> set = new TreeSet<>();
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
        try {
            for (String line : getResultFullSet()) {
                builder.append(line);
                builder.append('\n');
            }
        } catch (InterruptedException ex) {
            builder.append("BUSY\n");
        }
    }
    
    private String pollFirst() {
        try {
            semaphoreSet.acquire();
            String ip = ipSet.pollFirst();
            if (ip == null) {
                semaphoreSet.release();
                return null;
            } else {
                processSet.add(ip);
                semaphoreSet.release();
                CHANGED = true;
                return ip;
            }
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    private boolean dropProcess(String token) {
        try {
            semaphoreSet.acquire();
            boolean removed = processSet.remove(token);
            semaphoreSet.release();
            return removed;
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private boolean isWait() {
        return !ipSet.isEmpty();
    }
    
    private boolean addResult(String token, String result) {
        try {
            semaphoreSet.acquire();
            if (processSet.remove(token) && resultSet.add(token)) {
                CHANGED = true;
                if (resultWriter == null) {
                    File resultFile = getResultFile();
                    resultWriter = new FileWriter(resultFile, true);
                }
                resultWriter.write(token + " " + result + "\n");
                resultWriter.flush();
                if (ipSet.isEmpty() && processSet.isEmpty()) {
                    resultWriter.close();
                    resultWriter = null;
                }
                semaphoreSet.release();
                return true;
            } else {
                semaphoreSet.release();
                return false;
            }
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return false;
        } catch (IOException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static TreeSet<String> getIPSet(String hostname) {
        TreeSet<String> ipv4Set = getIPv4Set(hostname);
        TreeSet<String> ipv6Set = getIPv6Set(hostname);
        if (ipv4Set == null && ipv6Set == null) {
            return null;
        } else if (ipv4Set == null) {
            return ipv6Set;
        } else if (ipv6Set == null) {
            return ipv4Set;
        } else {
            TreeSet<String> ipSet = new TreeSet<>();
            ipSet.addAll(ipv4Set);
            ipSet.addAll(ipv6Set);
            return ipSet;
        }
    }
    
    public static TreeSet<String> getIPv4Set(String hostname) {
        TreeSet<String> ipv4Set = new TreeSet<>();
        try {
            Attributes attributesA = Server.getAttributesDNS(hostname, "A");
            if (attributesA != null) {
                Enumeration enumerationA = attributesA.getAll();
                while (enumerationA.hasMoreElements()) {
                    Attribute attributeA = (Attribute) enumerationA.nextElement();
                    NamingEnumeration enumeration = attributeA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv4(address)) {
                            address = SubnetIPv4.normalizeIPv4(address);
                            ipv4Set.add(address);
                        }
                    }
                }
            }
        } catch (NameNotFoundException ex) {
            return null;
        } catch (NamingException ex) {
            // Ignore.
        }
        return ipv4Set;
    }
    
    public static TreeSet<String> getIPv6Set(String hostname) {
        TreeSet<String> ipv6Set = new TreeSet<>();
        try {
            Attributes attributesAAAA = Server.getAttributesDNS(hostname, "AAAA");
            if (attributesAAAA != null) {
                Enumeration enumerationAAAA = attributesAAAA.getAll();
                while (enumerationAAAA.hasMoreElements()) {
                    Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                    NamingEnumeration enumeration = attributeAAAA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (isValidIPv6(address)) {
                            address = SubnetIPv6.normalizeIPv6(address);
                            ipv6Set.add(address);
                        }
                    }
                }
            }
        } catch (NameNotFoundException ex) {
            return null;
        } catch (NamingException ex) {
            // Ignore.
        }
        return ipv6Set;
    }
    
    private boolean process() {
        if (run) {
            String token = pollFirst();
            if (token == null) {
                return false;
            } else if (!token.startsWith(".") && Core.isExecutableSignature(token)) {
                return false;
            } else if (token.startsWith(".") && Core.isExecutableSignature(token.substring(1))) {
                return false;
            } else if (!token.startsWith(".") && Core.isSignatureURL(token)) {
                return false;
            } else if (token.startsWith(".") && Core.isSignatureURL(token.substring(1))) {
                return false;
            } else if (Subnet.isReservedIP(token)) {
                dropProcess(token);
                return false;
            } else if (Domain.isOfficialTLD(token)) {
                addResult(token, "RESERVED");
                return false;
            } else if (Generic.containsDynamic(token)) {
                addResult(token, "DYNAMIC");
                return false;
            } else if (!token.startsWith("@") && Domain.isRootDomain(token)) {
                add("@" + Domain.normalizeHostname(token, false));
                dropProcess(token);
                return false;
            } else if (isHostname(token)) {
                String hostname = Domain.normalizeHostname(token, true);
                TreeSet<String> ipLocalSet = Analise.getIPSet(hostname.substring(1));
                if (ipLocalSet == null) {
                    addResult(hostname, "NXDOMAIN");
                } else if (ipLocalSet.isEmpty()) {
                    addResult(hostname, "NONE");
                } else {
                    for (String ip : ipLocalSet) {
                        add(ip);
                    }
                    addResult(hostname, "RESOLVED");
                }
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
    public String toString() {
        if (semaphoreSet.tryAcquire()) {
            String result = getName() + " "
                    + ipSet.size() + " "
                    + processSet.size() + " "
                    + resultSet.size();
            semaphoreSet.release();
            return result;
        } else {
            return getName() + " BUSY";
        }
    }
    
    private int getProcessSetSize() {
        return processSet.size();
    }
    
    /**
     * Fila de processos.
     */
    private static final LinkedList<Analise> QUEUE = new LinkedList<>();
    /**
     * Mapa de processos.
     */
    private static final HashMap<String,Analise> MAP = new HashMap<>();
    
    private static synchronized int getProcessTotal() {
        int total = 0;
        for (Analise analise : MAP.values()) {
            total += analise.getProcessSetSize();
        }
        return total;
    }
    
    public static synchronized TreeSet<Analise> getAnaliseSet() {
        TreeSet<Analise> queue = new TreeSet<>();
        queue.addAll(QUEUE);
        return queue;
    }
    
    public static TreeSet<Analise> getAnaliseCloneSet() {
        TreeSet<Analise> queue = new TreeSet<>();
        for (String name : getNameSet()) {
            Analise analise = get(name, false);
            if (analise != null) {
                try {
                    Analise clone = analise.duplicate();
                    if (clone != null) {
                        queue.add(clone);
                    }
                } catch (InterruptedException ex) {
                    Server.logError(ex);
                }
            }
        }
        return queue;
    }
    
    public static synchronized TreeSet<String> getNameSet() {
        TreeSet<String> queue = new TreeSet<>();
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
    
    public static synchronized Analise get(String name, boolean create) {
        name = normalizeName(name);
        Analise analise = MAP.get(name);
        if (analise == null && create) {
            analise = new Analise(name);
            MAP.put(name, analise);
            QUEUE.addLast(analise);
        }
        return analise;
    }
    
    public static synchronized void add(Analise analise) {
        Analise analiseDropped = MAP.put(analise.getRealName(), analise);
        if (analiseDropped != null) {
            QUEUE.remove(analiseDropped);
        }
        QUEUE.add(analise);
    }
    
    private void clearSet() throws InterruptedException {
        semaphoreSet.acquire();
        ipSet.clear();
        processSet.clear();
        semaphoreSet.release();
    }
    
    public static synchronized Analise drop(String name) {
        name = normalizeName(name);
        Analise analise;
        if ((analise = MAP.remove(name)) != null) {
            try {
                analise.clearSet();
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
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        return analise;
    }
    
    private static synchronized Analise getNextWait() {
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
    
    /**
     * Enumeração do status da analise.
     */
    public enum Status {

        WHITE,
        GREEN,
        YELLOW,
        RED,
        BLOCK, // Blocked
        DNSBL, // DNS blacklist
        PROVIDER, // Provedor
        IGNORE, // Ignored
        CLOSED, // Closed
        TIMEOUT, // Timeout
        UNAVAILABLE, // Indisponível
        INVALID, // Reverso inválido
        NXDOMAIN, // Domínio inexistente
        ERROR, // Erro de processamento
        NONE, // Nenhum reverso
        RESERVED, // Domínio reservado
        GENERIC, //Reverso genérico
        DYNAMIC, //Reverso dinâmico
        FQDN
        ;
        
    }
    
    private static boolean SMTP_ACCESS_IPv4 = true;
    private static boolean SMTP_ACCESS_IPv6 = false;
    
    private static boolean hasAccessSMTP() {
        return SMTP_ACCESS_IPv4;
    }
    
    private static boolean hasAccessSMTP(String host) {
        if (isValidIPv4(host)) {
            return SMTP_ACCESS_IPv4;
        } else if (isValidIPv6(host)) {
            return SMTP_ACCESS_IPv6;
        } else if (isHostname(host)) {
            return SMTP_ACCESS_IPv4;
        } else {
            return false;
        }
    }
    
    protected static void checkAccessSMTP() {
        if (Core.isRunning()) {
            Server.logTrace("checking access to outgoing SMTP.");
            boolean accessIPv4 = false;
            boolean accessIPv6 = false;
            try {
                for (String mx : Reverse.getMXSet("gmail.com")) {
                    try {
                        for (String ip : Reverse.getAddressSet(mx)) {
                            if (!accessIPv4 && isValidIPv4(ip)) {
                                Object response = getResponseSMTP(ip, 25, 5000);
                                if (response != Status.TIMEOUT && response != Status.CLOSED) {
                                    accessIPv4 = true;
                                }
                            } else if (!accessIPv6 && isValidIPv6(ip)) {
                                Object response = getResponseSMTP(ip, 25, 5000);
                                if (response != Status.TIMEOUT && response != Status.CLOSED) {
                                    accessIPv6 = true;
                                }
                            }
                        }
                    } catch (NamingException ex) {
                        // Do nothing.
                    }
                }
            } catch (NamingException ex) {
                // Do nothing.
            }
            SMTP_ACCESS_IPv4 = accessIPv4;
            SMTP_ACCESS_IPv6 = accessIPv6;
            if (accessIPv4) {
                Server.logTrace("this server has IPv4 access to remote SMTP.");
            } else {
                Server.logInfo("this server don't has IPv4 access to remote SMTP.");
            }
            if (accessIPv6) {
                Server.logTrace("this server has IPv6 access to remote SMTP.");
            } else {
                Server.logInfo("this server don't has IPv6 access to remote SMTP.");
            }
        }
    }
    
    public static boolean isOpenSMTP(String host, int timeout) {
        return isOpenSMTP(host, timeout, 25);
    }
    
    public static boolean isOpenSMTP(String host, int timeout, int... ports) {
        if (ports == null) {
            return false;
        } else if (hasAccessSMTP(host)) {
            for (int port : ports) {
                Object response = getResponseSMTP(host, port, timeout);
                if (response != Status.CLOSED && response != Status.TIMEOUT) {
                    return true;
                }
            }
            return false;
        } else {
            return true;
        }
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
    
    private static Object getResponseSMTP(String ip, int timeout) {
        if (hasAccessSMTP(ip)) {
            return getResponseSMTP(ip, 25, timeout);
        } else {
            return null;
        }
    }
    
    private static Object getResponseSMTP(String host, int port, int timeout) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.starttls.enable", "false");
            props.put("mail.smtp.auth", "false");
            props.put("mail.smtp.timeout", Integer.toString(timeout));
            props.put("mail.smtp.connectiontimeout", "5000");
            Session session = Session.getInstance(props);
            try (SMTPTransport transport = (SMTPTransport) session.getTransport("smtp")) {
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
                if (helo.contains(".") && isHostname(helo)) {
                    return Domain.normalizeHostname(helo, true);
                } else {
                    return null;
                }
            }
        } catch (MailConnectException ex) {
            if (ex.getMessage().contains("timeout -1")) {
                return Status.CLOSED;
            } else {
                return Status.TIMEOUT;
            }
        } catch (MessagingException ex) {
            if (ex.getCause() instanceof SocketTimeoutException) {
                return Status.TIMEOUT;
            } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().contains(", response: -1")) {
                return Status.CLOSED;
            } else {
                return Status.UNAVAILABLE;
            }
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
        if (isValidIP(token)) {
            processIP(token, builder, timeout);
        } else if (token.startsWith("@") && isHostname(token.substring(1))) {
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
        Distribution dist = null;
        try {
            Object response;
            ArrayList<String> mxSet = Reverse.getMXSet(host);
            for (int index = 0; index < mxSet.size(); index++) {
                String mx = mxSet.get(index);
                if (isValidIP(mx)) {
                    String ip = Subnet.normalizeIP(mx);
                    tokenMX = ip;
                    if (Block.containsCIDR(ip)) {
                        statusMX = Status.BLOCK;
                        addBlock(tokenAddress, ip + ";BLOCK");
                        break;
                    } else if (hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout, 3)) instanceof Status) {
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
                } else if (isHostname(mx)) {
                    tokenMX = mx;
                    if (Block.containsDomain(mx, false)) {
                        statusMX = Status.BLOCK;
                        break;
                    } else if (Generic.containsDynamic(tokenMX)) {
                        statusMX = Status.DYNAMIC;
                        break;
                    } else if (Generic.containsGeneric(tokenMX)) {
                        statusMX = Status.GENERIC;
                        break;
                    } else if (Provider.containsDomain(mx)) {
                        statusMX = Status.PROVIDER;
                        break;
                    } else if (Ignore.containsHost(mx)) {
                        statusMX = Status.IGNORE;
                        break;
                    } else if (hasAccessSMTP() && (response = getResponseSMTP(mx.substring(1), 25, timeout, 3)) instanceof Status) {
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
            } else if (Block.containsDomain(host, false)) {
                statusAddress = Status.BLOCK;
            } else if (Generic.containsDynamic(host)) {
                statusAddress = Status.DYNAMIC;
            } else if (Generic.containsGeneric(host)) {
                statusAddress = Status.GENERIC;
            } else if (Provider.containsExact(tokenAddress)) {
                statusAddress = Status.PROVIDER;
            } else if (Ignore.contains(tokenAddress)) {
                statusAddress = Status.IGNORE;
            } else if (statusMX == Status.BLOCK && statusAddress == Status.GENERIC && addBlock(tokenAddress, tokenAddress + ";GENERIC")) {
                statusAddress = Status.BLOCK;
            } else if (statusMX == Status.GENERIC && statusAddress == Status.GENERIC && addBlock(tokenAddress, tokenAddress + ";GENERIC")) {
                statusAddress = Status.BLOCK;
            } else if (statusMX == Status.DYNAMIC && addBlock(tokenAddress, tokenMX + ";DYNAMIC")) {
                statusAddress = Status.BLOCK;
            } else if (statusMX == Status.CLOSED && addBlock(tokenAddress, tokenMX + ";CLOSED")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.UNAVAILABLE && addBlock(tokenAddress, tokenMX + ";UNAVAILABLE")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.RED && addBlock(tokenAddress, tokenMX + ";RED")) {
                statusAddress = Status.BLOCK;
            } else if (statusAddress == Status.RED && statusMX == Status.BLOCK && addBlock(tokenAddress, tokenMX + ";BLOCK")) {
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
            } else if (Block.containsDomain(host, false)) {
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
                } else if (Block.containsDomain(host, false)) {
                    statusAddress = Status.BLOCK;
                } else if (isValidIP(tokenMX)) {
                    statusAddress = Status.BLOCK;
                } else if (Domain.isOfficialTLD(tokenMX)) {
                    statusAddress = Status.RESERVED;
                } else {
                    statusAddress = Status.NXDOMAIN;
                    String domain = Domain.extractDomain(tokenMX, true);
                    try {
                        if (Reverse.hasValidNameServers(domain)) {
                            domain = tokenMX;
                        }
                    } catch (CommunicationException ex2) {
                        // Fazer nada.
                    } catch (ServiceUnavailableException ex2) {
                        // Fazer nada.
                    }
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
            builder.append(" NONE ");
            builder.append(statusMX);
            builder.append(' ');
            builder.append(probability);
            builder.append(' ');
            builder.append(frequency);
            builder.append(' ');
            if (isValidIP(tokenMX)) {
                builder.append(Subnet.expandIP(tokenMX));
            } else {
                builder.append(Domain.revert(tokenMX));
            }
        }
    }
    
    private static boolean addBlock(String token, String by) {
        try {
            if (Block.addExact(token)) {
                Server.logDebug(null, "new BLOCK '" + token + "' added by '" + by + "'.");
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
            boolean ipv4 = isValidIPv4(ip);
            Status statusIP;
            String tokenName;
            Status statusName;
            String tokenMask;
            String fqdn = FQDN.discoverFQDN(ip);
            String abuseEmail = Abuse.getEmail(ip, fqdn);
            if (Subnet.isReservedIP(ip)) {
                tokenName = ip;
                tokenMask = null;
                statusIP = Status.RESERVED;
                statusName = Status.NONE;
            } else if (fqdn != null) {
                net.spfbl.data.Domain.usingSince(fqdn);
                tokenMask = Generic.convertHostToMask(fqdn);
                tokenName = Domain.normalizeHostname(fqdn, true);
                statusName = Status.FQDN;
                if (White.containsFQDN(fqdn)) {
                    Block.clearFQDN(null, fqdn, fqdn + ";WHITE");
                    Block.clearCIDR(null, ip, fqdn + ";WHITE");
                    statusIP = Status.WHITE;
                } else if (Ignore.containsFQDN(fqdn)) {
                    Block.clearFQDN(null, fqdn, fqdn + ";IGNORE");
                    Block.clearCIDR(null, ip, fqdn + ";IGNORE");
                    statusIP = Status.IGNORE;
                } else if (Provider.containsFQDN(fqdn)) {
                    Block.clearFQDN(null, fqdn, fqdn + ";PROVIDER");
                    Block.clearCIDR(null, ip, fqdn + ";PROVIDER");
                    statusIP = Status.PROVIDER;
                } else if (Block.containsFQDN(fqdn)) {
                    Block.tryToDominoBlockIP(ip, "BLOCK");
                    statusIP = Status.BLOCK;
                } else if (dist == null) {
                    statusIP = Status.GREEN;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
                }
                if (statusIP == Status.GREEN && abuseEmail != null) {
                    Block.clearCIDR(null, ip, fqdn + ";GREEN");
                }
            } else if (abuseEmail != null) {
                String token = ip + (ipv4 ? "/32" : "/64");
                String cidr = Subnet.normalizeCIDR(token);
                TreeSet<String> ptrSet = Reverse.getPointerSetSafe(ip);
                if (ptrSet == null || ptrSet.isEmpty()) {
                    Block.tryToDominoBlockIP(ip, "NONE");
                    tokenName = ip;
                    tokenMask = null;
                    statusIP = Status.BLOCK;
                    statusName = Status.NONE;
                } else if ((token = Generic.returnDynamicPTR(ptrSet)) != null) {
                    Block.tryToDominoBlockIP(ip, "DYNAMIC");
                    tokenName = token;
                    tokenMask = Generic.convertHostToMask(token);
                    statusIP = Status.BLOCK;
                    statusName = Status.DYNAMIC;
                } else if ((token = White.returnWhitePTR(ptrSet)) != null && FQDN.addFQDN(ip, token, true)) {
                    White.addFQDN(token);
                    if (Block.drop(cidr)) {
                        Server.logDebug(null, "false positive BLOCK '" + cidr + "' detected by '" + token + ";WHITE'.");
                    }
                    tokenName = token;
                    tokenMask = Generic.convertHostToMask(token);
                    statusIP = Status.WHITE;
                    statusName = Status.FQDN;
                } else if ((token = Ignore.returnIgnorePTR(ptrSet)) != null && FQDN.addFQDN(ip, token, true)) {
                    if (Block.drop(cidr)) {
                        Server.logDebug(null, "false positive BLOCK '" + cidr + "' detected by '" + token + ";IGNORE'.");
                    }
                    tokenName = token;
                    tokenMask = Generic.convertHostToMask(token);
                    statusIP = Status.IGNORE;
                    statusName = Status.FQDN;
                } else if ((token = Provider.returnProviderPTR(ptrSet)) != null && FQDN.addFQDN(ip, token, true)) {
                    if (Block.drop(cidr)) {
                        Server.logDebug(null, "false positive BLOCK '" + cidr + "' detected by '" + token + ";PROVIDER'.");
                    }
                    tokenName = token;
                    tokenMask = Generic.convertHostToMask(token);
                    statusIP = Status.PROVIDER;
                    statusName = Status.FQDN;
                } else if ((token = Block.returnBlockedPTR(ptrSet)) != null) {
                    Block.tryToDominoBlockIP(ip, "BLOCK");
                    tokenName = token;
                    tokenMask = Generic.convertHostToMask(token);
                    statusIP = Status.BLOCK;
                    statusName = Status.BLOCK;
                } else if (Block.containsCIDR(ip)) {
                    if ((token = Generic.returnGenericPTR(ptrSet)) != null) {
                        tokenName = token;
                        tokenMask = Generic.convertHostToMask(token);
                        statusIP = Status.BLOCK;
                        statusName = Status.GENERIC;
                    } else if ((token = Reverse.getValidHostname(ip, ptrSet)) != null) {
                        tokenName = token;
                        tokenMask = Generic.convertHostToMask(token);
                        statusIP = Status.BLOCK;
                        statusName = Status.valueOf(SPF.getStatus(tokenName, true).name());
                    } else if (ptrSet.size() == 1) {
                        tokenName = ptrSet.first();
                        tokenMask = Generic.convertHostToMask(tokenName);
                        statusIP = Status.BLOCK;
                        statusName = Status.INVALID;
                    } else {
                        tokenName = ip;
                        tokenMask = null;
                        statusIP = Status.BLOCK;
                        statusName = Status.NONE;
                    }
                } else {
                    Object response = getResponseSMTP(ip, timeout);
                    if (response instanceof String && FQDN.addFQDN(ip, (String) response, true)) {
                        tokenName = (String) response;
                        tokenMask = Generic.convertHostToMask(tokenName);
                        statusIP = (dist == null ? Status.GREEN : Status.valueOf(dist.getStatus(ip).name()));
                        statusName = Status.FQDN;
                    } else if ((token = Generic.returnGenericPTR(ptrSet)) != null) {
                        tokenName = token;
                        tokenMask = Generic.convertHostToMask(token);
                        statusIP = (dist == null ? Status.GREEN : Status.valueOf(dist.getStatus(ip).name()));
                        statusName = Status.GENERIC;
                    } else if (ptrSet.size() == 1 && FQDN.addFQDN(ip, ptrSet.first(), true)) {
                        tokenName = ptrSet.first();
                        tokenMask = Generic.convertHostToMask(tokenName);
                        statusIP = (dist == null ? Status.GREEN : Status.valueOf(dist.getStatus(ip).name()));
                        statusName = Status.FQDN;
                    } else if (ptrSet.size() == 1) {
                        tokenName = ptrSet.first();
                        tokenMask = Generic.convertHostToMask(tokenName);
                        statusIP = (dist == null ? Status.GREEN : Status.valueOf(dist.getStatus(ip).name()));
                        statusName = Status.INVALID;
                    } else {
                        Block.tryToDominoBlockIP(ip, "NONE");
                        tokenName = ip;
                        tokenMask = null;
                        statusIP = Status.BLOCK;
                        statusName = Status.NONE;
                        abuseEmail = Abuse.dropSafe(ip) ? null : abuseEmail;
                    }
                }
            } else {
                Object response = null;
                statusName = Status.NONE;
                LinkedList<String> nameList = new LinkedList<>();
                try {
                    for (String ptr : Reverse.getPointerSet(ip)) {
                        nameList.add(ptr);
                        if (Generic.containsDynamic(ptr)) {
                            statusName = Status.DYNAMIC;
                            break;
                        } else if (Block.containsDomain(ptr, false)) {
                            statusName = Status.BLOCK;
                        } else if (Block.containsWHOIS(ptr)) {
                            statusName = Status.BLOCK;
                        } else {
                            try {
                                if (Generic.containsGeneric(ptr)) {
                                    statusName = Status.GENERIC;
                                } else if (Reverse.getAddressSet(ptr).contains(ip)) {
                                    Distribution distPTR;
                                    if (White.containsHostname(ptr)) {
                                        statusName = Status.WHITE;
                                        break;
                                    } else if (Ignore.contains(ptr)) {
                                        statusName = Status.IGNORE;
                                        break;
                                    } else if (Provider.containsDomain(ptr)) {
                                        statusName = Status.PROVIDER;
                                        break;
                                    } else if ((distPTR = SPF.getDistribution(ptr, false)) == null) {
                                        statusName = Status.GREEN;
                                        break;
                                    } else {
                                        statusName = Status.valueOf(distPTR.getStatus(ptr).name());
                                        break;
                                    }
                                } else {
                                    statusName = Status.INVALID;
                                }
                            } catch (NamingException ex) {
                                if (Generic.containsGeneric(ptr)) {
                                    statusName = Status.GENERIC;
                                } else {
                                    statusName = Status.NXDOMAIN;
                                }
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
                if (White.containsIPorFQDN(ip)) {
                    statusIP = Status.WHITE;
                } else if (Block.containsCIDR(ip)) {
                    statusIP = Status.BLOCK;
                } else if (Provider.containsIPorFQDN(ip)) {
                    statusIP = Status.PROVIDER;
                } else if (Ignore.containsIPorFQDN(ip)) {
                    statusIP = Status.IGNORE;
                } else if (statusName == Status.TIMEOUT && hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (statusName == Status.UNAVAILABLE && hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (statusName == Status.NONE && hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (dist == null) {
                    statusIP = Status.GREEN;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
                }
                if (response instanceof String) {
                    fqdn = (String) response;
                    nameList.addLast(fqdn);
                    FQDN.addFQDN(ip, fqdn, true);
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
                    if (Generic.containsDynamic(name)) {
                        tokenName = name;
                        statusName = Status.DYNAMIC;
                        break;
                    } else if (Block.containsDomain(name, false)) {
                        tokenName = name;
                        statusName = Status.BLOCK;
                        break;
                    } else if (Block.containsWHOIS(name)) {
                        tokenName = name;
                        statusName = Status.BLOCK;
                        break;
                    } else {
                        try {
                            if (Generic.containsGeneric(name)) {
                                tokenName = name;
                                statusName = Status.GENERIC;
                            } else if (Reverse.getAddressSet(name).contains(ip)) {
                                if (White.containsHostname(name)) {
                                    tokenName = name;
                                    statusName = Status.WHITE;
                                    break;
                                } else if (Ignore.contains(name)) {
                                    tokenName = name;
                                    statusName = Status.IGNORE;
                                    break;
                                } else if (Provider.containsDomain(name)) {
                                    tokenName = name;
                                    statusName = Status.PROVIDER;
                                    break;
                                } else {
                                    tokenName = name;
                                    Distribution distribution2 = SPF.getDistribution(name, false);
                                    if (distribution2 == null) {
                                        statusName = Status.GREEN;
                                    } else {
                                        statusName = Status.valueOf(distribution2.getStatus(name).name());
                                    }
                                }
                            }
                        } catch (NameNotFoundException ex) {
                            tokenName = name;
                            if (Generic.containsGeneric(name)) {
                                statusName = Status.GENERIC;
                            } else {
                                statusName = Status.NXDOMAIN;
                            }
                        } catch (NamingException ex) {
                            // Fazer nada.
                        }
                    }
                }
                tokenMask = Generic.convertHostToMask(tokenName);
                if (statusIP == Status.WHITE && (statusName == Status.INVALID || statusName == Status.NONE || statusName == Status.NXDOMAIN || statusName == Status.GENERIC)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (
                        (statusIP == Status.DYNAMIC && statusName == Status.GENERIC) ||
                        (statusIP != Status.BLOCK && statusName == Status.DYNAMIC) ||
                        (statusName == Status.GENERIC && Generic.isGenericEC2(tokenName))
                        ) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP != Status.BLOCK && statusName == Status.NONE) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP != Status.BLOCK && statusName == Status.BLOCK) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP != Status.BLOCK && abuseEmail == null && (statusName == Status.RESERVED || statusName == Status.NXDOMAIN)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP != Status.BLOCK && statusIP != Status.IGNORE && statusName != Status.PROVIDER && statusName != Status.IGNORE && statusName != Status.GREEN  && statusName != Status.WHITE && SubnetIPv6.isSLAAC(ip)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP == Status.DNSBL && abuseEmail == null && (statusName != Status.GREEN && statusName != Status.PROVIDER && statusName != Status.IGNORE && statusName != Status.WHITE)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP == Status.CLOSED && statusName == Status.RED) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP != Status.BLOCK && statusName == Status.INVALID && Generic.containsGenericDomain(tokenName)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusName == Status.INVALID && (statusIP == Status.CLOSED || statusIP == Status.RED || statusIP == Status.YELLOW)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusName == Status.GENERIC && (statusIP == Status.RED || statusIP == Status.YELLOW)) {
                    if (Block.tryToDominoBlockIP(ip, statusName.name())) {
                        statusIP = Status.BLOCK;
                    }
                } else if (statusIP == Status.DNSBL && (statusName == Status.PROVIDER || statusName == Status.IGNORE || statusName == Status.WHITE)) {
                    if (hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                        statusIP = (Status) response;
                    } else if (dist == null) {
                        statusIP = Status.GREEN;
                    } else {
                        statusIP = Status.valueOf(dist.getStatus(ip).name());
                    }
                    if (response instanceof String) {
                        fqdn = (String) response;
                        FQDN.addFQDN(ip, fqdn, true);
                    }
                } else if (statusName == Status.PROVIDER && (statusIP == Status.PROVIDER || statusIP == Status.GREEN)) {
                    if (FQDN.addFQDN(ip, tokenName, true)) {
                        statusName = Status.FQDN;
                    }
                } else if (statusIP == Status.BLOCK && (statusName == Status.PROVIDER || statusName == Status.IGNORE || statusName == Status.WHITE)) {
                    String cidr;
                    int mask = isValidIPv4(ip) ? 32 : 64;
                    if ((cidr = Block.clearCIDR(ip, mask)) != null) {
                        Server.logDebug(null, "false positive BLOCK '" + cidr + "' detected by '" + tokenName + ";" + statusName + "'.");
                    }
                    if (Provider.containsIPorFQDN(ip)) {
                        statusIP = Status.PROVIDER;
                    } else if (Ignore.containsIPorFQDN(ip)) {
                        statusIP = Status.IGNORE;
                    } else if (Block.containsDNSBL(ip)) {
                        statusIP = Status.DNSBL;
                    } else if (hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                        statusIP = (Status) response;
                    } else if (dist == null) {
                        statusIP = Status.GREEN;
                    } else {
                        statusIP = Status.valueOf(dist.getStatus(ip).name());
                    }
                    if (response instanceof String) {
                        fqdn = (String) response;
                        FQDN.addFQDN(ip, fqdn, true);
                    }
                } else if (tokenMask == null && statusIP == Status.GREEN && statusName == Status.GREEN) {
                    FQDN.addFQDN(ip, tokenName, true);
                }
            }
            builder.append(statusIP);
            builder.append(' ');
            builder.append(tokenName);
            if (tokenMask == null) {
                builder.append(" NONE");
            } else {
                builder.append(' ');
                builder.append(tokenMask);
            }
            builder.append(' ');
            builder.append(statusName);
            builder.append(' ');
            builder.append(probability);
            builder.append(' ');
            builder.append(dist == null ? "UNDEFINED" : dist.getFrequencyLiteral());
            builder.append(' ');
            if (isValidIP(tokenName)) {
                builder.append(Subnet.expandIP(tokenName));
            } else {
                builder.append(Domain.revert(tokenName));
            }
            if (abuseEmail == null) {
                builder.append(" NONE");
            } else {
                builder.append(' ');
                builder.append(abuseEmail);
            }
        } catch (Exception ex) {
            builder.append("ERROR");
            Server.logError(ex);
        }
    }
    
    private static final int MAX = 16;
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
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(set, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
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
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                for (Analise analise : set) {
                    try {
                        if (analise.semaphoreSet == null) {
                            analise.semaphoreSet = new Semaphore(1);
                        }
                        analise.ipSet.addAll(analise.processSet);
                        analise.processSet.clear();
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
