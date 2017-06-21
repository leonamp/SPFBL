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
import java.io.IOException;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
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
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.Provider;
import net.spfbl.data.White;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Owner;
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
    private Semaphore semaphoreSet = new Semaphore(1);
    private final TreeSet<String> ipSet = new TreeSet<String>(); // Lista dos IPs a serem analisados.
    private final TreeSet<String> processSet = new TreeSet<String>(); // Lista dos IPs em processamento.
    private final TreeSet<String> resultSet = new TreeSet<String>(); // Lista dos resultados das analises.
    private transient FileWriter resultWriter = null;
    
    private long last = System.currentTimeMillis();
    
    private Analise(String name) {
        this.name = normalizeName(name);
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
        if (Subnet.isValidIP(token)) {
            token = Subnet.normalizeIP(token);
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        return containsFullSet(token);
    }
    
    public boolean add(String token) {
        if (Subnet.isValidIP(token)) {
            token = Subnet.normalizeIP(token);
        } else if (!token.startsWith("@") && Domain.isDomain(token)) {
            token = "@" + Domain.normalizeHostname(token, false);
        } else if (Domain.isHostname(token)) {
            token = Domain.normalizeHostname(token, true);
        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
            token = "@" + Domain.normalizeHostname(token.substring(1), false);
        } else {
            return false;
        }
        return addNew(token);
    }
    
    private boolean addNew(String token) {
        if (!run) {
            return false;
        } else if (!semaphoreSet.tryAcquire()) {
            return false;
        } else if (ipSet.contains(token)) {
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
            return false;
        }
    }
    
    public static void initProcess() {
        int count = 0;
        while (count++ < 256 && getProcessTotal() > 0 && SEMAPHORE.tryAcquire()) {
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
        TreeMap<String,String> map = new TreeMap<String,String>();
        whiteFullSet(map);
        File resultFile = getResultFile();
        if (resultFile.exists()) {
            try {
                FileReader fileReader = new FileReader(resultFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                try {
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
        long time = (System.currentTimeMillis() - last) / Server.DAY_TIME;
        return time >= ANALISE_EXPIRES;
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
        TreeSet<String> ipSet = new TreeSet<String>();
        try {
            Attributes attributesA = Server.getAttributesDNS(
                    hostname, new String[]{"A"}
            );
            if (attributesA != null) {
                Enumeration enumerationA = attributesA.getAll();
                while (enumerationA.hasMoreElements()) {
                    Attribute attributeA = (Attribute) enumerationA.nextElement();
                    NamingEnumeration enumeration = attributeA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (SubnetIPv4.isValidIPv4(address)) {
                            address = SubnetIPv4.normalizeIPv4(address);
                            ipSet.add(address);
                        }
                    }
                }
            }
            Attributes attributesAAAA = Server.getAttributesDNS(
                    hostname, new String[]{"AAAA"}
            );
            if (attributesAAAA != null) {
                Enumeration enumerationAAAA = attributesAAAA.getAll();
                while (enumerationAAAA.hasMoreElements()) {
                    Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                    NamingEnumeration enumeration = attributeAAAA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (SubnetIPv6.isValidIPv6(address)) {
                            address = SubnetIPv6.normalizeIPv6(address);
                            ipSet.add(address);
                        }
                    }
                }
            }
        } catch (NameNotFoundException ex) {
            return null;
        } catch (NamingException ex) {
            // Ignore.
        }
        return ipSet;
    }
    
    public static TreeSet<String> getIPv4Set(String hostname) {
        TreeSet<String> ipv4Set = new TreeSet<String>();
        try {
            Attributes attributesA = Server.getAttributesDNS(
                    hostname, new String[]{"A"}
            );
            if (attributesA != null) {
                Enumeration enumerationA = attributesA.getAll();
                while (enumerationA.hasMoreElements()) {
                    Attribute attributeA = (Attribute) enumerationA.nextElement();
                    NamingEnumeration enumeration = attributeA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (SubnetIPv4.isValidIPv4(address)) {
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
        TreeSet<String> ipv6Set = new TreeSet<String>();
        try {
            Attributes attributesAAAA = Server.getAttributesDNS(
                    hostname, new String[]{"AAAA"}
            );
            if (attributesAAAA != null) {
                Enumeration enumerationAAAA = attributesAAAA.getAll();
                while (enumerationAAAA.hasMoreElements()) {
                    Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                    NamingEnumeration enumeration = attributeAAAA.getAll();
                    while (enumeration.hasMoreElements()) {
                        String address = (String) enumeration.next();
                        if (SubnetIPv6.isValidIPv6(address)) {
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
            } else if (Subnet.isReservedIP(token)) {
                dropProcess(token);
                return false;
            } else if (Domain.isOfficialTLD(token)) {
                addResult(token, "RESERVED");
                return false;
            } else if (Generic.containsDynamic(token)) {
                addResult(token, "DYNAMIC");
                return false;
            } else if (!token.startsWith("@") && Domain.isDomain(token)) {
                add("@" + Domain.normalizeHostname(token, false));
                dropProcess(token);
                return false;
            } else if (Domain.isHostname(token)) {
                String hostname = Domain.normalizeHostname(token, true);
                TreeSet<String> ipLocalSet = Analise.getIPSet(hostname.substring(1));
                if (ipLocalSet == null) {
                    if (!Generic.containsGeneric(hostname) && Block.tryAdd(hostname)) {
                        Server.logDebug("new BLOCK '" + hostname + "' added by 'NXDOMAIN'.");
                    }
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
    private static final LinkedList<Analise> QUEUE = new LinkedList<Analise>();
    /**
     * Mapa de processos.
     */
    private static final HashMap<String,Analise> MAP = new HashMap<String,Analise>();
    
    private static synchronized int getProcessTotal() {
        int total = 0;
        for (Analise analise : MAP.values()) {
            total += analise.getProcessSetSize();
        }
        return total;
    }
    
    public static synchronized TreeSet<Analise> getAnaliseSet() {
        TreeSet<Analise> queue = new TreeSet<Analise>();
        queue.addAll(QUEUE);
        return queue;
    }
    
    public static TreeSet<Analise> getAnaliseCloneSet() {
        TreeSet<Analise> queue = new TreeSet<Analise>();
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
    
    public static boolean processToday(String token) {
        if (ANALISE_EXPIRES > 0) {
            if (token == null) {
                return false;
            } else if (ANALISE_IP && Subnet.isValidIP(token)) {
                token = Subnet.normalizeIP(token);
            } else if (Domain.isOfficialTLD(token)) {
                return false;
            } else if (ANALISE_MX && !token.startsWith("@") && Domain.isDomain(token)) {
                token = "@" + Domain.normalizeHostname(token, false);
            } else if (ANALISE_IP && Domain.isHostname(token)) {
                token = Domain.normalizeHostname(token, true);
            } else if (ANALISE_MX && token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                token = "@" + Domain.isHostname(token.substring(1));
            } else if (ANALISE_IP && Subnet.isValidCIDR(token)) {
                String cidr = Subnet.normalizeCIDR(token);
                String last = Subnet.getLastIP(cidr);
                String ip = Subnet.getFirstIP(cidr);
                processToday(ip);
                if (!ip.equals(last)) {
                    while (!last.equals(ip = Subnet.getNextIP(ip))) {
                        processToday(ip);
                    }
                    processToday(last);
                }
                return false;
            } else {
                return false;
            }
            for (Analise analise : Analise.getAnaliseSet()) {
                if (analise.contains(token)) {
                    return false;
                }
            }
            Date today = new Date();
            String name = Core.SQL_FORMAT.format(today);
            Analise analise = Analise.get(name, true);
            return analise.add(token);
        } else {
            return false;
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
//        NOTLS, // Sem TLS
        TIMEOUT, // Timeout
        UNAVAILABLE, // Indisponível
        INVALID, // Reverso inválido
        NXDOMAIN, // Domínio inexistente
        ERROR, // Erro de processamento
        NONE, // Nenhum reverso
        RESERVED, // Domínio reservado
        GENERIC, //Reverso genérico
        DYNAMIC, //Reverso dinâmico
        ;
        
    }
    
    private static boolean SMTP_ACCESS_IPv4 = true;
    private static boolean SMTP_ACCESS_IPv6 = false;
    
    private static boolean hasAccessSMTP() {
        return SMTP_ACCESS_IPv4;
    }
    
    private static boolean hasAccessSMTP(String host) {
        if (SubnetIPv4.isValidIPv4(host)) {
            return SMTP_ACCESS_IPv4;
        } else if (SubnetIPv6.isValidIPv6(host)) {
            return SMTP_ACCESS_IPv6;
        } else if (Domain.isHostname(host)) {
            return SMTP_ACCESS_IPv4;
        } else {
            return false;
        }
    }
    
    protected static void checkAccessSMTP() {
        boolean accessIPv4 = false;
        boolean accessIPv6 = false;
        try {
            for (String mx : Reverse.getMXSet("gmail.com")) {
                try {
                    for (String ip : Reverse.getAddressSet(mx)) {
                        if (!accessIPv4 && SubnetIPv4.isValidIPv4(ip)) {
                            Object response = getResponseSMTP(ip, 25, 3000);
                            if (response != Status.TIMEOUT && response != Status.CLOSED) {
                                accessIPv4 = true;
                            }
                        } else if (!accessIPv6 && SubnetIPv6.isValidIPv6(ip)) {
                            Object response = getResponseSMTP(ip, 25, 3000);
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
            Server.logDebug("this server don't has IPv4 access to remote SMTP.");
        }
        if (accessIPv6) {
            Server.logTrace("this server has IPv6 access to remote SMTP.");
        } else {
            Server.logDebug("this server don't has IPv6 access to remote SMTP.");
        }
    }
    
    public static boolean isOpenSMTP(String host, int timeout) {
        if (hasAccessSMTP(host)) {
            Object response = getResponseSMTP(host, 25, timeout);
            if (response == Status.CLOSED) {
                return false;
            } else if (response == Status.TIMEOUT) {
                return false;
            } else {
                return true;
            }
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
    
    private static Object getResponseSMTP(String host, int port, int timeout) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.starttls.enable", "false");
            props.put("mail.smtp.auth", "false");
            props.put("mail.smtp.timeout", Integer.toString(timeout));
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
        Distribution dist = null;
        try {
            Object response;
            ArrayList<String> mxSet = Reverse.getMXSet(host);
            for (int index = 0; index < mxSet.size(); index++) {
                String mx = mxSet.get(index);
                if (Subnet.isValidIP(mx)) {
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
                } else if (Domain.isHostname(mx)) {
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
            } else if (statusMX == Status.GENERIC && addBlock(tokenAddress, tokenMX + ";GENERIC")) {
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
                } else if (Subnet.isValidIP(tokenMX)) {
                    addBlock(tokenAddress, "NXDOMAIN");
                    statusAddress = Status.BLOCK;
                    if (Block.tryAdd(tokenMX)) {
                        Server.logDebug("new BLOCK '" + tokenMX + "' added by 'NXDOMAIN'.");
                        Peer.sendBlockToAll(tokenMX);
                    }
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
                    }
                    if (Block.addExact(domain)) {
                        Server.logDebug("new BLOCK '" + domain + "' added by 'NXDOMAIN'.");
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
                addCluster(extractTLD(tokenMX), statusMX, dist);
                addCluster(Domain.getOwnerID(tokenMX), statusMX, dist);
            }
        }
    }
    
    private static String convertHostToMask(String host) {
        if (host == null) {
            return null;
        } else if (Generic.containsDynamic(host)) {
            return null;
        } else {
            String mask = Generic.convertDomainToMask(host);
            if (Generic.containsGenericExact(mask)) {
                return null;
            } else {
                mask = Generic.convertHostToMask(host);
                if (Generic.containsGenericExact(mask)) {
                    return null;
                } else {
                    return mask;
                }
            }
        }
    }
    
    private static String extractTLD(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else {
            try {
                return Domain.extractTLD(host, true);
            } catch (ProcessException ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private static boolean addBlock(String token, String by) {
        try {
            if (Block.addExact(token)) {
                Server.logDebug("new BLOCK '" + token + "' added by '" + by + "'.");
                Peer.sendBlockToAll(token);
            }
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static boolean hasReverse(String ip) {
        try {
            TreeSet<String> reverseSet = Reverse.getPointerSet(ip);
            if (reverseSet == null) {
                return false;
            } else {
                return !reverseSet.isEmpty();
            }
        } catch (NamingException ex) {
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
            boolean ipv4 = SubnetIPv4.isValidIPv4(ip);
            Object response = null;
            Status statusIP;
            String tokenName;
            Status statusName = Status.NONE;
            LinkedList<String> nameList = new LinkedList<String>();
            try {
                for (String ptr : Reverse.getPointerSet(ip)) {
                    nameList.add(ptr);
                    if (Generic.containsDynamic(ptr)) {
                        statusName = Status.DYNAMIC;
                        break;
                    } else if (Block.containsDomain(ptr, false)) {
                        statusName = Status.BLOCK;
                    } else if (Block.containsREGEX(ptr)) {
                        statusName = Status.BLOCK;
                    } else if (Block.containsWHOIS(ptr)) {
                        statusName = Status.BLOCK;
                    } else if (Generic.containsGeneric(ptr)) {
                        statusName = Status.GENERIC;
                    } else {
                        try {
                            if (Reverse.getAddressSet(ptr).contains(ip)) {
                                Distribution distPTR;
                                if (White.containsDomain(ptr)) {
                                    statusName = Status.WHITE;
                                    break;
                                } else if (Provider.containsDomain(ptr)) {
                                    statusName = Status.PROVIDER;
                                    break;
                                } else if (Ignore.contains(ptr)) {
                                    statusName = Status.IGNORE;
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
                            statusName = Status.NXDOMAIN;
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
            if (White.containsIP(ip)) {
                statusIP = Status.WHITE;
            } else if (Block.containsCIDR(ip)) {
                statusIP = Status.BLOCK;
            } else if (Provider.containsCIDR(ip)) {
                statusIP = Status.PROVIDER;
            } else if (Ignore.containsCIDR(ip)) {
                statusIP = Status.IGNORE;
            } else if (Block.containsDNSBL(ip)) {
                statusIP = Status.DNSBL;
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
                if (Generic.containsDynamic(name)) {
                    tokenName = name;
                    statusName = Status.DYNAMIC;
                    break;
                } else if (Block.containsDomain(name, false)) {
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
                } else if (Generic.containsGeneric(name)) {
                    tokenName = name;
                    statusName = Status.GENERIC;
                    break;
                } else {
                    try {
                        if (Reverse.getAddressSet(name).contains(ip)) {
                            if (White.containsDomain(name)) {
                                tokenName = name;
                                statusName = Status.WHITE;
                                break;
                            } else if (Provider.containsDomain(name)) {
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
                                }
                            }
                        }
                    } catch (NameNotFoundException ex) {
                        tokenName = name;
                        statusName = Status.NXDOMAIN;
                    } catch (NamingException ex) {
                        // Fazer nada.
                    }
                }
            }
            if (statusName == Status.INVALID || statusName == Status.NXDOMAIN) {
                try {
                    String domain = Domain.extractDomain(tokenName, true);
                    if (!Reverse.hasValidNameServers(domain)) {
                        if (Block.addExact(domain)) {
                            statusName = Status.BLOCK;
                            Server.logDebug("new BLOCK '" + domain + "' added by 'NXDOMAIN'.");
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
            if (statusIP != Status.BLOCK && statusName == Status.DYNAMIC) {
                String token = ip + (SubnetIPv4.isValidIPv4(ip) ? "/24" : "/48");
                String cidr = Subnet.normalizeCIDR(token);
                if (Block.tryOverlap(cidr)) {
                    Server.logDebug("new BLOCK '" + token + "' added by '" + tokenName + ";" + statusName + "'.");
                } else if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                String previous = Subnet.getFirstIP(cidr);
                previous = Subnet.getPreviousIP(previous);
                previous = Subnet.getPreviousIP(previous);
                Analise.processToday(previous);
                String next = Subnet.getLastIP(cidr);
                next = Subnet.getNextIP(next);
                next = Subnet.getNextIP(next);
                Analise.processToday(next);
                statusIP = Status.BLOCK;
            } else if (statusIP != Status.BLOCK && statusName == Status.NONE) {
                String token = ip + (ipv4 ? "/32" : "/64");
                String cidr = Subnet.normalizeCIDR(token);
                if (Block.tryOverlap(cidr)) {
                    Server.logDebug("new BLOCK '" + token + "' added by '" + tokenName + ";" + statusName + "'.");
                } else if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                if (ipv4) {
                    cidr = Subnet.normalizeCIDR(ip + "/24");
                    String next = Subnet.getFirstIP(cidr);
                    for (int index = 0; index < 256; index++) {
                        if (!hasReverse(next) && Block.tryAdd(next)) {
                            Server.logDebug("new BLOCK '" + next + "' added by '" + next + ";" + statusName + "'.");
                        }
                        next = Subnet.getNextIP(next);
                    }
                }
                statusIP = Status.BLOCK;
            } else if (statusIP != Status.BLOCK && (statusName == Status.BLOCK || statusName == Status.RESERVED || statusName == Status.NXDOMAIN)) {
                if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP != Status.BLOCK && statusIP != Status.IGNORE && statusName != Status.PROVIDER && statusName != Status.IGNORE && statusName != Status.GREEN  && statusName != Status.WHITE && SubnetIPv6.isSLAAC(ip)) {
                String token = ip + "/64";
                String cidr = SubnetIPv6.normalizeCIDRv6(token);
                if (Block.tryOverlap(cidr)) {
                    Server.logDebug("new BLOCK '" + token + "' added by 'SLAAC'.");
                } else if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by 'SLAAC'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP == Status.DNSBL && (statusName != Status.GREEN && statusName != Status.PROVIDER && statusName != Status.IGNORE && statusName != Status.WHITE)) {
                if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusIP + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP == Status.CLOSED && statusName == Status.RED) {
                if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusIP + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP != Status.BLOCK && statusName == Status.INVALID && Generic.containsGenericDomain(tokenName)) {
                if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusIP = Status.BLOCK;
            } else if ((statusName == Status.INVALID || statusName == Status.GENERIC) && (statusIP == Status.CLOSED || statusIP == Status.RED || statusIP == Status.YELLOW)) {
                if (Block.tryAdd(ip)) {
                    Server.logDebug("new BLOCK '" + ip + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusIP = Status.BLOCK;
            } else if (statusIP == Status.BLOCK && (statusName == Status.YELLOW || statusName == Status.RED)) {
                if (Block.tryAdd(tokenName)) {
                    Server.logDebug("new BLOCK '" + tokenName + "' added by '" + tokenName + ";" + statusName + "'.");
                }
                statusName = Status.BLOCK;
            } else if (statusIP == Status.BLOCK && (statusName == Status.PROVIDER || statusName == Status.IGNORE || statusName == Status.WHITE)) {
                String cidr;
                int mask = SubnetIPv4.isValidIPv4(ip) ? 32 : 64;
                if ((cidr = Block.clearCIDR(ip, mask)) != null) {
                    Server.logInfo("false positive BLOCK '" + cidr + "' detected by '" + tokenName + ";" + statusName + "'.");
                }
                if (Provider.containsCIDR(ip)) {
                    statusIP = Status.PROVIDER;
                } else if (Ignore.containsCIDR(ip)) {
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
            } else if (statusIP == Status.DNSBL && (statusName == Status.PROVIDER || statusName == Status.IGNORE || statusName == Status.WHITE)) {
                if (hasAccessSMTP(ip) && (response = getResponseSMTP(ip, 25, timeout)) instanceof Status) {
                    statusIP = (Status) response;
                } else if (dist == null) {
                    statusIP = Status.GREEN;
                } else {
                    statusIP = Status.valueOf(dist.getStatus(ip).name());
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
                addCluster(convertHostToMask(tokenName), statusName, dist);
                addCluster(extractTLD(tokenName), statusName, dist);
                addCluster(Domain.getOwnerID(tokenName), statusName, dist);
            }
            addCluster(Subnet.normalizeCIDR(ip + (ipv4 ? "/24" : "/56")), statusIP, dist);
        } catch (Exception ex) {
            builder.append("ERROR");
            Server.logError(ex);
        }
    }
    
    private static final TreeMap<String,Short[]> clusterMap = new TreeMap<String,Short[]>(); // Mapa dos agrupamentos.
    
    private static synchronized void addCluster(String token, Status status, Distribution dist) {
        try {
            if (token != null) {
                Short[] clusterDist = clusterMap.get(token);
                if (clusterDist == null) {
                    clusterDist = new Short[2];
                    clusterDist[0] = 0;
                    clusterDist[1] = 0;
                    clusterMap.put(token, clusterDist);
                }
                int ham = clusterDist[0];
                int spam = clusterDist[1];
                if (dist != null) {
                    ham += dist.getHAM();
                    spam += dist.getSPAM();
                }
                switch (status) {
                    case WHITE: case GREEN: case PROVIDER: case IGNORE:
                        ham++;
                        break;
                    case BLOCK: case RED: case DNSBL: case NXDOMAIN: case DYNAMIC:
                        spam++;
                        break;
                }
                while (ham + spam > Short.MAX_VALUE) {
                    ham /= 2;
                    spam /= 2;
                }
                clusterDist[0] = (short) ham;
                clusterDist[1] = (short) spam;
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    protected static synchronized TreeMap<String,Short[]> getClusterCloneMap() {
        TreeMap<String,Short[]> cloneMap = new TreeMap<String,Short[]>();
        cloneMap.putAll(clusterMap);
        return cloneMap;
    }

    protected static void dumpClusterRED(StringBuilder builder) {
        TreeMap<String,Short[]> map = getClusterCloneMap();
        for (String token : map.keySet()) {
            Short[] dist = map.get(token);
            int spam = dist[1];
            if (spam > 512) {
                int ham = dist[0];
                float total = ham + spam;
                float reputation = spam / total;
                if (reputation > 0.9375f) {
                    if (!Generic.containsGenericExact(token)) {
                        if (!Block.contains(token)) {
                            builder.append(token);
                            builder.append(' ');
                            builder.append(ham);
                            builder.append(' ');
                            builder.append(spam);
                            builder.append('\n');
                        }
                    }
                }
            }
        }
    }
    
    protected static void dumpClusterTLD(StringBuilder builder) {
        TreeMap<String,Short[]> map = getClusterCloneMap();
        for (String token : map.keySet()) {
            Short[] dist = map.get(token);
            int spam = dist[1];
            if (spam > 128) {
                int ham = dist[0];
                float total = ham + spam;
                float reputation = spam / total;
                if (reputation > 0.5f) {
                    if (Domain.isOfficialTLD(token)) {
                        builder.append(token);
                        builder.append(' ');
                        builder.append(ham);
                        builder.append(' ');
                        builder.append(spam);
                        builder.append('\n');
                    }
                }
            }
        }
    }
    
    protected static void dumpClusterMask(StringBuilder builder) {
        TreeMap<String,Short[]> map = getClusterCloneMap();
        for (String token : map.keySet()) {
            Short[] dist = map.get(token);
            int spam = dist[1];
            if (spam > 128) {
                int ham = dist[0];
                float total = ham + spam;
                float reputation = spam / total;
                if (reputation > 0.5f) {
                    if (Generic.containsGenericExact(token)) {
                        builder.append(token);
                        builder.append(' ');
                        builder.append(ham);
                        builder.append(' ');
                        builder.append(spam);
                        builder.append('\n');
                    }
                }
            }
        }
    }
    
    public static synchronized boolean isCusterRED(String token) {
        if (token == null) {
            return false;
        } else {
            Short[] dist = clusterMap.get(token);
            if (dist == null) {
                return false;
            } else {
                int spam = dist[1];
                if (spam > 512) {
                    int ham = dist[0];
                    float total = ham + spam;
                    float reputation = spam / total;
                    return reputation > 0.9375f;
                } else {
                    return false;
                }
            }
        }
    }
    
    public static boolean isCusterRED(String ip, String sender, String hostname) {
        if (isCusterRED(extractTLD(hostname))) {
            return true;
        } else if (isCusterRED(extractTLD(sender))) {
            return true;
        } else if (isCusterRED(convertHostToMask(hostname))) {
            return true;
        } else if (isCusterRED(Domain.getOwnerID(hostname))) {
            return true;
        } else if (isCusterRED(Domain.getOwnerID(sender))) {
            return true;
        } else {
            boolean ipv4 = SubnetIPv4.isValidIPv4(ip);
            String cidr = Subnet.normalizeCIDR(ip + (ipv4 ? "/24" : "/56"));
            return isCusterRED(cidr);
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
            Server.logTrace(getName() + " thread allocation.");
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
                Server.logTrace(getName() + " thread released.");
            }
        }
    }
    
    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing analise.set");
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
            try {
//                Server.logTrace("storing cluster.map");
                long time = System.currentTimeMillis();
                TreeMap<String,Short[]> map = getClusterCloneMap();
                File file = new File("./data/cluster.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
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
        time = System.currentTimeMillis();
        file = new File("./data/cluster.map");
        if (file.exists()) {
            try {
                TreeMap<String,Short[]> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String token : map.keySet()) {
                    Short[] value = map.get(token);
                    if (token.contains("#") || token.contains(".H.")) {
                        String hostname = token.replace("#", "0");
                        hostname = hostname.replace(".H.", ".0a.");
                        if (Domain.isHostname(hostname)) {
                            clusterMap.put(token, value);
                        }
                    } else if (Domain.isHostname(token)) {
                        String hostname = Domain.normalizeHostname(token, true);
                        if (Domain.isOfficialTLD(hostname)) {
                            clusterMap.put(hostname, value);
                        }
                    } else if (Owner.isOwnerID(token)) {
                        String ownerID = Owner.normalizeID(token);
                        clusterMap.put(ownerID, value);
                    } else if (Subnet.isValidCIDR(token)) {
                        clusterMap.put(token, value);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
