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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */

package net.spfbl.data;

import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
import net.spfbl.core.Server;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Properties;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import net.spfbl.core.Core;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Reverse;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;

/**
 * Represents the reputation structure of outgoing email systems.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class FQDN {
    
    private String name;
    private int last;
    
    private FQDN(String name) {
        this.name = name;
        this.last = TIME;
    }
    
    private FQDN(String name, int last) {
        this.name = name;
        this.last = last;
    }
    
    private static int TIME = (int) (System.currentTimeMillis() >>> 32);
    
    private static void refreshIntegerTime() {
        TIME = (int) (System.currentTimeMillis() >>> 32);
    }
    
    private boolean isExpired() {
        return TIME - last > 2;
    }
    
    public boolean equals(FQDN other) {
        if (other == null) {
            return false;
        } else if (this.last == other.last) {
            return this.name.equals(other.name);
        } else {
            return false;
        }
    }
    
    /**
     * General reputation map of outgoing email systems.
     */
    private static final HashMap<String,FQDN> MAP = new HashMap<>();
    
    private synchronized static boolean putFQDN(String key, String value) {
        if (key == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            FQDN fqdn = new FQDN(value);
            FQDN other = MAP.put(key, fqdn);
            if (fqdn.equals(other)) {
                return false;
            } else {
                append("PUT " + key + " " + fqdn.name + " " + fqdn.last);
                return true;
            }
        }
    }

    private synchronized static String dropFQDN(String key) {
        if (key == null) {
            return null;
        } else {
            FQDN fqdn = MAP.remove(key);
            if (fqdn == null) {
                return null;
            } else {
                append("DROP " + key + " " + fqdn.name);
                return fqdn.name;
            }
        }
    }
    
    public static String getFQDN(String key) {
        if (key == null) {
            return null;
        } else {
            FQDN fqdn = MAP.get(key);
            if (fqdn == null) {
                return null;
            } else {
                fqdn.last = TIME;
                return fqdn.name;
            }
        }
    }
    
    public static boolean containsKeyFQDN(String key) {
        if (key == null) {
            return false;
        } else {
            return MAP.containsKey(key);
        }
    }
    
    public synchronized static ArrayList<String> getKeyList() {
        int size = MAP.size();
        ArrayList<String> keySet = new ArrayList<>(size);
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    public static TreeMap<String,String> getMap() {
        TreeMap<String,String> map = new TreeMap<>();
        for (String ip : getKeyList()) {
            String fqdn = getFQDN(ip);
            if (fqdn != null) {
                map.put(ip, fqdn);
            }
        }
        return map;
    }
    
    public static boolean isFQDN(InetAddress address, String helo) {
        if (address == null) {
            return false;
        } else {
            return isFQDN(address.getHostAddress(), helo);
        }
    }
    
    public static boolean isFQDN(String ip, String helo) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return false;
        } else if ((helo = Domain.normalizeHostname(helo, false)) == null) {
            return false;
        } else {
            return helo.equals(getFQDN(ip));
        }
    }
    
    public static boolean hasFQDN(String ip) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return false;
        } else {
            return containsKeyFQDN(ip);
        }
    }
    
    public static String dropIP(String ip) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            return dropFQDN(ip);
        }
    }
    
    public static String discoverFQDN(String ip) {
        if (ip == null) {
            return null;
        } else if (CIDR.isPublicIP(ip)) {
            String fqdn = FQDN.getFQDN(ip, true);
            if (fqdn == null) {
                TreeSet<String> ptrSet = Reverse.getPointerSetSafe(ip, false);
                if (ptrSet == null || ptrSet.isEmpty()) {
                    return null;
                } else if (Generic.returnDynamicPTR(ptrSet) != null) {
                    return null;
                } else if ((fqdn = White.returnWhitePTR(ptrSet)) != null && FQDN.addFQDN(ip, fqdn, true)) {
                    return fqdn;
                } else if ((fqdn = Ignore.returnIgnorePTR(ptrSet)) != null && FQDN.addFQDN(ip, fqdn, true)) {
                    return fqdn;
                } else if ((fqdn = Provider.returnProviderPTR(ptrSet)) != null && FQDN.addFQDN(ip, fqdn, true)) {
                    return fqdn;
                } else if (Block.returnBlockedPTR(ptrSet) != null) {
                    return null;
                } else if (Block.containsCIDR(ip)) {
                    return null;
                } else {
                    String hostname = getBannerHostnameMultiport(ip, 30000, 25, 587);
                    if (FQDN.addFQDN(ip, hostname, true)) {
                        net.spfbl.data.Domain.usingSince(hostname);
                        return hostname;
                    } else if (Generic.returnGenericPTR(ptrSet) != null) {
                        return null;
                    } else if (ptrSet.size() == 1 && FQDN.addFQDN(ip, hostname = ptrSet.first(), true)) {
                        net.spfbl.data.Domain.usingSince(hostname);
                        return hostname;
                    } else {
                        return null;
                    }
                }
            } else {
                return fqdn;
            }
        } else {
            return null;
        }
    }
    
    private static String getBannerHostnameMultiport(String host, int timeout, int... ports) {
        if (host == null) {
            return null;
        } else if (ports == null) {
            return null;
        } else {
            for (int port : ports) {
                String hostname = getBannerHostname(host, port, timeout);
                if (hostname != null) {
                    return hostname;
                }
            }
            return null;
        }
    }
    
    private static String getBannerHostname(String host, int port, int timeout) {
        try {
            if (host == null) {
                return null;
            } else {
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
                    String hostname = response.substring(beginIndex, endIndex);
                    if (hostname.contains(".") && isHostname(hostname)) {
                        return Domain.normalizeHostname(hostname, false);
                    } else {
                        return null;
                    }
                }
            }
        } catch (MailConnectException ex) {
            return null;
        } catch (MessagingException ex) {
            return null;
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static String getFQDN(InetAddress ip, boolean checkNow) {
        if (ip == null) {
            return null;
        } else {
            return getFQDN(ip.getHostAddress(), checkNow);
        }
    }
    
    public static String getFQDN(String ip, boolean checkNow) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            String fqdn = getFQDN(ip);
            if (fqdn == null) {
                return null;
            } else if (checkNow) {
                return checkFQDN(ip, fqdn);
            } else {
                checkIP(ip);
                return fqdn;
            }
        }
    }
    
    private static String checkFQDN(String ip, String fqdn) {
        if (ip == null) {
            return null;
        } else if (fqdn == null) {
            return null;
        } else if (Generic.containsGenericFQDN(fqdn)) {
            dropFQDN(ip);
            return null;
        } else if (isValidIPv4(ip)) {
            try {
                TreeSet<String> addressSet = Reverse.getAddress4Set(fqdn);
                if (addressSet != null && addressSet.contains(ip)) {
                    return fqdn;
                } else {
                    dropFQDN(ip);
                    return null;
                }
            } catch (NameNotFoundException ex) {
                dropFQDN(ip);
                return null;
            } catch (NamingException ex) {
                return fqdn;
            }
        } else if (isValidIPv6(ip)) {
            try {
                TreeSet<String> addressSet = Reverse.getAddress6Set(fqdn);
                if (addressSet != null && addressSet.contains(ip)) {
                    return fqdn;
                } else {
                    dropFQDN(ip);
                    return null;
                }
            } catch (NameNotFoundException ex) {
                dropFQDN(ip);
                return null;
            } catch (NamingException ex) {
                return fqdn;
            }
        } else {
            return null;
        }
    }
    
    public static boolean addFQDN(InetAddress address, String fqdn, boolean check) {
        if (address == null) {
            return false;
        } else {
            return addFQDN(address.getHostAddress(), fqdn, check);
        }
    }
    
    public static boolean addFQDN(String ip, String fqdn, boolean check) {
        if (ip == null) {
            return false;
        } else if (fqdn == null) {
            return false;
        } else if (isValidIP(fqdn)) {
            return false;
        } else if ((ip = Subnet.normalizeIP(ip)) == null) {
            return false;
        } else if ((fqdn = Domain.normalizeHostname(fqdn, false)) == null) {
            return false;
        } else if (Subnet.isReservedIP(ip)) {
            return false;
        } else if (Generic.containsGenericFQDN(fqdn)) {
            return false;
        } else if (check && isValidIPv4(ip)) {
            try {
                TreeSet<String> addressSet = Reverse.getAddress4Set(fqdn);
                if (addressSet == null) {
                    return false;
                } else if (addressSet.contains(ip)) {
                    return putFQDN(ip, fqdn);
                } else {
                    return false;
                }
            } catch (NamingException ex) {
                return false;
            }
        } else if (check && isValidIPv6(ip)) {
            try {
                TreeSet<String> addressSet = Reverse.getAddress6Set(fqdn);
                if (addressSet == null) {
                    return false;
                } else if (addressSet.contains(ip)) {
                    return putFQDN(ip, fqdn);
                } else {
                    return false;
                }
            } catch (NamingException ex) {
                return false;
            }
        } else if (fqdn.equals(getFQDN(ip))) {
            return true;
        } else {
            return putFQDN(ip, fqdn);
        }
    }
    
    private static final File FILE = new File("./data/fqdn.txt");
    private static Writer WRITER = null;
    private static final LinkedList<String> LIST = new LinkedList<>();
    private static final Semaphore SEMAPHORE = new Semaphore(0);
    
    private static void append(String line) {
        if (SEMAPHORE.tryAcquire()) {
            try {
                writeList();
                WRITER.append(line);
                WRITER.write('\n');
                WRITER.flush();
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                SEMAPHORE.release();
            }
        } else {
            LIST.offer(line);
        }
    }
    
    private static void writeList() {
        try {
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line);
                WRITER.write('\n');
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private static void startWriter() {
        try {
            WRITER = new FileWriter(FILE, true);
            writeList();
            if (Core.isRunning()) {
                WRITER.flush();
            } else {
                WRITER.close();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            if (Core.isRunning()) {
                SEMAPHORE.release();
            }
        }
    }
    
    public static void load() {
        long time = System.currentTimeMillis();
        if (FILE.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        StringTokenizer tokenizer = new StringTokenizer(line, " ");
                        String token = tokenizer.nextToken();
                        if (token.equals("PUT")) {
                            String ip = tokenizer.nextToken();
                            String name = tokenizer.nextToken();
                            int last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                            FQDN fqdn = new FQDN(name, last);
                            MAP.put(ip, fqdn);
                        } else if (token.equals("DROP")) {
                            String ip = tokenizer.nextToken();
                            MAP.remove(ip);
                        } else if (token.equals("REP")) {
                            String zone = tokenizer.nextToken();
                            float xiSum = Float.parseFloat(tokenizer.nextToken());
                            float xi2Sum = Float.parseFloat(tokenizer.nextToken());
                            int last = Integer.parseInt(tokenizer.nextToken());
                            String flag = tokenizer.nextToken();
                            byte min = 0;
                            byte max = 0;
                            if (tokenizer.hasMoreTokens()) {
                                min = Byte.parseByte(tokenizer.nextToken());
                                max = Byte.parseByte(tokenizer.nextToken());
                            }
                            Node.load(zone, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("QUEUE")) {
                            String fqdn = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(fqdn, value);
                        }
                    } catch (Exception ex) {
                        Server.logError(line);
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, FILE);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        startWriter();
    }

    public static boolean store() {
        refreshIntegerTime();
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    for (String ip : getKeyList()) {
                        FQDN fqdn = MAP.get(ip);
                        if (fqdn == null) {
                            dropFQDN(ip);
                        } else if (fqdn.isExpired()) {
                            dropFQDN(ip);
                        } else {
                            writer.write("PUT ");
                            writer.write(ip);
                            writer.write(' ');
                            writer.write(fqdn.name);
                            writer.write(' ');
                            writer.write(Integer.toString(fqdn.last));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    ROOT.store(writer, ".");
                    THREAD.store(writer);
                }
                Files.move(temp, source, REPLACE_EXISTING);
                Server.logStore(time, FILE);
                return true;
            } finally {
                startWriter();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static final Node ROOT = new Node();
    
    public static boolean addHarmful(String fqdn) {
        return addOperation(fqdn, (byte) -4);
    }
    
    public static boolean addUndesirable(String fqdn) {
        return addOperation(fqdn, (byte) -2);
    }
    
    public static boolean addUnacceptable(String fqdn) {
        return addOperation(fqdn, (byte) -1);
    }
    
    public static boolean addAcceptable(String fqdn) {
        return addOperation(fqdn, (byte) 1);
    }
    
    public static boolean addDesirable(String fqdn) {
        return addOperation(fqdn, (byte) 2);
    }
    
    public static boolean addBeneficial(String fqdn) {
        return addOperation(fqdn, (byte) 4);
    }
    
    public static boolean checkIP(String ip) {
        if (ip == null) {
            return false;
        } else {
            return addOperation(ip, null);
        }
    }
    
    public static boolean checkIdentifiedIP(String ip) {
        if (ip == null) {
            return false;
        } else if (FQDN.containsKeyFQDN(ip)) {
            return addOperation(ip, null);
        } else {
            return false;
        }
    }
    
    private static boolean addOperation(String key, Byte value) {
        if (key == null) {
            return false;
        } else if (value == null) {
            THREAD.add(key);
            return true;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(key, value));
            return true;
        }
    }
    
    private static final ProcessThread THREAD = new ProcessThread();
    
    public static void startThread() {
        THREAD.start();
    }
    
    public static void terminateThread() {
        THREAD.terminate();
    }
    
    private static class ProcessThread extends Thread {
        
        private final TreeSet<String> SET = new TreeSet<>();
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private boolean run = true;
        
        private ProcessThread() {
            super("FQDNTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private synchronized void add(String ip) {
            SET.add(ip);
        }
        
        private synchronized String higher(String ip) {
            return SET.higher(ip);
        }
        
        private synchronized String pollFirst() {
            return SET.pollFirst();
        }
        
        private synchronized boolean remove(String ip) {
            return SET.remove(ip);
        }
        
        private void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notifyQueue();
        }
        
        private String pollNext(String ip) {
            if (ip == null || (ip = higher(ip)) == null) {
                return pollFirst();
            } else {
                remove(ip);
                return ip;
            }
        }
        
        private SimpleImmutableEntry poll() {
            return QUEUE.poll();
        }
        
        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        private boolean continueRun() {
            return run;
        }
        
        public void terminate() {
            run = false;
            notifyQueue();
        }
        
        public synchronized void notifyQueue() {
            notify();
        }
        
        @Override
        public void run() {
            try {
                Server.logTrace("thread started.");
                String lastIP = null;
                SimpleImmutableEntry<String,Byte> entry;
                while (Core.isRunning() && continueRun()) {
                    while (Core.isRunning() && (entry = poll()) != null) {
                        String fqdn = entry.getKey();
                        if (!isValidIPv4(fqdn) && !Generic.containsGenericFQDN(fqdn)) {
                            byte value = entry.getValue();
                            if (value < -1 && Ignore.containsFQDN(fqdn)) {
                                value = -1;
                            } else if (value == -4 && Provider.containsFQDN(fqdn)) {
                                value = -2;
                            } else if (value == 4 && Provider.containsFQDN(fqdn)) {
                                value = 2;
                            }
                            int level = 0;
                            LinkedList<String> stack = new LinkedList<>();
                            StringTokenizer tokenizer = new StringTokenizer(fqdn, ".");
                            while (tokenizer.hasMoreTokens()) {
                                stack.push(tokenizer.nextToken());
                            }
                            Node reputation = ROOT;
                            String zone = ".";
                            reputation.addValue(zone, value, level);
                            Flag flag = reputation.refreshFlag(zone, level, Flag.ACCEPTABLE);
                            while (!stack.isEmpty()) {
                                if (++level > 7) {
                                    break;
                                } else {
                                    String key = stack.pop();
                                    reputation = reputation.newReputation(zone, key);
                                    if (reputation == null) {
                                        break;
                                    } else {
                                        zone += key + '.';
                                        reputation.addValue(zone, value, level);
                                        flag = reputation.refreshFlag(zone, level, flag);
                                    }
                                }
                            }
                            if (value == -4 && flag == Flag.HARMFUL) {
                                White.dropFQDN(fqdn);
                                if (Block.addFQDN(fqdn, "HARMFUL")) {
                                    for (String ip : Reverse.getAddressSetSafe(fqdn)) {
                                        Block.tryToDominoBlockIP(ip, zone + ";HARMFUL");
                                    }
                                }
                            } else if (value == -2 && flag == Flag.UNDESIRABLE) {
                                if (!Block.containsFQDN(fqdn)) {
                                    for (String ip : Reverse.getAddressSetSafe(fqdn)) {
                                        if (CIDR.isUndesirable(ip)) {
                                            White.dropFQDN(fqdn);
                                            Block.addFQDN(fqdn, "UNDESIRABLE");
                                            Block.tryToDominoBlockIP(ip, zone + ";UNDESIRABLE");
                                        }
                                    }
                                }
                            } else if (value == 2 && flag == Flag.DESIRABLE) {
                                if (Block.containsFQDN(fqdn)) {
                                    for (String ip : Reverse.getAddressSetSafe(fqdn)) {
                                        if (CIDR.isDesirable(ip)) {
                                            Block.clearFQDN(null, fqdn, "DESIRABLE");
                                            Block.clearCIDR(null, ip, "DESIRABLE");
                                        }
                                    }
                                }
                            } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                if (Block.clearFQDN(null, fqdn, "BENEFICIAL")) {
                                    for (String ip : Reverse.getAddressSetSafe(fqdn)) {
                                        if (FQDN.isFQDN(ip, fqdn)) {
                                            Block.clearCIDR(null, ip, "BENEFICIAL");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if ((lastIP = pollNext(lastIP)) != null) {
                        if (isValidIP(lastIP)) {
                            String fqdn = FQDN.getFQDN(lastIP);
                            if (fqdn != null) {
                                FQDN.checkFQDN(lastIP, fqdn);
                            } else if (CIDR.value(lastIP) == null) {
                                fqdn = FQDN.discoverFQDN(lastIP);
                                if (fqdn == null) {
                                    Block.tryToDominoBlockIP(lastIP, "INVALID");
                                } else if (Block.containsFQDN(fqdn)) {
                                    Block.tryToDominoBlockIP(lastIP, "BLOCK");
                                } else if (Reputation.isHarmful(lastIP, fqdn)) {
                                    Block.tryToDominoBlockIP(lastIP, "HARMFUL");
                                } else {
                                    net.spfbl.data.Domain.usingSince(fqdn);
                                }
                            }
                        }
                    }
                    waitNext();
                }
                
            } finally {
                Server.logTrace("thread closed.");
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            SimpleImmutableEntry<String,Byte> entry;
            while ((entry = poll()) != null) {
                String fqdn = entry.getKey();
                Byte value = entry.getValue();
                writer.write("QUEUE ");
                writer.write(fqdn);
                if (value != null) {
                    writer.write(' ');
                    writer.write(Byte.toString(value));
                }
                writer.write('\n');
                writer.flush();
            }
            String ip = null;
            while ((ip = pollNext(ip)) != null) {
                writer.write("QUEUE ");
                writer.write(ip);
                writer.write('\n');
                writer.flush();
            }
        }
    }
    
    public static boolean isBeneficial(String fqdn) {
        Flag flag = getFlag(fqdn);
        return flag == Flag.BENEFICIAL;
    }
    
    public static boolean isHarmful(String fqdn) {
        Flag flag = getFlag(fqdn);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isUndesirable(String fqdn) {
        Flag flag = getFlag(fqdn);
        if (flag == Flag.HARMFUL) {
            return true;
        } else if (flag == Flag.UNDESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDesirable(String fqdn) {
        Flag flag = getFlag(fqdn);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.DESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static Flag getFlag(String ip, boolean check) {
        String fqdn = getFQDN(ip, check);
        return getFlag(fqdn);
    }
    
    public static Flag getFlag(String fqdn) {
        if (fqdn == null) {
            return Flag.UNACCEPTABLE;
        } else {
            LinkedList<String> stack = new LinkedList<>();
            StringTokenizer tokenizer = new StringTokenizer(fqdn, ".");
            while (tokenizer.hasMoreTokens()) {
                stack.push(tokenizer.nextToken());
            }
            Node node = ROOT;
            Flag flag = node.getFlag(ACCEPTABLE);
            while (!stack.isEmpty()) {
                String key = stack.pop();
                node = node.getReputation(key);
                if (node == null) {
                    break;
                } else {
                    Flag newFlag = node.getFlag(flag);
                    if (newFlag == null) {
                        break;
                    } else {
                        flag = newFlag;
                    }
                }
            }
            if (flag == Flag.HARMFUL || flag == Flag.UNDESIRABLE) { // Temporary.
                if (Ignore.containsFQDN(fqdn) || Provider.containsFQDN(fqdn)) {
                    return Flag.UNACCEPTABLE;
                }
            }
            return flag;
        }
    }
    
    protected static final HashSet<String> RESERVED = new HashSet<>();
    
    static {
        RESERVED.add(".");
        RESERVED.add(".com.");
        RESERVED.add(".org.");
        RESERVED.add(".net.");
        RESERVED.add(".edu.");
        RESERVED.add(".gov.");
        RESERVED.add(".mil.");
        RESERVED.add(".ac.");
        RESERVED.add(".ad.");
        RESERVED.add(".ae.");
        RESERVED.add(".af.");
        RESERVED.add(".ag.");
        RESERVED.add(".ai.");
        RESERVED.add(".al.");
        RESERVED.add(".am.");
        RESERVED.add(".ao.");
        RESERVED.add(".aq.");
        RESERVED.add(".ar.");
        RESERVED.add(".as.");
        RESERVED.add(".at.");
        RESERVED.add(".au.");
        RESERVED.add(".aw.");
        RESERVED.add(".ax.");
        RESERVED.add(".az.");
        RESERVED.add(".ba.");
        RESERVED.add(".bb.");
        RESERVED.add(".bd.");
        RESERVED.add(".be.");
        RESERVED.add(".bf.");
        RESERVED.add(".bg.");
        RESERVED.add(".bh.");
        RESERVED.add(".bi.");
        RESERVED.add(".bj.");
        RESERVED.add(".bm.");
        RESERVED.add(".bn.");
        RESERVED.add(".bo.");
        RESERVED.add(".br.");
        RESERVED.add(".bs.");
        RESERVED.add(".bt.");
        RESERVED.add(".bw.");
        RESERVED.add(".by.");
        RESERVED.add(".bz.");
        RESERVED.add(".ca.");
        RESERVED.add(".cc.");
        RESERVED.add(".cd.");
        RESERVED.add(".cf.");
        RESERVED.add(".cg.");
        RESERVED.add(".ch.");
        RESERVED.add(".ci.");
        RESERVED.add(".ck.");
        RESERVED.add(".cl.");
        RESERVED.add(".cm.");
        RESERVED.add(".cn.");
        RESERVED.add(".co.");
        RESERVED.add(".cr.");
        RESERVED.add(".cu.");
        RESERVED.add(".cv.");
        RESERVED.add(".cw.");
        RESERVED.add(".cx.");
        RESERVED.add(".cy.");
        RESERVED.add(".cz.");
        RESERVED.add(".de.");
        RESERVED.add(".dj.");
        RESERVED.add(".dk.");
        RESERVED.add(".dm.");
        RESERVED.add(".do.");
        RESERVED.add(".dz.");
        RESERVED.add(".ec.");
        RESERVED.add(".ee.");
        RESERVED.add(".eg.");
        RESERVED.add(".er.");
        RESERVED.add(".es.");
        RESERVED.add(".et.");
        RESERVED.add(".eu.");
        RESERVED.add(".fi.");
        RESERVED.add(".fj.");
        RESERVED.add(".fk.");
        RESERVED.add(".fm.");
        RESERVED.add(".fo.");
        RESERVED.add(".fr.");
        RESERVED.add(".ga.");
        RESERVED.add(".gd.");
        RESERVED.add(".ge.");
        RESERVED.add(".gf.");
        RESERVED.add(".gg.");
        RESERVED.add(".gh.");
        RESERVED.add(".gi.");
        RESERVED.add(".gl.");
        RESERVED.add(".gm.");
        RESERVED.add(".gn.");
        RESERVED.add(".gp.");
        RESERVED.add(".gq.");
        RESERVED.add(".gr.");
        RESERVED.add(".gs.");
        RESERVED.add(".gt.");
        RESERVED.add(".gu.");
        RESERVED.add(".gw.");
        RESERVED.add(".gy.");
        RESERVED.add(".hk.");
        RESERVED.add(".hm.");
        RESERVED.add(".hn.");
        RESERVED.add(".hr.");
        RESERVED.add(".ht.");
        RESERVED.add(".hu.");
        RESERVED.add(".id.");
        RESERVED.add(".ie.");
        RESERVED.add(".il.");
        RESERVED.add(".im.");
        RESERVED.add(".in.");
        RESERVED.add(".io.");
        RESERVED.add(".iq.");
        RESERVED.add(".ir.");
        RESERVED.add(".is.");
        RESERVED.add(".it.");
        RESERVED.add(".je.");
        RESERVED.add(".jm.");
        RESERVED.add(".jo.");
        RESERVED.add(".jp.");
        RESERVED.add(".ke.");
        RESERVED.add(".kg.");
        RESERVED.add(".kh.");
        RESERVED.add(".ki.");
        RESERVED.add(".km.");
        RESERVED.add(".kn.");
        RESERVED.add(".kp.");
        RESERVED.add(".kr.");
        RESERVED.add(".kw.");
        RESERVED.add(".ky.");
        RESERVED.add(".kz.");
        RESERVED.add(".la.");
        RESERVED.add(".lb.");
        RESERVED.add(".lc.");
        RESERVED.add(".li.");
        RESERVED.add(".lk.");
        RESERVED.add(".lr.");
        RESERVED.add(".ls.");
        RESERVED.add(".lt.");
        RESERVED.add(".lu.");
        RESERVED.add(".lv.");
        RESERVED.add(".ly.");
        RESERVED.add(".ma.");
        RESERVED.add(".mc.");
        RESERVED.add(".md.");
        RESERVED.add(".me.");
        RESERVED.add(".mg.");
        RESERVED.add(".mh.");
        RESERVED.add(".mk.");
        RESERVED.add(".ml.");
        RESERVED.add(".mm.");
        RESERVED.add(".mn.");
        RESERVED.add(".mo.");
        RESERVED.add(".mp.");
        RESERVED.add(".mq.");
        RESERVED.add(".mr.");
        RESERVED.add(".ms.");
        RESERVED.add(".mt.");
        RESERVED.add(".mu.");
        RESERVED.add(".mv.");
        RESERVED.add(".mw.");
        RESERVED.add(".mx.");
        RESERVED.add(".my.");
        RESERVED.add(".mz.");
        RESERVED.add(".na.");
        RESERVED.add(".nc.");
        RESERVED.add(".ne.");
        RESERVED.add(".nf.");
        RESERVED.add(".ng.");
        RESERVED.add(".ni.");
        RESERVED.add(".nl.");
        RESERVED.add(".no.");
        RESERVED.add(".np.");
        RESERVED.add(".nr.");
        RESERVED.add(".nu.");
        RESERVED.add(".nz.");
        RESERVED.add(".om.");
        RESERVED.add(".pa.");
        RESERVED.add(".pe.");
        RESERVED.add(".pf.");
        RESERVED.add(".pg.");
        RESERVED.add(".ph.");
        RESERVED.add(".pk.");
        RESERVED.add(".pl.");
        RESERVED.add(".pm.");
        RESERVED.add(".pn.");
        RESERVED.add(".pr.");
        RESERVED.add(".ps.");
        RESERVED.add(".pt.");
        RESERVED.add(".pw.");
        RESERVED.add(".py.");
        RESERVED.add(".qa.");
        RESERVED.add(".re.");
        RESERVED.add(".ro.");
        RESERVED.add(".rs.");
        RESERVED.add(".ru.");
        RESERVED.add(".rw.");
        RESERVED.add(".sa.");
        RESERVED.add(".sb.");
        RESERVED.add(".sc.");
        RESERVED.add(".sd.");
        RESERVED.add(".se.");
        RESERVED.add(".sg.");
        RESERVED.add(".sh.");
        RESERVED.add(".si.");
        RESERVED.add(".sk.");
        RESERVED.add(".sl.");
        RESERVED.add(".sm.");
        RESERVED.add(".sn.");
        RESERVED.add(".so.");
        RESERVED.add(".sr.");
        RESERVED.add(".ss.");
        RESERVED.add(".st.");
        RESERVED.add(".su.");
        RESERVED.add(".sv.");
        RESERVED.add(".sx.");
        RESERVED.add(".sy.");
        RESERVED.add(".sz.");
        RESERVED.add(".tc.");
        RESERVED.add(".td.");
        RESERVED.add(".tf.");
        RESERVED.add(".tg.");
        RESERVED.add(".th.");
        RESERVED.add(".tj.");
        RESERVED.add(".tk.");
        RESERVED.add(".tl.");
        RESERVED.add(".tm.");
        RESERVED.add(".tn.");
        RESERVED.add(".to.");
        RESERVED.add(".tr.");
        RESERVED.add(".tt.");
        RESERVED.add(".tv.");
        RESERVED.add(".tw.");
        RESERVED.add(".tz.");
        RESERVED.add(".ua.");
        RESERVED.add(".ug.");
        RESERVED.add(".uk.");
        RESERVED.add(".us.");
        RESERVED.add(".uy.");
        RESERVED.add(".uz.");
        RESERVED.add(".va.");
        RESERVED.add(".vc.");
        RESERVED.add(".ve.");
        RESERVED.add(".vg.");
        RESERVED.add(".vi.");
        RESERVED.add(".vn.");
        RESERVED.add(".vu.");
        RESERVED.add(".wf.");
        RESERVED.add(".ws.");
        RESERVED.add(".ye.");
        RESERVED.add(".yt.");
        RESERVED.add(".za.");
        RESERVED.add(".zm.");
        RESERVED.add(".zw.");
        RESERVED.add(".email");
        RESERVED.add(".info.");
        RESERVED.add(".online.");
        RESERVED.add(".digital.");
        RESERVED.add(".mobi.");
        RESERVED.add(".live.");
        RESERVED.add(".store.");
        RESERVED.add(".cloud.");
        RESERVED.add(".org.uk.");
        RESERVED.add(".app.br.");
        RESERVED.add(".io");
        RESERVED.add(".family");
    }

    private static class Node extends Reputation {
        
        private static final int POPULATION[] = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private Node() {
            super();
        }
        
        private Node(Node other) {
            super(other, 2.0f);
        }
        
        private void addValue(String zone, int value, int level) {
            if (value == 4 && Domain.containsTLD(Domain.revert(zone))) {
                value = 2;
            } else if (value == -4 && RESERVED.contains(zone)) {
                value = -2;
            }
            if (level == 0 && value > 1) {
                value = 1;
            }
            super.add(value, POPULATION[level]);
        }
        
        private TreeMap<String,Node> MAP = null;
        
        private synchronized Node newReputation(String zone, String key) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (key == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (flag == Flag.HARMFUL && minimum == -4 && maximum == -4 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else if (flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else if (flag == Flag.DESIRABLE && minimum == 2 && maximum == 2 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else if (flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4 && !RESERVED.contains(zone)) {
                MAP = null;
                return null;
            } else {
                Node node = null;
                if (MAP == null) {
                    MAP = new TreeMap<>();
                } else {
                    node = MAP.get(key);
                }
                if (node == null) {
                    node = new Node(this);
                    MAP.put(key, node);
                }
                return node;
            }
        }
        
        private synchronized void clearMap() {
            MAP = null;
        }
        
        private synchronized void dropMap(String key) {
            if (MAP != null) {
                MAP.remove(key);
                if (MAP.isEmpty()) {
                    MAP = null;
                }
            }
        }
        
        private synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAP != null) {
                keySet.addAll(MAP.keySet());
            }
            return keySet;
        }
        
        private synchronized Node getReputation(String key) {
            if (MAP == null) {
                return null;
            } else {
                return MAP.get(key);
            }
        }
        
        private Flag refreshFlag(String zone, int level, Flag defaultFlag) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION[level], RESERVED.contains(zone)
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP " + zone + " " + xisArray[0] + " " + xisArray[1] + " "
                                + last + " " + newFlag + " "
                                + extremes[0] + " " + extremes[1]
                );
            }
            if (newFlag == null) {
                return defaultFlag;
            } else {
                return newFlag;
            }
        }
        
        private static void load(
                String zone,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                if (flag.equals("BENEFICIAL") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "DESIRABLE";
                } else if (flag.equals("HARMFUL") && RESERVED.contains(zone)) {
                    flag = "UNDESIRABLE";
                }
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                Node node = ROOT;
                String zoneNode = ".";
                while (node != null && tokenizer.hasMoreTokens()) {
                    String key = tokenizer.nextToken();
                    node = node.newReputation(zoneNode, key);
                    zoneNode += key + '.';
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void store(FileWriter writer, String zone) throws IOException {
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REP ");
            writer.write(zone);
            writer.write(' ');
            writer.write(Float.toString(xiResult[0]));
            writer.write(' ');
            writer.write(Float.toString(xiResult[1]));
            writer.write(' ');
            writer.write(Integer.toString(last));
            writer.write(' ');
            writer.write(flag.toString());
            writer.write(' ');
            writer.write(Byte.toString(extremes[0]));
            writer.write(' ');
            writer.write(Byte.toString(extremes[1]));
            writer.write('\n');
            writer.flush();
            if (flag instanceof Integer) {
                clearMap();
            } else if (flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4 && !RESERVED.contains(zone)) {
                clearMap();
            } else if (flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2 && !RESERVED.contains(zone)) {
                clearMap();
            } else if (flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1 && !RESERVED.contains(zone)) {
                clearMap();
            } else if (flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1 && !RESERVED.contains(zone)) {
                clearMap();
            } else if (flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2 && !RESERVED.contains(zone)) {
                clearMap();
            } else if (flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4 && !RESERVED.contains(zone)) {
                clearMap();
            } else {
                for (String key : keySet()) {
                    Node reputation = getReputation(key);
                    if (reputation != null) {
                        if (reputation.isExpired()) {
                            dropMap(key);
                        } else {
                            reputation.store(writer, zone + key + '.');
                        }
                    }
                }
            }
        }
    }
}
