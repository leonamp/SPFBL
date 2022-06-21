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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import net.spfbl.core.Server;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Core;
import static net.spfbl.core.Regex.isValidCIDRv4;
import static net.spfbl.core.Regex.isValidCIDRv6;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;

/**
 * Representa a estrutura de reputação dos sistemas de envio.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class CIDR {
    
    public static boolean addHarmful(String ip) {
        return addOperation(ip, (byte) -4);
    }
    
    public static boolean addUndesirable(String ip) {
        return addOperation(ip, (byte) -2);
    }
    
    public static boolean addUnacceptable(String ip) {
        return addOperation(ip, (byte) -1);
    }
    
    public static boolean addAcceptable(String ip) {
        return addOperation(ip, (byte) 1);
    }
    
    public static boolean addDesirable(String ip) {
        return addOperation(ip, (byte) 2);
    }
    
    public static boolean addBeneficial(String ip) {
        return addOperation(ip, (byte) 4);
    }
    
    private static boolean addOperation(String ip, Byte value) {
        if (ip == null) {
            return false;
        } else if (value == null) {
            THREAD.add(ip);
            return true;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(ip, value));
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
            super("CIDRTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private void add(String ip) {
            SET.add(ip);
        }
        
        private void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notifyQueue();
        }
        
        private String pollNext(String ip) {
            if (ip == null || (ip = SET.higher(ip)) == null) {
                return SET.pollFirst();
            } else {
                SET.remove(ip);
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
                        String ip = entry.getKey();
                        if (isPublicIP(ip)) {
                            byte value = entry.getValue();
                            if (value < -1 && Ignore.containsIP(ip)) {
                                value = -1;
                            }
                            Flag flag;
                            if (ip.contains(":")) {
                                long address = SubnetIPv6.getAddressLong(ip);
                                byte mask = 0;
                                NodeReputation node = ROOTREP6;
                                node.add6(value, mask);
                                flag = node.refreshFlag6(address, mask, Flag.ACCEPTABLE);
                                while (mask < 64) {
                                    if ((address & (0x8000000000000000L >>> mask)) == 0) {
                                        node = node.newLeft6(mask);
                                    } else {
                                        node = node.newRigth6(mask);
                                    }
                                    if (node == null) {
                                        break;
                                    } else {
                                        mask++;
                                        node.add6(value, mask);
                                        flag = node.refreshFlag6(address, mask, flag);
                                    }
                                }
                            } else {
                                int address = SubnetIPv4.getAddressIP(ip);
                                byte mask = 0;
                                NodeReputation node = ROOTREP4;
                                node.add4(value, mask);
                                flag = node.refreshFlag4(address, mask, Flag.ACCEPTABLE);
                                while (mask < 32) {
                                    if ((address & (0x80000000 >>> mask)) == 0) {
                                        node = node.newLeft4(mask);
                                    } else {
                                        node = node.newRigth4(mask);
                                    }
                                    if (node == null) {
                                        break;
                                    } else {
                                        mask++;
                                        node.add4(value, mask);
                                        flag = node.refreshFlag4(address, mask, flag);
                                    }
                                }
                            }
                            if (value == -4 && flag == Flag.HARMFUL) {
                                Block.tryToDominoBlockIP(ip, "HARMFUL");
                            } else if (value == -4 && !Abuse.containsSubscribedIP(ip)) {
                                Block.tryToDominoBlockIP(ip, "HARMFUL");
                            } else if (value == -2 && flag == Flag.UNDESIRABLE) {
                                String fqdn = FQDN.discoverFQDN(ip);
                                if (fqdn == null || FQDN.isUndesirable(fqdn)) {
                                    Block.tryToDominoBlockIP(ip, "UNDESIRABLE");
                                }
                            } else if (value == 2 && flag == Flag.DESIRABLE) {
                                String fqdn = FQDN.discoverFQDN(ip);
                                if (fqdn != null && FQDN.isDesirable(fqdn)) {
                                    Block.clearCIDR(null, ip, "DESIRABLE");
                                }
                            } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                if (FQDN.containsKeyFQDN(ip)) {
                                    Block.clearCIDR(null, ip, "BENEFICIAL");
                                }
                            }
                        }
                    }
                    if ((lastIP = pollNext(lastIP)) != null) {
                        if (CIDR.value(lastIP) == null) {
                            String fqdn = FQDN.discoverFQDN(lastIP);
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
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
                
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String ip = entry.getKey();
                    Byte value = entry.getValue();
                    writer.write("QUEUE ");
                    writer.write(ip);
                    writer.write(' ');
                    writer.write(Byte.toString(value));
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
    }
    
    public static boolean isBeneficial(String ip) {
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.BENEFICIAL;
    }
    
    public static boolean isHarmful(String ip) {
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isBeneficialFQDN(String ip) {
        String fqnd = FQDN.getFQDN(ip, false);
        Flag flag = FQDN.getFlag(fqnd);
        return flag == Flag.BENEFICIAL;
    }
    
    public static boolean isUndesirable(String ip) {
        Flag flag = getFlag(ip);
        if (flag == Flag.HARMFUL) {
            return true;
        } else if (flag == Flag.UNDESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDesirable(String ip) {
        Flag flag = getFlag(ip);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.DESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static Flag getFlag(String ip) {
        if (ip == null) {
            return null;
        } else {
            Flag flag;
            if (ip.contains(":")) {
                long address = SubnetIPv6.getAddressLong(ip);
                byte mask = 0;
                NodeReputation node = ROOTREP6;
                flag = node.getFlag(ACCEPTABLE);
                while (mask < 64) {
                    if ((address & (0x8000000000000000L >>> mask)) == 0) {
                        node = node.getLeft();
                    } else {
                        node = node.getRigth();
                    }
                    if (node == null) {
                        break;
                    } else {
                        mask++;
                        Flag newFlag = node.getFlag(flag);
                        if (newFlag == null) {
                            break;
                        } else {
                            flag = newFlag;
                        }
                    }
                }
            } else {
                int address = SubnetIPv4.getAddressIP(ip);
                byte mask = 0;
                NodeReputation node = ROOTREP4;
                flag = node.getFlag(ACCEPTABLE);
                while (mask < 32) {
                    if ((address & (0x80000000 >>> mask)) == 0) {
                        node = node.getLeft();
                    } else {
                        node = node.getRigth();
                    }
                    if (node == null) {
                        break;
                    } else {
                        mask++;
                        Flag newFlag = node.getFlag(flag);
                        if (newFlag == null) {
                            break;
                        } else {
                            flag = newFlag;
                        }
                    }
                }
            }
            return flag;
        }
    }
    
    private static final File FILE = new File("./data/cidr.txt");
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
            Integer timeInt = TIME;
            TreeMap<Integer,Integer> timeMap = new TreeMap<>();
            timeMap.put(timeInt, timeInt);
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        StringTokenizer tokenizer = new StringTokenizer(line, " ");
                        String token = tokenizer.nextToken();
                        if (token.equals("ADD4")) {
                            String cidr = tokenizer.nextToken();
                            String value = tokenizer.nextToken();
                            if (value == null) {
                                timeInt = TIME;
                            } else if (value.equals("null")) {
                                timeInt = TIME;
                            } else {
                                int timeInt4 = Integer.parseInt(value);
                                if ((timeInt = timeMap.get(timeInt4)) == null) {
                                    timeMap.put(timeInt4, timeInt4);
                                }
                            }
                            put4(cidr, timeInt);
                        } else if (token.equals("ADD6")) {
                            String cidr = tokenizer.nextToken();
                            String value = tokenizer.nextToken();
                            if (value == null) {
                                timeInt = TIME;
                            } else if (value.equals("null")) {
                                timeInt = TIME;
                            } else {
                                int timeInt6 = Integer.parseInt(value);
                                if ((timeInt = timeMap.get(timeInt6)) == null) {
                                    timeMap.put(timeInt6, timeInt6);
                                }
                            }
                            put6(cidr, timeInt);
                        } else if (token.equals("DEL4")) {
                            String cidr = tokenizer.nextToken();
                            remove4(cidr);
                        } else if (token.equals("DEL6")) {
                            String cidr = tokenizer.nextToken();
                            remove6(cidr);
                        } else if (token.equals("REP4")) {
                            String cidr = tokenizer.nextToken();
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
                            NodeReputation.load4(cidr, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("REP6")) {
                            String cidr = tokenizer.nextToken();
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
                            NodeReputation.load6(cidr, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("QUEUE")) {
                            String ip = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(ip, value);
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
                    CIDR.store4(writer);
                    CIDR.store6(writer);
                    ROOTREP4.store4(writer, (int) 0, (byte) 0);
                    ROOTREP6.store6(writer, (long) 0, (byte) 0);
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
    
    private static Integer TIME = (int) (System.currentTimeMillis() >>> 32);
    
    private static void refreshIntegerTime() {
        int time = (int) (System.currentTimeMillis() >>> 32);
        if (TIME < time) {
            TIME = time;
        }
    }
    
    private static String normalizeCIDRv4(int address, byte mask) {
        int octet4 = address & 0xFF;
        address >>>= 8;
        int octet3 = address & 0xFF;
        address >>>= 8;
        int octet2 = address & 0xFF;
        address >>>= 8;
        int octet1 = address & 0xFF;
        return SubnetIPv4.normalizeCIDRv4(
                octet1 + "." + octet2 + "." +
                octet3 + "." + octet4 + "/" + mask
        );
    }
    
    private static String normalizeCIDRv6(BigInteger address, short mask) {
        int p8 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p7 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p6 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p5 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p4 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p3 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p2 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p1 = address.intValue() & 0xFFFF;
        return SubnetIPv6.normalizeCIDRv6(
                Integer.toHexString(p1) + ":" +
                Integer.toHexString(p2) + ":" +
                Integer.toHexString(p3) + ":" +
                Integer.toHexString(p4) + ":" +
                Integer.toHexString(p5) + ":" +
                Integer.toHexString(p6) + ":" +
                Integer.toHexString(p7) + ":" +
                Integer.toHexString(p8) + "/" + mask
        );
    }
    
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final int EXPIRATION = 4;
    
    private static final NodeMap ROOTMAP4 = new NodeMap();
    private static final NodeMap ROOTMAP6 = new NodeMap();
    
    /**
     * Reserved IP addresses.
     * These values cannot be overlapped and must return always FALSE.
     */
    static {
        put4("0.0.0.0/8", Boolean.FALSE); // Current network.
        put4("10.0.0.0/8", Boolean.FALSE); // Used for local communications within a private network.
        put4("100.64.0.0/10", Boolean.FALSE); // Shared getAddressIP space for communications between a service provider and its subscribers when using a carrier-grade NAT.
        put4("127.0.0.0/8", Boolean.FALSE); // Used for loopback addresses to the local host.
        put4("169.254.0.0/16", Boolean.FALSE); // Used for link-local addresses between two hosts on a single link when no IP getAddressIP is otherwise specified, such as would have normally been retrieved from a DHCP server.
        put4("172.16.0.0/12", Boolean.FALSE); // Used for local communications within a private network.
        put4("192.88.99.0/24", Boolean.FALSE); // Formerly used for IPv6 to IPv4 relay.
        put4("192.168.0.0/16", Boolean.FALSE); // Used for local communications within a private network.
        put4("198.18.0.0/15", Boolean.FALSE); // Used for benchmark testing of inter-network communications between two separate subnets.
        put4("198.51.100.0/24", Boolean.FALSE); // Assigned as TEST-NET-2, documentation and examples.
        put4("203.0.113.0/24", Boolean.FALSE); // Assigned as TEST-NET-3, documentation and examples.
        put4("224.0.0.0/4", Boolean.FALSE); // In use for IP multicast.
        put4("240.0.0.0/4", Boolean.FALSE); // Reserved for future use.
        put4("255.255.255.255/32", Boolean.FALSE); // Reserved for the "limited broadcast" destination getAddressIP.
        put6("::/64", Boolean.FALSE); // Used for loopback addresses to the local host.
        put6("::ffff:0:0/96", Boolean.FALSE); // IPv4 mapped addresses.
        put6("::ffff:0:0:0/96", Boolean.FALSE); // IPv4 translated addresses.
        put6("64:ff9b::/96", Boolean.FALSE); // IPv4/IPv6 translation.
        put6("100::/64", Boolean.FALSE); // Discard prefix.
        put6("2001::/32", Boolean.FALSE); // Teredo tunneling.
        put6("2001:20::/28", Boolean.FALSE); // ORCHIDv2.
        put6("2001:db8::/32", Boolean.FALSE); // Addresses used in documentation and example source code.
        put6("2002::/16", Boolean.FALSE); // The 6to4 addressing scheme.
        put6("fc00::/7", Boolean.FALSE); // Unique local getAddressIP.
        put6("fe80::/10", Boolean.FALSE); // Link-local getAddressIP.
        put6("ff00::/8", Boolean.FALSE); // Multicast addresses.
    }
    
    private static class NodeMap {
        
        private Object left = null;
        private Object rigth = null;
        
        private Object clearLeft() {
            Object element = left;
            left = null;
            return element;
        }
        
        private Object clearRigth() {
            Object element = rigth;
            rigth = null;
            return element;
        }
        
        private Object setLeft(Object value) {
            Object element = left;
            left = value;
            return element;
        }
        
        private Object setRigth(Object value) {
            Object element = rigth;
            rigth = value;
            return element;
        }
        
        private void setLeft(NodeMap node) {
            left = node;
        }
        
        private void setRigth(NodeMap node) {
            rigth = node;
        }
        
        private Object getLeft() {
            return left;
        }
        
        private Object getRigth() {
            return rigth;
        }
        
        private Object getNormalizedLeft() {
            Object element = left;
            if (element instanceof NodeMap && ((NodeMap)element).isNull()) {
                return left = null;
            } else {
                return element;
            }
        }
        
        private Object getNormalizedRigth() {
            Object element = rigth;
            if (element instanceof NodeMap && ((NodeMap)element).isNull()) {
                return rigth = null;
            } else {
                return element;
            }
        }
        
        private boolean isNull() {
            return left == null && rigth == null;
        }
    }
    
    public static boolean add(String cidr) {
        if (cidr == null) {
            return false;
        } else if (isValidCIDRv4(cidr)) {
            return put4(cidr, TIME);
        } else if (isValidCIDRv6(cidr)) {
            return put6(cidr, TIME);
        } else if (isValidIPv4(cidr)) {
            return put4(cidr + "/32", TIME);
        } else if (isValidIPv6(cidr)) {
            return put6(cidr + "/128", TIME);
        } else {
            return false;
        }
    }
    
    public static boolean addCIDR(String cidr) {
        if (cidr == null) {
            return false;
        } else if (isValidCIDRv4(cidr)) {
            return put4(cidr, TIME);
        } else if (isValidCIDRv6(cidr)) {
            return put6(cidr, TIME);
        } else {
            return false;
        }
    }
    
    public static boolean addIP(String ip) {
        if (ip == null) {
            return false;
        } else if (isValidIPv4(ip)) {
            return put4(ip + "/32", TIME);
        } else if (isValidIPv6(ip)) {
            return put6(ip + "/128", TIME);
        } else {
            return false;
        }
    }
    
    public static boolean remove(String cidr) {
        if (cidr == null) {
            return false;
        } else if (isValidCIDRv4(cidr)) {
            return remove4(cidr);
        } else if (isValidCIDRv6(cidr)) {
            return remove6(cidr);
        } else if (isValidIPv4(cidr)) {
            return remove4(cidr + "/32");
        } else if (isValidIPv6(cidr)) {
            return remove6(cidr + "/128");
        } else {
            return false;
        }
    }
    
    public static Object valueIPv4(String ipv4) {
        return value4(ipv4 + "/32");
    }
    
    public static Object valueIPv6(String ipv6) {
        return value6(ipv6 + "/128");
    }
    
    public static Object value(String cidr) {
        if (cidr == null) {
            return false;
        } else if (isValidCIDRv4(cidr)) {
            return value4(cidr);
        } else if (isValidCIDRv6(cidr)) {
            return value6(cidr);
        } else if (isValidIPv4(cidr)) {
            return value4(cidr + "/32");
        } else if (isValidIPv6(cidr)) {
            return value6(cidr + "/128");
        } else {
            return false;
        }
    }
    
    public static boolean contains(String cidr) {
        if (cidr == null) {
            return false;
        } else if (isValidCIDRv4(cidr)) {
            return contains4(cidr);
        } else if (isValidCIDRv6(cidr)) {
            return contains6(cidr);
        } else if (isValidIPv4(cidr)) {
            return contains4(cidr + "/32");
        } else if (isValidIPv6(cidr)) {
            return contains6(cidr + "/128");
        } else {
            return false;
        }
    }
    
    public static boolean containsIP(String ip) {
        if (ip == null) {
            return false;
        } else if (isValidIPv4(ip)) {
            return contains4(ip + "/32");
        } else if (isValidIPv6(ip)) {
            return contains6(ip + "/128");
        } else {
            return false;
        }
    }
    
    // Temporary method.
    public static boolean containsCIDRv6(String cidr) {
        return contains6(cidr);
    }
    
    // Temporary method.
    public static boolean addCIDRv6(String cidr) {
        return put6(cidr, TIME);
    }
    
    // Temporary method.
    public static boolean addIPv4(String ip) {
        return put4(ip + "/32", TIME);
    }
    
    public static String get(String token) {
        if (token == null) {
            return null;
        } else if (isValidIPv4(token)) {
            return get4(token + "/32");
        } else if (isValidCIDRv4(token)) {
            return get4(token);
        } else if (isValidIPv6(token)) {
            return get6(token + "/128");
        } else if (isValidCIDRv6(token)) {
            return get6(token);
        } else {
            return null;
        }
    }
    
    public static boolean isPublicIP(String ip) {
        if (ip == null) {
            return false;
        } else if (isValidIPv4(ip)) {
            return value4(ip + "/32") != Boolean.FALSE;
        } else if (isValidIPv6(ip)) {
            return value6(ip + "/128") != Boolean.FALSE;
        } else {
            return false;
        }
    }
    
    private static boolean put4(String cidr, Object value) {
        if (value == null) {
            value = (int) (System.currentTimeMillis() >>> 32);
        }
        NodeMap parent = ROOTMAP4;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.setLeft(value);
            parent.setRigth(value);
            return true;
        } else {
            LinkedList<NodeMap> stack = new LinkedList();
            stack.push(parent);
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element instanceof Integer) {
                    break;
                } else if (element instanceof Boolean) {
                    return false;
                } else {
                    NodeMap node = new NodeMap();
                    if ((address & 0x80000000) == 0) {
                        parent.setLeft(node);
                    } else {
                        parent.setRigth(node);
                    }
                    parent = node;
                }
                address <<= 1;
                stack.push(parent);
            }
            if ((address & 0x80000000) == 0) {
                element = parent.setLeft(value);
            } else {
                element = parent.setRigth(value);
            }
            if (value instanceof Boolean) {
                return true;
            } else if (element instanceof Integer) {
                return false;
            } else {
                append("ADD4 " + cidr + " " + value);
                while (!stack.isEmpty()) {
                    NodeMap child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left instanceof Integer && rigth instanceof Integer) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.setLeft(value);
                        } else {
                            parent.setRigth(value);
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private static boolean remove4(String cidr) {
        NodeMap parent = ROOTMAP4;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.clearLeft();
            parent.clearRigth();
            return true;
        } else {
            LinkedList<NodeMap> stack = new LinkedList();
            stack.push(parent);
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element == null) {
                    break;
                } else if (element instanceof Boolean) {
                    return false;
                } else {
                    NodeMap node = new NodeMap();
                    node.setLeft(TIME);
                    node.setRigth(TIME);
                    if ((address & 0x80000000) == 0) {
                        parent.setLeft(node);
                    } else {
                        parent.setRigth(node);
                    }
                    parent = node;
                }
                address <<= 1;
                stack.push(parent);
            }
            if ((address & 0x80000000) == 0) {
                element = parent.clearLeft();
            } else {
                element = parent.clearRigth();
            }
            if (element == null) {
                return false;
            } else {
                append("DEL4 " + cidr);
                while (!stack.isEmpty()) {
                    NodeMap child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left == null && rigth == null) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.clearLeft();
                        } else {
                            parent.clearRigth();
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private static boolean contains4(String cidr) {
        Object value = value4(cidr);
        if (value instanceof Integer) {
            return true;
        } else if (value instanceof Boolean) {
            return (Boolean) value;
        } else {
            return false;
        }
    }
    
    private static Object value4(String cidr) {
        NodeMap parent = ROOTMAP4;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            return left instanceof Integer && rigth instanceof Integer;
        } else {
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element instanceof Boolean) {
                    return element;
                } else {
                    break;
                }
                address <<= 1;
            }
            if ((address & 0x80000000) == 0) {
                element = parent.getLeft();
            } else {
                element = parent.getRigth();
            }
            if (element instanceof Integer) {
                if ((address & 0x80000000) == 0) {
                    parent.setLeft(TIME);
                } else {
                    parent.setRigth(TIME);
                }
                return TIME;
            } else if (element instanceof Boolean) {
                return element;
            } else {
                return null;
            }
        }
    }
    
    private static String get4(String cidr) {
        NodeMap parent = ROOTMAP4;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            if (left instanceof Integer && rigth instanceof Integer) {
                return "0.0.0.0/0";
            } else {
                return null;
            }
        } else {
            String ip = cidr.substring(0, index);
            int address = SubnetIPv4.getAddressIP(ip);
            Object element;
            byte mask;
            for (mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else {
                    break;
                }
                address <<= 1;
            }
            if ((address & 0x80000000) == 0) {
                element = parent.getLeft();
            } else {
                element = parent.getRigth();
            }
            if (element instanceof Integer) {
                if ((address & 0x80000000) == 0) {
                    parent.setLeft(TIME);
                } else {
                    parent.setRigth(TIME);
                }
                return SubnetIPv4.normalizeCIDRv4(ip + "/" + mask);
            } else if (element == Boolean.TRUE) {
                return SubnetIPv4.normalizeCIDRv4(ip + "/" + mask);
            } else {
                return null;
            }
        }
    }
    
    private static boolean put6(String cidr, Object value) {
        if (value == null) {
            value = (int) (System.currentTimeMillis() >>> 32);
        }
        NodeMap parent = ROOTMAP6;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.setLeft(value);
            parent.setRigth(value);
            return true;
        } else {
            LinkedList<NodeMap> stack = new LinkedList();
            stack.push(parent);
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element instanceof Integer) {
                    break;
                } else if (element instanceof Boolean) {
                    return false;
                } else {
                    NodeMap node = new NodeMap();
                    if (address.testBit(127)) {
                        parent.setRigth(node);
                    } else {
                        parent.setLeft(node);
                    }
                    parent = node;
                }
                address = address.shiftLeft(1);
                stack.push(parent);
            }
            if (address.testBit(127)) {
                element = parent.setRigth(value);
            } else {
                element = parent.setLeft(value);
            }
            if (value instanceof Boolean) {
                return true;
            } else if (element instanceof Integer) {
                return false;
            } else {
                append("ADD6 " + cidr + " " + value);
                while (!stack.isEmpty()) {
                    NodeMap child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left instanceof Integer && rigth instanceof Integer) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.setLeft(value);
                        } else {
                            parent.setRigth(value);
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private static boolean remove6(String cidr) {
        NodeMap parent = ROOTMAP6;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.clearLeft();
            parent.clearRigth();
            return true;
        } else {
            LinkedList<NodeMap> stack = new LinkedList();
            stack.push(parent);
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element == null) {
                    break;
                } else if (element instanceof Boolean) {
                    return false;
                } else {
                    NodeMap node = new NodeMap();
                    node.setLeft(TIME);
                    node.setRigth(TIME);
                    if (address.testBit(127)) {
                        parent.setRigth(node);
                    } else {
                        parent.setLeft(node);
                    }
                    parent = node;
                }
                address = address.shiftLeft(1);
                stack.push(parent);
            }
            if (address.testBit(127)) {
                element = parent.clearRigth();
            } else {
                element = parent.clearLeft();
            }
            if (element == null) {
                return false;
            } else {
                append("DEL6 " + cidr);
                while (!stack.isEmpty()) {
                    NodeMap child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left == null && rigth == null) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.clearLeft();
                        } else {
                            parent.clearRigth();
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private static boolean contains6(String cidr) {
        Object value = value6(cidr);
        if (value instanceof Integer) {
            return true;
        } else if (value instanceof Boolean) {
            return (Boolean) value;
        } else {
            return false;
        }
    }
    
    private static Object value6(String cidr) {
        NodeMap parent = ROOTMAP6;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            return left instanceof Integer && rigth instanceof Integer;
        } else {
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else if (element instanceof Boolean) {
                    return element;
                } else {
                    break;
                }
                address = address.shiftLeft(1);
            }
            if (address.testBit(127)) {
                element = parent.getRigth();
            } else {
                element = parent.getLeft();
            }
            if (element instanceof Integer) {
                if (address.testBit(127)) {
                    parent.setRigth(TIME);
                } else {
                    parent.setLeft(TIME);
                }
                return TIME;
            } else if (element instanceof Boolean) {
                return element;
            } else {
                return null;
            }
        }
    }
    
    private static String get6(String cidr) {
        NodeMap parent = ROOTMAP6;
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            if (left instanceof Integer && rigth instanceof Integer) {
                return "0:0:0:0:0:0:0:0/0";
            } else {
                return null;
            }
        } else {
            String ip = cidr.substring(0, index);
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(ip));
            Object element;
            short mask;
            for (mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof NodeMap) {
                    parent = (NodeMap) element;
                } else {
                    break;
                }
                address = address.shiftLeft(1);
            }
            if (address.testBit(127)) {
                element = parent.getRigth();
            } else {
                element = parent.getLeft();
            }
            if (element instanceof Integer) {
                if (address.testBit(127)) {
                    parent.setRigth(TIME);
                } else {
                    parent.setLeft(TIME);
                }
                return SubnetIPv6.normalizeCIDRv6(ip + "/" + mask);
            } else if (element == Boolean.TRUE) {
                return SubnetIPv6.normalizeCIDRv6(ip + "/" + mask);
            } else {
                return null;
            }
        }
    }
    
    private static void store4(FileWriter writer) throws IOException {
        LinkedList<NodeMap> stack = new LinkedList();
        stack.push(ROOTMAP4);
        Integer time = TIME - EXPIRATION;
        byte mask = 0;
        int address = 0;
        NodeMap actual;
        NodeMap previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address <<= 1;
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof NodeMap && rigth instanceof NodeMap) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((NodeMap) rigth);
                    address++;
                } else {
                    stack.push(actual);
                    stack.push((NodeMap) left);
                }
            } else if (!(left instanceof NodeMap) && rigth instanceof NodeMap) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("ADD4 ");
                            writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                            writer.write(' ');
                            writer.write(left.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((NodeMap) rigth);
                    address++;
                }
            } else if (left instanceof NodeMap && !(rigth instanceof NodeMap)) {
                if (left == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("ADD4 ");
                            writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                            writer.write(' ');
                            writer.write(rigth.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((NodeMap) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("ADD4 ");
                        writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                        writer.write(' ');
                        writer.write(left.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("ADD4 ");
                        writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                        writer.write(' ');
                        writer.write(rigth.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address >>>= 2;
            }
            previuos = actual;
        }
    }
    
    private static void store6(FileWriter writer) throws IOException {
        LinkedList<NodeMap> stack = new LinkedList();
        stack.push(ROOTMAP6);
        int time = TIME - EXPIRATION;
        short mask = 0;
        BigInteger address = BigInteger.valueOf(0);
        NodeMap actual;
        NodeMap previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address = address.shiftLeft(1);
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof NodeMap && rigth instanceof NodeMap) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((NodeMap) rigth);
                    address = address.add(ONE);
                } else {
                    stack.push(actual);
                    stack.push((NodeMap) left);
                }
            } else if (!(left instanceof NodeMap) && rigth instanceof NodeMap) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("ADD6 ");
                            writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                            writer.write(' ');
                            writer.write(left.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((NodeMap) rigth);
                    address = address.add(ONE);
                }
            } else if (left instanceof NodeMap && !(rigth instanceof NodeMap)) {
                if (left == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("ADD6 ");
                            writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                            writer.write(' ');
                            writer.write(rigth.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((NodeMap) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("ADD6 ");
                        writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                        writer.write(' ');
                        writer.write(left.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("ADD6 ");
                        writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                        writer.write(' ');
                        writer.write(rigth.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address = address.shiftRight(2);
            }
            previuos = actual;
        }
    }
    
    private static final NodeReputation ROOTREP4 = new NodeReputation();
    private static final NodeReputation ROOTREP6 = new NodeReputation();
    
    private static class NodeReputation extends Reputation {
        
        private static final int POPULATION4[] = {
            32768, 29127, 25891, 23014, 20457, 18184, 16163, 14368,
            12771, 11352, 10091, 8970, 7973, 7087, 6300, 5600,
            4977, 4424, 3933, 3496, 3107, 2762, 2455, 2182,
            1940, 1724, 1533, 1362, 1211, 1077, 957, 851, 756
        };
        
        private static final int POPULATION6[] = {
            65536, 61681, 58053, 54638, 51424, 48399, 45552, 42872,
            40350, 37977, 35743, 33640, 31662, 29799, 28046, 26396,
            24844, 23382, 22007, 20712, 19494, 18347, 17268, 16252,
            15296, 14396, 13550, 12753, 12002, 11296, 10632, 10007,
            9418, 8864, 8342, 7852, 7390, 6955, 6546, 6161,
            5799, 5457, 5136, 4834, 4550, 4282, 4030, 3793,
            3570, 3360, 3163, 2976, 2801, 2637, 2482, 2336,
            2198, 2069, 1947, 1833, 1725, 1623, 1528, 1438, 1353
        };
        
        private NodeReputation() {
            super();
        }
        
        private NodeReputation(NodeReputation other, float ajust) {
            super(other, ajust);
        }
        
        private Flag refreshFlag4(int address, byte mask, Flag defaultFlag) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION4[mask], mask <= 16
            );
            if (newFlag != oldFlag) {
                if (mask < 32) {
                    address &= ~(0xFFFFFFFF >>> mask);
                }
                String part1 = Integer.toString((address >>> 24) & 0xFF);
                String part2 = Integer.toString((address >>> 16) & 0xFF);
                String part3 = Integer.toString((address >>> 8) & 0xFF);
                String part4 = Integer.toString(address & 0xFF);
                String cidr = part1 + '.' + part2 + '.' + part3 + '.' + part4 + '/' + mask;
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP4 " + cidr + " " + xisArray[0] + " " + xisArray[1] + " "
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
        
        private Flag refreshFlag6(long address, byte mask, Flag defaultFlag) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION6[mask], mask <= 32
            );
            if (newFlag != oldFlag) {
                if (mask < 64) {
                    address &= ~(0xFFFFFFFFFFFFFFFFL >>> mask);
                }
                String part1 = Long.toString((address >>> 48) & 0xFFFF, 16);
                String part2 = Long.toString((address >>> 32) & 0xFFFF, 16);
                String part3 = Long.toString((address >>> 16) & 0xFFFF, 16);
                String part4 = Long.toString(address & 0xFFFF, 16);
                String cidr = part1 + ':' + part2 + ':' + part3 + ':' + part4 + "::/" + mask;
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP6 " + cidr + " " + xisArray[0] + " " + xisArray[1] + " "
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
        
        private void add4(int value, byte mask) {
            if (value == 4 && mask <= 24) {
                value = 2;
            } else if (value == -4 && mask <= 24) {
                value = -2;
            }
            if (value == 2 && mask <= 16) {
                value = 1;
            } else if (value == -2 && mask <= 16) {
                value = -1;
            }
            super.add(value, POPULATION4[mask]);
        }
        
        private void add6(int value, byte mask) {
            if (value == 4 && mask <= 48) {
                value = 2;
            } else if (value == -4 && mask <= 48) {
                value = -2;
            }
            if (value == 2 && mask <= 32) {
                value = 1;
            } else if (value == -2 && mask <= 32) {
                value = -1;
            }
            super.add(value, POPULATION6[mask]);
        }
        
        private NodeReputation left = null;
        private NodeReputation rigth = null;
        
        private synchronized NodeReputation getLeft() {
            return left;
        }
        
        private synchronized NodeReputation getRigth() {
            return rigth;
        }
       
        private NodeReputation newLeft4(byte mask) {
            return newLeft(1.125f, mask <= 24);
        }
        
        private NodeReputation newLeft6(byte mask) {
            return newLeft(1.0625f, mask <= 48);
        }
        
        private synchronized NodeReputation newLeft(float ajust, boolean reserved) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (flag == null) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.HARMFUL && minimum == -4 && maximum == -4) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.DESIRABLE && minimum == 2 && maximum == 2) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4) {
                clearChild();
                return null;
            } else if (left == null) {
                return left = new NodeReputation(this, ajust);
            } else {
                return left;
            }
        }
        
        private NodeReputation newRigth4(byte mask) {
            return newRigth(1.125f, mask <= 24);
        }
        
        private NodeReputation newRigth6(byte mask) {
            return newRigth(1.0625f, mask <= 48);
        }
        
        private synchronized NodeReputation newRigth(float ajust, boolean reserved) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (flag == null) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.HARMFUL && minimum == -4 && maximum == -4) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.DESIRABLE && minimum == 2 && maximum == 2) {
                clearChild();
                return null;
            } else if (!reserved && flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4) {
                clearChild();
                return null;
            } else if (rigth == null) {
                return rigth = new NodeReputation(this, ajust);
            } else {
                return rigth;
            }
        }
        
        private synchronized void clearChild() {
            left = null;
            rigth = null;
        }
        
        private synchronized void clearLeft() {
            left = null;
        }
        
        private synchronized void clearRigth() {
            rigth = null;
        }
        
        private static void load4(
                String cidr,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                short max = Subnet.getMask(cidr);
                String ip = SubnetIPv4.getFirstIPv4(cidr);
                int address = SubnetIPv4.getAddressIP(ip);
                NodeReputation node = ROOTREP4;
                for (byte mask = 0; mask < max; mask++) {
                    if ((address & (0x80000000 >>> mask)) == 0) {
                        node = node.newLeft4(mask);
                    } else {
                        node = node.newRigth4(mask);
                    }
                    if (node == null) {
                        break;
                    }
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private static void load6(
                String cidr,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                short max = Subnet.getMask(cidr);
                String ip = SubnetIPv6.getFirstIPv6(cidr);
                long address = SubnetIPv6.getAddressLong(ip);
                NodeReputation node = ROOTREP6;
                for (byte mask = 0; mask < max; mask++) {
                    if ((address & (0x8000000000000000L >>> mask)) == 0) {
                        node = node.newLeft6(mask);
                    } else {
                        node = node.newRigth6(mask);
                    }
                    if (node == null) {
                        break;
                    }
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void store4(FileWriter writer, int address, byte mask) throws IOException {
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REP4 ");
            writer.write(Integer.toString((address >>> 24) & 0xFF));
            writer.write('.');
            writer.write(Integer.toString((address >>> 16) & 0xFF));
            writer.write('.');
            writer.write(Integer.toString((address >>> 8) & 0xFF));
            writer.write('.');
            writer.write(Integer.toString(address & 0xFF));
            writer.write('/');
            writer.write(Byte.toString(mask));
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
                clearChild();
            } else if (mask > 24 && flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4) {
                clearChild();
            } else if (mask > 24 && flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2) {
                clearChild();
            } else if (mask > 24 && flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1) {
                clearChild();
            } else if (mask > 24 && flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1) {
                clearChild();
            } else if (mask > 24 && flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2) {
                clearChild();
            } else if (mask > 24 && flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4) {
                clearChild();
            } else if (mask < 32) {
                NodeReputation child;
                if ((child = getLeft()) != null) {
                    if (child.isExpired(EXPIRATION)) {
                        clearLeft();
                    } else {
                        child.store4(writer, address, (byte) (mask+1));
                    }
                }
                if ((child = getRigth()) != null) {
                    if (child.isExpired(EXPIRATION)) {
                        clearRigth();
                    } else {
                        child.store4(writer, address + (0x80000000 >>> mask), (byte) (mask+1));
                    }
                }
            }
        }
        
        private void store6(FileWriter writer, long address, byte mask) throws IOException {
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REP6 ");
            writer.write(Long.toString((address >>> 48) & 0xFFFF, 16));
            writer.write(':');
            writer.write(Long.toString((address >>> 32) & 0xFFFF, 16));
            writer.write(':');
            writer.write(Long.toString((address >>> 16) & 0xFFFF, 16));
            writer.write(':');
            writer.write(Long.toString(address & 0xFFFF, 16));
            writer.write(':');
            writer.write(':');
            writer.write('/');
            writer.write(Byte.toString(mask));
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
                clearChild();
            } else if (mask > 48 && flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4) {
                clearChild();
            } else if (mask > 48 && flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2) {
                clearChild();
            } else if (mask > 48 && flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1) {
                clearChild();
            } else if (mask > 48 && flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1) {
                clearChild();
            } else if (mask > 48 && flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2) {
                clearChild();
            } else if (mask > 48 && flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4) {
                clearChild();
            } else if (mask < 64) {
                NodeReputation child;
                if ((child = getLeft()) != null) {
                    if (child.isExpired(EXPIRATION)) {
                        clearLeft();
                    } else {
                        child.store6(writer, address, (byte) (mask+1));
                    }
                }
                if ((child = getRigth()) != null) {
                    if (child.isExpired(EXPIRATION)) {
                        clearRigth();
                    } else {
                        child.store6(writer, address + (0x8000000000000000L >>> mask), (byte) (mask+1));
                    }
                }
            }
        }
    }
}
