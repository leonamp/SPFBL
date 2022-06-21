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
import java.util.HashSet;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Core;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDRv4;
import static net.spfbl.core.Regex.isValidCIDRv6;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Reverse;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;

/**
 * Representa a estrutura de reputação dos sistemas de envio.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class URI {
    
    public static boolean addHarmful(String address) {
        return addOperation(address, (byte) -4);
    }
    
    public static boolean addUndesirable(String address) {
        return addOperation(address, (byte) -2);
    }
    
    public static boolean addUnacceptable(String address) {
        return addOperation(address, (byte) -1);
    }
    
    public static boolean addAcceptable(String address) {
        return addOperation(address, (byte) 1);
    }
    
    public static boolean addDesirable(String address) {
        return addOperation(address, (byte) 2);
    }
    
    public static boolean addBeneficial(String address) {
        return addOperation(address, (byte) 4);
    }
    
    private static boolean addOperation(String address, Byte value) {
        if (address == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(address, value));
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
        
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private boolean run = true;
        
        private ProcessThread() {
            super("URITHREAD");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notifyQueue();
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
                SimpleImmutableEntry<String,Byte> entry;
                while (Core.isRunning() && continueRun()) {
                    while (Core.isRunning() && (entry = poll()) != null) {
                        String key = entry.getKey();
                        byte value = entry.getValue();
                        if (isValidIP(key)) {
                            if (isPublicIP(key)) {
                                String ip = Subnet.normalizeIP(key);
                                Flag flag;
                                if (ip.contains(":")) {
                                    long address = SubnetIPv6.getAddressLong(ip);
                                    byte mask = 0;
                                    NodeIP node = ROOTREP6;
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
                                    NodeIP node = ROOTREP4;
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
                                    if (Block.addExact("HREF=" + ip)) {
                                        Server.logDebug(null, "new BLOCK 'HREF=" + ip + "' added by 'HARMFUL'.");
                                    }
                                } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                    if (Block.dropExact("HREF=" + ip)) {
                                        Server.logDebug(null, "false positive BLOCK 'HREF=" + ip + "' dropped by 'BENEFICIAL'.");
                                    }
                                }
                            }
                        } else if (Core.isSignatureURL(key)) {
                            String signature = key;
                            String host = Core.getSignatureHostURL(key);
                            Flag flag = URI.getFlag(host);
                            if (value == -4 && flag == Flag.HARMFUL) {
                                if (Block.addExact(signature)) {
                                    Server.logDebug(null, "new BLOCK '" + signature + "' added by 'HARMFUL'.");
                                }
                            } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                if (Block.dropExact(signature)) {
                                    Server.logDebug(null, "false positive BLOCK '" + signature + "' dropped by 'BENEFICIAL'.");
                                }
                            }
                            addOperation(host, value);
                        } else if (key.endsWith(".http")) {
                            Server.logError(key); // Temporary
                        } else if (key.endsWith(".https")) {
                            Server.logError(key); // Temporary
                        } else if (isHostname(key)) {
                            String domain = Domain.normalizeHostname(key, false);
                            TreeSet<String> addressSet = Reverse.getAddressSetSafe(domain);
                            if (addressSet.isEmpty()) {
                                if (Ignore.containsHost(domain)) {
                                    continue;
                                } else if (Provider.containsDomain(domain)) {
                                    continue;
                                } else if (value == -2 || value == -4) {
                                    String rootDomain = Domain.extractDomainSafeNotNull(domain, false);
                                    addressSet = Reverse.getAddressSetSafe(rootDomain);
                                    if (addressSet.isEmpty()) {
                                        domain = rootDomain;
                                    }
                                    if (Block.addExact("HREF=." + domain)) {
                                        Server.logDebug(null, "new BLOCK 'HREF=." + domain + "' added by 'NXDOMAIN'.");
                                    }
                                }
                            } else {
                                for (String ip : addressSet) {
                                    Flag flag = URI.getFlag(ip);
                                    if (value == -4 && flag == Flag.HARMFUL) {
                                        if (Block.addExact("HREF=." + domain)) {
                                            Server.logDebug(null, "new BLOCK 'HREF=." + domain + "' added by 'HARMFUL'.");
                                        }
                                        String url = "http://" + domain + "/";
                                        String signature = Core.getSignatureURL(url);
                                        if (Block.addExact(signature)) {
                                            Server.logDebug(null, "new BLOCK '" + signature + "' added by 'HARMFUL'.");
                                        }
                                    } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                        if (Block.dropExact("HREF=." + domain)) {
                                            Server.logDebug(null, "false positive BLOCK 'HREF=." + domain + "' dropped by 'BENEFICIAL'.");
                                        }
                                        String url = "http://" + domain + "/";
                                        String signature = Core.getSignatureURL(url);
                                        if (Block.dropExact(signature)) {
                                            Server.logDebug(null, "false positive BLOCK '" + signature + "' dropped by 'BENEFICIAL'.");
                                        }
                                    } else if (value == -2 && flag == Flag.UNDESIRABLE) {
                                        if (Block.addExact("HREF=." + domain)) {
                                            Server.logDebug(null, "new BLOCK 'HREF=." + domain + "' added by 'UNDESIRABLE'.");
                                        }
                                    } else if (value == 2 && flag == Flag.DESIRABLE) {
                                        if (Block.dropExact("HREF=." + domain)) {
                                            Server.logDebug(null, "false positive BLOCK 'HREF=." + domain + "' dropped by 'DESIRABLE'.");
                                        }
                                    }
                                    addOperation(ip, value);
                                }
                                int level = 0;
                                LinkedList<String> stack = new LinkedList<>();
                                StringTokenizer tokenizer = new StringTokenizer(domain, ".");
                                while (tokenizer.hasMoreTokens()) {
                                    stack.push(tokenizer.nextToken());
                                }
                                NodeDomain reputation = ROOTREPD;
                                String zone = ".";
                                reputation.addValue(zone, value, level);
                                Flag flag = reputation.refreshFlag(
                                        zone, level, Flag.ACCEPTABLE
                                );
                                while (!stack.isEmpty()) {
                                    if (++level > 7) {
                                        break;
                                    } else {
                                        String keyNode = stack.pop();
                                        reputation = reputation.newReputation(zone, keyNode);
                                        if (reputation == null) {
                                            break;
                                        } else {
                                            zone += keyNode + '.';
                                            reputation.addValue(zone, value, level);
                                            flag = reputation.refreshFlag(zone, level, flag);
                                        }
                                    }
                                }
                                if (value == -4 && flag == Flag.HARMFUL) {
                                    if (Block.addExact("HREF=." + domain)) {
                                        Server.logDebug(null, "new BLOCK 'HREF=." + domain + "' added by 'HARMFUL'.");
                                    }
                                    String url = "http://" + domain + "/";
                                    String signature = Core.getSignatureURL(url);
                                    if (Block.addExact(signature)) {
                                        Server.logDebug(null, "new BLOCK '" + signature + "' added by 'HARMFUL'.");
                                    }
                                } else if (value == 4 && flag == Flag.BENEFICIAL) {
                                    if (Block.dropExact("HREF=." + domain)) {
                                        Server.logDebug(null, "false positive BLOCK 'HREF=." + domain + "' dropped by 'BENEFICIAL'.");
                                    }
                                    String url = "http://" + domain + "/";
                                    String signature = Core.getSignatureURL(url);
                                    if (Block.dropExact(signature)) {
                                        Server.logDebug(null, "false positive BLOCK '" + signature + "' dropped by 'BENEFICIAL'.");
                                    }
                                } else if (value == -2 && flag == Flag.UNDESIRABLE) {
                                    if (Block.addExact("HREF=." + domain)) {
                                        Server.logDebug(null, "new BLOCK 'HREF=." + domain + "' added by 'UNDESIRABLE'.");
                                    }
                                } else if (value == 2 && flag == Flag.DESIRABLE) {
                                    if (Block.dropExact("HREF=." + domain)) {
                                        Server.logDebug(null, "false positive BLOCK 'HREF=." + domain + "' dropped by 'DESIRABLE'.");
                                    }
                                }
                            }
                        } else if (isValidEmail(key)) {
                            String email = Domain.normalizeEmail(key);
                            if (email != null) {
                                int index = email.indexOf('@');
                                String recipient = email.substring(0, index);
                                String domain = email.substring(index + 1);
                                if (Reverse.isRouteableForMail(domain)) {
                                    byte valueD = entry.getValue();
                                    byte valueR = entry.getValue();
                                    if (valueD < -1 && Ignore.containsExact('@' + domain)) {
                                        valueD = -1;
                                    } else if (valueD < -1 && Ignore.containsHost(domain)) {
                                        valueD = -1;
                                    } else if (valueD < -2 && Provider.containsDomain(domain)) {
                                        valueD = -2;
                                    }
        //                            Server.logTrace("reputation " + valueR + " " + email);
                                    int level = 0;
                                    LinkedList<String> stack = new LinkedList<>();
                                    StringTokenizer tokenizer = new StringTokenizer(domain, ".");
                                    while (tokenizer.hasMoreTokens()) {
                                        stack.push(tokenizer.nextToken());
                                    }
                                    NodeEmail reputationZ = ROOTREPE;
                                    String zone = ".";
                                    reputationZ.addValue(zone, valueD, level);
                                    Flag flag = reputationZ.refreshFlag(zone, level, Flag.ACCEPTABLE);
                                    while (!stack.isEmpty()) {
                                        if (++level > 7) {
                                            break;
                                        } else {
                                            key = stack.pop();
                                            reputationZ = reputationZ.newReputationZ(zone, key);
                                            if (reputationZ == null) {
                                                break;
                                            } else {
                                                zone += key + '.';
                                                reputationZ.addValue(zone, valueD, level);
                                                flag = reputationZ.refreshFlag(zone, level, flag);
                                            }
                                        }
                                    }
                                    if (valueD == -4 && flag == Flag.HARMFUL) {
                                        if (Block.addExact("HREF=@" + domain)) {
                                            Server.logDebug(null, "new BLOCK 'HREF=@" + domain + "' added by 'HARMFUL'.");
                                        }
                                    } else if (valueD == 4 && flag == Flag.BENEFICIAL) {
                                        if (Block.dropExact("HREF=@" + domain)) {
                                            Server.logDebug(null, "false positive BLOCK 'HREF=@" + domain + "' dropped by 'BENEFICIAL'.");
                                        }
                                    }
                                    if (reputationZ != null && stack.isEmpty()) {
                                        Reputation reputationR = reputationZ.newReputationR(
                                                recipient, level
                                        );
                                        if (reputationR != null) {
                                            reputationR.add(valueR, NodeEmail.POPULATIONR);
                                            index = zone.length() - 1;
                                            zone = zone.substring(0, index);
                                            zone += '@' + recipient;
                                            flag = NodeEmail.refreshFlag(zone, reputationR, flag);
                                            if (valueR == -4 && flag == Flag.HARMFUL) {
                                                if (Block.addExact("HREF=" + email)) {
                                                    Server.logDebug(null, "new BLOCK 'HREF=" + email + "' added by 'HARMFUL'.");
                                                }
                                            } else if (valueR == 4 && flag == Flag.BENEFICIAL) {
                                                if (Block.dropExact("HREF=" + email)) {
                                                    Server.logDebug(null, "false positive BLOCK 'HREF=" + email + "' dropped by 'BENEFICIAL'.");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            Server.logError("not defined HREF " + key);
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
                    if (value != null) {
                        writer.write(' ');
                        writer.write(Byte.toString(value));
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
    
    public static Flag getFlag(String token) {
        if (token == null) {
            return null;
        } else if (isPublicIP(token)) {
            String ip = token;
            Flag flag;
            if (ip.contains(":")) {
                long address = SubnetIPv6.getAddressLong(ip);
                byte mask = 0;
                NodeIP node = ROOTREP6;
                flag = node.getFlag();
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
                        Flag newFlag = node.getFlag();
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
                NodeIP node = ROOTREP4;
                flag = node.getFlag(Flag.ACCEPTABLE);
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
                        Flag newFlag = node.getFlag();
                        if (newFlag == null) {
                            break;
                        } else {
                            flag = newFlag;
                        }
                    }
                }
            }
            return flag;
        } else if (Core.isSignatureURL(token)) {
            String host = Core.getSignatureHostURL(token);
            return getFlag(host);
        } else if (isHostname(token)) {
            String domain = token;
            LinkedList<String> stack = new LinkedList<>();
            StringTokenizer tokenizer = new StringTokenizer(domain, ".");
            while (tokenizer.hasMoreTokens()) {
                stack.push(tokenizer.nextToken());
            }
            boolean inconclusive = false;
            NodeDomain node = ROOTREPD;
            Flag flag = node.getFlag(ACCEPTABLE);
            while (!stack.isEmpty()) {
                String key = stack.pop();
                node = node.getReputation(key);
                if (node == null) {
                    break;
                } else {
                    inconclusive = node.isInconclusive();
                    Flag newFlag = node.getFlag();
                    if (newFlag == null) {
                        break;
                    } else {
                        flag = newFlag;
                    }
                }
            }
            if (inconclusive) {
                boolean undesirable = flag.ordinal() < UNACCEPTABLE.ordinal();
                boolean desirable = flag.ordinal() > ACCEPTABLE.ordinal();
                TreeSet<Flag> flagSet = new TreeSet<>();
                flagSet.add(flag);
                for (String ip : Reverse.getAddressSetSafe(domain)) {
                    if ((flag = getFlag(ip)) != null) {
                        flagSet.add(flag);
                        switch (flag) {
                            case HARMFUL: case UNDESIRABLE:
                                undesirable = true;
                                break;
                            case BENEFICIAL: case DESIRABLE:
                                desirable = true;
                                break;
                        }
                    }
                }
                if (undesirable && desirable) {
                    return ACCEPTABLE;
                } else if (undesirable) {
                    return flagSet.first();
                } else if (desirable) {
                    return flagSet.last();
                } else {
                    return ACCEPTABLE;
                }
            } else {
                return flag;
            }
        } else if (isValidEmail(token)) {
            String email = Domain.normalizeEmail(token);
            int index = email.indexOf('@');
            String recipient = email.substring(0, index);
            String domain = email.substring(index + 1);
            return getFlagFull(domain, recipient);
        } else if (Core.isValidURL(token)) {
            return getFlag(Core.getHostnameURL(token));
        } else {
            return null;
        }
    }
    
    private static Flag getFlagFull(String domain, String recipient) {
        if (domain == null) {
            return null;
        } else {
            LinkedList<String> stack = new LinkedList<>();
            StringTokenizer tokenizer = new StringTokenizer(domain, ".");
            while (tokenizer.hasMoreTokens()) {
                stack.push(tokenizer.nextToken());
            }
            NodeEmail node = ROOTREPE;
            Flag flag = node.getFlag();
            while (!stack.isEmpty()) {
                String key = stack.pop();
                node = node.getReputationZone(key);
                if (node == null) {
                    break;
                } else {
                    Flag newFlag = node.getFlag();
                    if (newFlag == null) {
                        break;
                    } else {
                        flag = newFlag;
                    }
                }
            }
            if (Provider.containsExact('@' + domain)) {
                if (flag == Flag.HARMFUL) {
                    flag = Flag.UNDESIRABLE;
                } else if (flag == Flag.BENEFICIAL) {
                    flag = Flag.DESIRABLE;
                }
            }
            if (node != null && recipient != null) {
                Reputation reputation = node.getReputationRecipient(recipient);
                if (reputation != null) {
                    Flag newFlag = reputation.getFlag();
                    if (newFlag != null) {
                        flag = newFlag;
                    }
                }
            }
            return flag;
        }
    }
    
    private static final File FILE = new File("./data/uri.txt");
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
                            int timeInt4 = Integer.parseInt(value);
                            if ((timeInt = timeMap.get(timeInt4)) == null) {
                                timeMap.put(timeInt4, timeInt4);
                            }
                            put4(cidr, timeInt);
                        } else if (token.equals("ADD6")) {
                            String cidr = tokenizer.nextToken();
                            String value = tokenizer.nextToken();
                            int timeInt6 = Integer.parseInt(value);
                            if ((timeInt = timeMap.get(timeInt6)) == null) {
                                timeMap.put(timeInt6, timeInt6);
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
                            NodeIP.load4(cidr, xiSum, xi2Sum, last, flag, min, max);
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
                            NodeIP.load6(cidr, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("REPD")) {
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
                            NodeDomain.load(zone, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("REPE")) {
                            String zone = tokenizer.nextToken().toLowerCase();
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
                            NodeEmail.load(zone, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("QUEUE")) {
                            String address = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(address, value);
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
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    URI.store4(writer);
                    URI.store6(writer);
                    ROOTREP4.store4(writer, (int) 0, (byte) 0);
                    ROOTREP6.store6(writer, (long) 0, (byte) 0);
                    ROOTREPD.store(writer, ".");
                    ROOTREPE.store(writer, ".");
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
        } finally {
            refreshIntegerTime();
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
    private static final int EXPIRATION = 2;
    
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
    
    private static final NodeIP ROOTREP4 = new NodeIP();
    private static final NodeIP ROOTREP6 = new NodeIP();
    
    private static class NodeIP extends Reputation {
        
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
        
        private NodeIP() {
            super();
        }
        
        private NodeIP(NodeIP other, float ajust) {
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
        
        private NodeIP left = null;
        private NodeIP rigth = null;
        
        private synchronized NodeIP getLeft() {
            return left;
        }
        
        private synchronized NodeIP getRigth() {
            return rigth;
        }
       
        private NodeIP newLeft4(byte mask) {
            return newLeft(1.125f, mask <= 24);
        }
        
        private NodeIP newLeft6(byte mask) {
            return newLeft(1.0625f, mask <= 48);
        }
        
        private synchronized NodeIP newLeft(float ajust, boolean reserved) {
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
                return left = new NodeIP(this, ajust);
            } else {
                return left;
            }
        }
        
        private NodeIP newRigth4(byte mask) {
            return newRigth(1.125f, mask <= 24);
        }
        
        private NodeIP newRigth6(byte mask) {
            return newRigth(1.0625f, mask <= 48);
        }
        
        private synchronized NodeIP newRigth(float ajust, boolean reserved) {
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
                return rigth = new NodeIP(this, ajust);
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
                NodeIP node = ROOTREP4;
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
                NodeIP node = ROOTREP6;
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
                NodeIP child;
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
                NodeIP child;
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
    
    private static final HashSet<String> RESERVED = new HashSet<>();
    
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
    }
    
    private static final NodeDomain ROOTREPD = new NodeDomain();

    private static class NodeDomain extends Reputation {
        
        private static final int POPULATION[] = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private NodeDomain() {
            super();
        }
        
        private NodeDomain(NodeDomain other) {
            super(other, 2.0f);
        }
        
        private void addValue(String zone, int value, int level) {
            if (value == 4 && Domain.containsTLD(Domain.revert(zone))) {
                value = 2;
            } else if (value == -4 && RESERVED.contains(zone)) {
                value = -2;
            }
            super.add(value, POPULATION[level]);
        }
        
        private TreeMap<String,NodeDomain> MAP = null;
        
        private synchronized NodeDomain newReputation(String zone, String key) {
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
                NodeDomain node = null;
                if (MAP == null) {
                    MAP = new TreeMap<>();
                } else {
                    node = MAP.get(key);
                }
                if (node == null) {
                    node = new NodeDomain(this);
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
        
        private synchronized NodeDomain getReputation(String key) {
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
                        "REPD " + zone + " " + xisArray[0] + " " + xisArray[1] + " "
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
                NodeDomain node = ROOTREPD;
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
            writer.write("REPD ");
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
                    NodeDomain reputation = getReputation(key);
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
    
    private static final NodeEmail ROOTREPE = new NodeEmail();
    
    private static class NodeEmail extends Reputation {
        
        private static final int POPULATIONR = 64;
        
        private static final int[] POPULATIONZ = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private NodeEmail() {
            super();
        }
        
        private NodeEmail(NodeEmail other) {
            super(other, 2.0f);
        }
        
        private TreeMap<String,Reputation> MAPR = null;
        
        private synchronized Reputation newReputationR(String recipient, int level) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (recipient == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (flag == Flag.HARMFUL && minimum == -4 && maximum == -4) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.DESIRABLE && minimum == 2 && maximum == 2) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else {
                Reputation reputation = null;
                if (MAPR == null) {
                    MAPR = new TreeMap<>();
                } else {
                    reputation = MAPR.get(recipient);
                }
                if (reputation == null) {
                    float ajust = POPULATIONZ[level] / POPULATIONR;
                    reputation = new Reputation(this, ajust);
                    MAPR.put(recipient, reputation);
                }
                return reputation;
            }
        }
        
        private TreeMap<String,NodeEmail> MAPZ = null;
        
        private void addValue(String zone, int value, int level) {
            if (value == 4 && Domain.containsTLD(Domain.revert(zone))) {
                value = 2;
            } else if (value == -4 && RESERVED.contains(zone)) {
                value = -2;
            }
            super.add(value, POPULATIONZ[level]);
        }
        
        private synchronized NodeEmail newReputationZ(String zone, String key) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (key == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (flag == Flag.HARMFUL && minimum == -4 && maximum == -4 && !RESERVED.contains(zone)) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2 && !RESERVED.contains(zone)) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1 && !RESERVED.contains(zone)) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1 && !RESERVED.contains(zone)) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.DESIRABLE && minimum == 2 && maximum == 2 && !RESERVED.contains(zone)) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4 && !Domain.containsTLD(Domain.revert(zone))) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else {
                NodeEmail node = null;
                if (MAPZ == null) {
                    MAPZ = new TreeMap<>();
                } else {
                    node = MAPZ.get(key);
                }
                if (node == null) {
                    node = new NodeEmail(this);
                    MAPZ.put(key, node);
                }
                return node;
            }
        }
        
        private synchronized void clearMap() {
            MAPZ = null;
        }
        
        private synchronized void dropMapZone(String key) {
            if (MAPZ != null) {
                MAPZ.remove(key);
                if (MAPZ.isEmpty()) {
                    MAPZ = null;
                }
            }
        }
        
        private synchronized void dropMapRecipient(String key) {
            if (MAPR != null) {
                MAPR.remove(key);
                if (MAPR.isEmpty()) {
                    MAPR = null;
                }
            }
        }
        
        private synchronized TreeSet<String> keySetZone() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAPZ != null) {
                keySet.addAll(MAPZ.keySet());
            }
            return keySet;
        }
        
        private synchronized TreeSet<String> keySetRecipient() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAPR != null) {
                keySet.addAll(MAPR.keySet());
            }
            return keySet;
        }
        
        private synchronized NodeEmail getReputationZone(String key) {
            if (MAPZ == null) {
                return null;
            } else {
                return MAPZ.get(key);
            }
        }
        
        private synchronized Reputation getReputationRecipient(String recipient) {
            if (MAPR == null) {
                return null;
            } else {
                return MAPR.get(recipient);
            }
        }
        
        private static Flag refreshFlag(String zone, Reputation reputation, Flag defaultFlag) {
            if (zone.contains(" ")) {
                Server.logError(new Exception(zone));
            }
            Flag oldFlag = reputation.getFlag();
            Flag newFlag = reputation.refreshFlag(
                    POPULATIONR, false
            );
            if (newFlag != oldFlag) {
                float[] xisArray = reputation.getXiSum();
                byte[] extremes = reputation.getExtremes();
                int last = reputation.getLast();
                append(
                        "REPE " + zone + " " + xisArray[0] + " " + xisArray[1]
                                + " " + last + " " + newFlag + " "
                                + extremes[0] + " " + extremes[1]
                );
            }
            if (newFlag == null) {
                return defaultFlag;
            } else {
                return newFlag;
            }
        }
        
        private Flag refreshFlag(String zone, int level, Flag defaultFlag) {
            if (zone.contains(" ")) {
                Server.logError(new Exception(zone));
            }
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATIONZ[level], RESERVED.contains(zone)
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REPE " + zone + " " + xisArray[0] + " " + xisArray[1]
                                + " " + last + " " + newFlag + " "
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
                String recipient = null;
                int index = zone.indexOf('@');
                if (index > 0) {
                    recipient = zone.substring(index + 1);
                    zone = zone.substring(0, index) + '.';
                } else if (flag.equals("BENEFICIAL") && Provider.containsExact('@' + Domain.revert(zone).substring(1))) {
                    flag = "DESIRABLE";
                }
                if (flag.equals("BENEFICIAL") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "DESIRABLE";
                } else if (flag.equals("HARMFUL") && RESERVED.contains(zone)) {
                    flag = "UNDESIRABLE";
                }
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                int level = tokenizer.countTokens();
                NodeEmail node = ROOTREPE;
                String zoneNode = ".";
                while (node != null && tokenizer.hasMoreTokens()) {
                    String key = tokenizer.nextToken();
                    node = node.newReputationZ(zoneNode, key);
                    zoneNode += key + '.';
                }
                if (node != null) {
                    if (recipient == null) {
                        node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                    } else {
                        Reputation reputation = node.newReputationR(
                                recipient, level
                        );
                        if (reputation != null) {
                            reputation.set(
                                    xiSum, xi2Sum, last, flag,
                                    minimum, maximum
                            );
                        }
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void store(FileWriter writer, String zone) throws IOException {
            if (zone.contains(" ")) {
                Server.logError(new Exception(zone));
            }
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REPE ");
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
            } else if (flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else {
                for (String key : keySetRecipient()) {
                    Reputation reputation = getReputationRecipient(key);
                    if (reputation != null) {
                        if (reputation.isExpired()) {
                            dropMapRecipient(key);
                        } else {
                            xiResult = reputation.getXiSum();
                            flag = reputation.getFlagObject();
                            extremes = reputation.getExtremes();
                            last = reputation.getLast();
                            int index = zone.length() - 1;
                            writer.write("REPE ");
                            writer.write(zone.substring(0, index));
                            writer.write('@');
                            writer.write(key);
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
                        }
                    }
                }
                for (String key : keySetZone()) {
                    NodeEmail reputation = getReputationZone(key);
                    if (reputation != null) {
                        if (reputation.isExpired()) {
                            dropMapZone(key);
                        } else {
                            reputation.store(writer, zone + key + '.');
                        }
                    }
                }
            }
        }
    }
}
