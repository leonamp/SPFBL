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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.StringTokenizer;
import net.spfbl.core.Server;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Core;
import static net.spfbl.data.FQDN.RESERVED;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.spf.SPF.Qualifier;
import static net.spfbl.spf.SPF.Qualifier.FAIL;
import static net.spfbl.spf.SPF.Qualifier.SOFTFAIL;
import net.spfbl.whois.Domain;

/**
 * Representa a estrutura de reputação dos sistemas de envio.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class SPF {
    
    private static final File FILE = new File("./data/spf.txt");
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
                        if (token.equals("REP")) {
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
                            Node.load(zone, xiSum, xi2Sum, last, flag, min, max);
                        } else if (token.equals("QUEUE")) {
                            String domain = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(domain, value);
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
    
    public static boolean isBeneficial(
            String sender, Qualifier qualifier
    ) {
        Flag flag = getFlag(sender, qualifier);
        return flag == Flag.BENEFICIAL;
    }
    
    public static boolean isHarmful(
            String sender, Qualifier qualifier
    ) {
        Flag flag = getFlag(sender, qualifier);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isExtreme(
            String sender, Qualifier qualifier
    ) {
        Flag flag = getFlag(sender, qualifier);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.HARMFUL) {
            return true;
        } else {
            return false;
        }
    }
    
    private static final Node ROOT = new Node();
    
    public static boolean addHarmful(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) -4);
        } else {
            return false;
        }
    }
    
    public static boolean addHarmful(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) -4);
        } else {
            return false;
        }
    }
    
    public static boolean addUndesirable(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) -2);
        } else {
            return false;
        }
    }
    
    public static boolean addUndesirable(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) -2);
        } else {
            return false;
        }
    }
    
    public static boolean addUnacceptable(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) -1);
        } else {
            return false;
        }
    }
    
    public static boolean addUnacceptable(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) -1);
        } else {
            return false;
        }
    }
    
    public static boolean addAcceptable(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) 1);
        } else {
            return false;
        }
    }
    
    public static boolean addAcceptable(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) 1);
        } else {
            return false;
        }
    }
    
    public static boolean addDesirable(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) 2);
        } else {
            return false;
        }
    }
    
    public static boolean addDesirable(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) 2);
        } else {
            return false;
        }
    }
    
    public static boolean addBeneficial(String sender, Qualifier qualifier) {
        if (sender == null) {
            return false;
        } else if (qualifier == Qualifier.PASS) {
            return addOperation(sender, (byte) 4);
        } else {
            return false;
        }
    }
    
    public static boolean addBeneficial(String sender, String result) {
        if (sender == null) {
            return false;
        } else if (result == null) {
            return false;
        } else if (result.equals("PASS")) {
            return addOperation(sender, (byte) 4);
        } else {
            return false;
        }
    }
    
    private static boolean addOperation(String sender, Byte value) {
        if (sender == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(sender, value));
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
            super("SPFTHREAD");
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
                        String sender = Domain.normalizeEmail(entry.getKey());
                        if (sender != null) {
                            int index = sender.indexOf('@');
                            String recipient = sender.substring(0, index);
                            String domain = sender.substring(index + 1);
                            boolean freemail = Provider.containsExact('@' + domain);
                            byte valueD = entry.getValue();
                            byte valueR = entry.getValue();
                            if (freemail) {
                                if (valueD < -1 && Ignore.containsExact(sender)) {
                                    valueD = -1;
                                } else if (valueD == -4) {
                                    valueD = -2;
                                } else if (valueD == 4) {
                                    valueD = 2;
                                }
                            } else {
                                if (valueD < -1 && Ignore.containsExact('@' + domain)) {
                                    valueD = -1;
                                } else if (valueD < -1 && Ignore.containsHost(domain)) {
                                    valueD = -1;
                                } else if (valueD < -2 && Provider.containsDomain(domain)) {
                                    valueD = -2;
                                }
                            }
                            int level = 0;
                            LinkedList<String> stack = new LinkedList<>();
                            StringTokenizer tokenizer = new StringTokenizer(domain, ".");
                            while (tokenizer.hasMoreTokens()) {
                                stack.push(tokenizer.nextToken());
                            }
                            Node reputationZ = ROOT;
                            String zone = ".";
                            reputationZ.addValue(zone, valueD, level);
                            Flag flag = reputationZ.refreshFlag(zone, level, Flag.ACCEPTABLE);
                            while (!stack.isEmpty()) {
                                if (++level > 7) {
                                    break;
                                } else {
                                    String key = stack.pop();
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
                            if (freemail && reputationZ != null && stack.isEmpty()) {
                                // Freemail.
                                if (flag == Flag.HARMFUL) {
                                    flag = Flag.UNDESIRABLE;
                                } else if (flag == Flag.BENEFICIAL) {
                                    flag = Flag.DESIRABLE;
                                }
                                Reputation reputationR = reputationZ.newReputationR(recipient, level, freemail);
                                if (reputationR != null) {
                                    reputationR.add(valueR, Node.POPULATIONR);
                                    index = zone.length() - 1;
                                    zone = zone.substring(0, index);
                                    zone += '@' + recipient;
                                    flag = Node.refreshFlag(zone, reputationR, flag);
                                }
                            }
                            if (freemail && valueR == -4 && flag == Flag.HARMFUL) {
                                if (Block.addExact(sender)) {
                                    Server.logDebug(null, "new BLOCK '" + sender + "' added by 'HARMFUL'.");
                                }
                            } else if (freemail && valueR == 4 && flag == Flag.BENEFICIAL) {
                                if (Block.dropExact(sender)) {
                                    Server.logDebug(null, "false positive BLOCK '" + sender + "' dropped by 'BENEFICIAL'.");
                                }
                            } else if (!freemail && valueD == -4 && flag == Flag.HARMFUL) {
                                if (Block.addExact("@" + domain)) {
                                    Server.logDebug(null, "new BLOCK '@" + domain + "' added by 'HARMFUL'.");
                                }
                            } else if (!freemail && valueD == 4 && flag == Flag.BENEFICIAL) {
                                if (Block.dropExact("@" + domain)) {
                                    Server.logDebug(null, "false positive BLOCK '@" + domain + "' dropped by 'BENEFICIAL'.");
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
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String domain = entry.getKey();
                    Byte value = entry.getValue();
                    writer.write("QUEUE ");
                    writer.write(domain);
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
    
    public static Flag getFlag(String sender, Qualifier qualifier) {
        if (sender == null) {
            return ACCEPTABLE;
        } else if ((sender = Domain.normalizeEmail(sender)) == null) {
            return UNACCEPTABLE;
        } else {
            int index = sender.indexOf('@');
            String recipient = sender.substring(0, index);
            String domain = sender.substring(index + 1);
            Flag flag = getFlagFull(domain, recipient);
            if (qualifier == Qualifier.PASS) {
                return flag;
            } else if (flag == HARMFUL) {
                return HARMFUL;
            } else if (Ignore.containsSender(sender)) {
                return HARMFUL;
            } else if (flag == UNDESIRABLE) {
                return UNDESIRABLE;
            } else if (qualifier == FAIL) {
                return UNDESIRABLE;
            } else if (flag == UNACCEPTABLE) {
                return UNACCEPTABLE;
            } else if (qualifier == SOFTFAIL) {
                return UNACCEPTABLE;
            } else if (qualifier == null) {
                return UNACCEPTABLE;
            } else {
                return ACCEPTABLE;
            }
        }
    }
    
    public static Flag getFlag(String sender, String result) {
        if (sender == null) {
            return ACCEPTABLE;
        } else if ((sender = Domain.normalizeEmail(sender)) == null) {
            return UNACCEPTABLE;
        } else {
            int index = sender.indexOf('@');
            String recipient = sender.substring(0, index);
            String domain = sender.substring(index + 1);
            Flag flag = getFlagFull(domain, recipient);
            if (result.equals("PASS")) {
                return flag;
            } else if (flag == Flag.HARMFUL) {
                return flag;
            } else if (flag == Flag.UNDESIRABLE) {
                return flag;
            } else {
                return Flag.UNACCEPTABLE;
            }
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
            Node node = ROOT;
            Flag flag = node.getFlag(Flag.ACCEPTABLE);
            while (!stack.isEmpty()) {
                String key = stack.pop();
                node = node.getReputationZone(key);
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
            if (Provider.containsExact('@' + domain)) {
                if (flag == Flag.HARMFUL) {
                    flag = Flag.UNDESIRABLE;
                } else if (flag == Flag.BENEFICIAL) {
                    flag = Flag.DESIRABLE;
                }
            } else if (Provider.containsFQDN(domain)) {
                if (flag == Flag.HARMFUL) {
                    flag = Flag.UNDESIRABLE;
                } else if (flag == Flag.BENEFICIAL) {
                    flag = Flag.DESIRABLE;
                }
            }
            if (node != null && recipient != null) {
                Reputation reputation = node.getReputationRecipient(recipient);
                if (reputation != null) {
                    Flag newFlag = reputation.getFlag(flag);
                    if (newFlag != null) {
                        flag = newFlag;
                    }
                }
            }
            return flag;
        }
    }

    private static class Node extends Reputation {
        
        private static final int POPULATIONR = 64;
        
        private static final int[] POPULATIONZ = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private Node() {
            super();
        }
        
        private Node(Node other) {
            super(other, 2.0f);
        }
        
        private TreeMap<String,Reputation> MAPR = null;
        
        private synchronized Reputation newReputationR(String recipient, int level, boolean freemail) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (recipient == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (!freemail && flag == Flag.HARMFUL && minimum == -4 && maximum == -4) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (!freemail && flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (!freemail && flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (!freemail && flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (!freemail && flag == Flag.DESIRABLE && minimum == 2 && maximum == 2) {
                MAPZ = null;
                MAPR = null;
                return null;
            } else if (!freemail && flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4) {
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
        
        private TreeMap<String,Node> MAPZ = null;
        
        private void addValue(String zone, int value, int level) {
            if (value == 4 && Domain.containsTLD(Domain.revert(zone))) {
                value = 2;
            } else if (value == -4 && RESERVED.contains(zone)) {
                value = -2;
            }
            if (level == 0 && value > 1) {
                value = 1;
            }
            super.add(value, POPULATIONZ[level]);
        }
        
        private synchronized Node newReputationZ(String zone, String key) {
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
                Node node = null;
                if (MAPZ == null) {
                    MAPZ = new TreeMap<>();
                } else {
                    node = MAPZ.get(key);
                }
                if (node == null) {
                    node = new Node(this);
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
        
        private synchronized Node getReputationZone(String key) {
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
            Flag oldFlag = reputation.getFlag();
            Flag newFlag = reputation.refreshFlag(
                    POPULATIONR, false
            );
            if (newFlag != oldFlag) {
                float[] xisArray = reputation.getXiSum();
                byte[] extremes = reputation.getExtremes();
                int last = reputation.getLast();
                append(
                        "REP " + zone + " " + xisArray[0] + " " + xisArray[1]
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
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATIONZ[level], RESERVED.contains(zone)
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP " + zone + " " + xisArray[0] + " " + xisArray[1]
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
                boolean freemail = false;
                int index = zone.indexOf('@');
                String domain = Domain.revert(zone).substring(1);
                if (index > 0) {
                    recipient = zone.substring(index + 1);
                    zone = zone.substring(0, index) + '.';
                    freemail = Provider.containsExact('@' + domain);
                } else if (flag.equals("BENEFICIAL") && Provider.containsExact('@' + domain)) {
                    flag = "DESIRABLE";
                } else if (flag.equals("BENEFICIAL") && Provider.containsFQDN(domain)) {
                    flag = "DESIRABLE";
                }
                if (flag.equals("BENEFICIAL") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "DESIRABLE";
                } else if (flag.equals("HARMFUL") && RESERVED.contains(zone)) {
                    flag = "UNDESIRABLE";
                }
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                int level = tokenizer.countTokens();
                Node node = ROOT;
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
                                recipient, level, freemail
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
                            writer.write("REP ");
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
                    Node reputation = getReputationZone(key);
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
