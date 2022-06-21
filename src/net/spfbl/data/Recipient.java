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
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import static net.spfbl.data.Recipient.Type.INEXISTENT;
import static net.spfbl.data.Recipient.Type.TRAP;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.DESIRABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import static net.spfbl.whois.Domain.normalizeEmail;

/**
 * Representa a estutura de dados dos destinatários do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Recipient {

    public enum Type {
        MAILBOX,
        ALIAS,
        PRIVATE,
        RESTRICT,
        INEXISTENT,
        TRAP,
        ABUSE,
        HACKED
    }
    
    private Type type;
    private final Reputation reputation;
    private long lockUntil;
    
    
    private Recipient() {
        this.type = null;
        this.reputation = new Reputation();
        this.lockUntil = 0L;
    }
    
    private Recipient(Type type) {
        this.type = type;
        this.reputation = new Reputation();
        this.lockUntil = 0L;
    }
    
    private Recipient(Type type, Reputation reputation) {
        this.type = type;
        this.reputation = new Reputation(reputation, 1.0f);
        this.lockUntil = 0L;
    }
    
    private Recipient(Recipient other) {
        this.type = Type.MAILBOX;
        this.reputation = new Reputation(other.reputation, 1.0f);
        this.lockUntil = other.lockUntil;
    }

    private boolean isExpired() {
        if (type == INEXISTENT) {
            return reputation.isExpired(2);
        } else {
            return reputation.isExpired(4);
        }
    }
    
    private Reputation getReputation() {
        return reputation;
    }
    
    private long getLockUntil() {
        return lockUntil;
    }
    
    private synchronized Type getType() {
        if (type == Type.HACKED && System.currentTimeMillis() > lockUntil) {
            type = Type.MAILBOX;
            lockUntil = 0L;
        }
        return type;
    }
    
    private Flag getFlag() {
        switch (type) {
            case TRAP:
                return reputation.getFlag(HARMFUL);
            case INEXISTENT:
                return reputation.getFlag(UNACCEPTABLE);
            case ABUSE:
                return reputation.getFlag(DESIRABLE);
            case PRIVATE:
                return reputation.getFlag(UNDESIRABLE);
            case RESTRICT:
                return reputation.getFlag(UNACCEPTABLE);
            default:
                return reputation.getFlag(ACCEPTABLE);
        }
    }

    private synchronized boolean setType(Type type) {
        if (type == null) {
            return false;
        } else if (type == this.type) {
            return false;
        } else if (type == Type.HACKED) {
            if (this.type == Type.MAILBOX) {
                this.type = type;
                this.lockUntil = System.currentTimeMillis() + Server.WEEK_TIME;
                return true;
            } else {
                return false;
            }
        } else {
            this.type = type;
            this.lockUntil = 0L;
            return true;
        }
    }
    
    private synchronized boolean changeType(Type oldType, Type newType) {
        if (oldType == null) {
            return false;
        } else if (newType == null) {
            return false;
        } else if (this.type == newType) {
            return false;
        } else if (System.currentTimeMillis() < lockUntil) {
            return false;
        } else if (this.type == oldType) {
            this.type = newType;
            return true;
        } else {
            return false;
        }
    }
    
    private synchronized boolean setExistent(boolean existent) {
        if (existent) {
            lockUntil = System.currentTimeMillis() + Server.WEEK_TIME;
            switch (type) {
                case INEXISTENT:
                case TRAP:
                    type = Type.MAILBOX;
                    return true;
                default:
                    return false;
            }
        } else if (System.currentTimeMillis() > lockUntil) {
            switch (type) {
                case MAILBOX:
                case ALIAS:
                case PRIVATE:
                case RESTRICT:
                case ABUSE:
                    type = Type.INEXISTENT;
                    lockUntil = System.currentTimeMillis() + 7 * Server.WEEK_TIME;
                    return true;
                default:
                    return false;
            }
        } else {
            return false;
        }
    }
    
    private synchronized Object[] getAttributes() {
        Object[] attributes = new Object[6];
        attributes[0] = type.name();
        attributes[1] = reputation.getExtremes();
        attributes[2] = reputation.getXiSum();
        attributes[3] = reputation.getLast();
        attributes[4] = reputation.getFlagObject();
        attributes[5] = lockUntil;
        return attributes;
    }

    private boolean append(String address) {
        if (address == null) {
            return false;
        } else {
            Object[] attributes = getAttributes();
            String typeName = (String) attributes[0];
            byte[] extremes = (byte[]) attributes[1];
            float[] xisArray = (float[]) attributes[2];
            int last = (int) attributes[3];
            Object flag = attributes[4];
            long lock = (Long) attributes[5];
            appendLine(
                    "REP " + typeName + " " + address + " "
                            + xisArray[0] + " " + xisArray[1] + " "
                            + last + " " + flag + " "
                            + extremes[0] + " " + extremes[1] + " " + lock
            );
            return true;
        }
    }

    private static final int POPULATION = 1024;
    
    private static final HashMap<String,Recipient> MAP = new HashMap<>();
    
    private synchronized static TreeSet<String> getAddressKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    private static Recipient getRecipient(String address) {
        if (address == null) {
            return null;
        } else {
            return MAP.get(address);
        }
    }
    
    private synchronized static boolean dropRecipient(String address) {
        if (address == null) {
            return false;
        } else {
            return MAP.remove(address) != null;
        }
    }

    private synchronized static Recipient newRecipient(
            String address, Type type
    ) {
        if (address == null) {
            return null;
        } else {
            Recipient recipient = MAP.get(address);
            if (recipient == null) {
                recipient = new Recipient(type);
                MAP.put(address, recipient);
            }
            return recipient;
        }
    }
    
    
    private synchronized static Recipient newRecipient(
            String address, Reputation reputation
    ) {
        if (address == null) {
            return null;
        } else {
            Recipient recipient = MAP.get(address);
            if (recipient == null) {
                if (reputation == null) {
                    recipient = new Recipient();
                } else {
                    recipient = new Recipient(Type.MAILBOX, reputation);
                }
                MAP.put(address, recipient);
            }
            return recipient;
        }
    }
    
    public static Flag getFlag(String userEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return null;
        } else {
            Recipient recipient = getRecipient(userEmail);
            if (recipient == null) {
                return ACCEPTABLE;
            } else {
                return recipient.reputation.getFlag(ACCEPTABLE);
            }
        }
    }
    
    public static Flag getFlag(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return null;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return null;
        } else {
            Flag flag = ACCEPTABLE;
            Recipient recipient = getRecipient(userEmail);
            if (recipient != null) {
                flag = recipient.reputation.getFlag(flag);
                recipient = getRecipient(userEmail + ':' + recipientEmail);
                if (recipient != null) {
                    flag = recipient.reputation.getFlag(flag);
                }
            }
            return flag;
        }
    }
    
    public static Flag getFlag(User user, String recipientEmail) {
        if (user == null) {
            return null;
        } else {
            return getFlag(user.getEmail(), recipientEmail);
        }
    }
    
    public static Long getInexistentLong(User user, String recipientEmail) {
        if (user == null) {
            return null;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return null;
        } else {
            String address = user.getEmail() + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return null;
            } else {
                switch (recipient.getType()) {
                    case INEXISTENT:
                        return Long.MAX_VALUE;
                    case TRAP:
                        return 0L;
                    default:
                        return null;
                }
            }
        }
    }
    
    public static boolean setExistent(User user, String recipientEmail, Boolean existent) {
        if (existent == null) {
            return false;
        } else if (user == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = user.getEmail() + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                if (!existent) {
                    recipient = newRecipient(address, Type.INEXISTENT);
                } else if (recipientEmail.startsWith("abuse@")) {
                    recipient = newRecipient(address, Type.ABUSE);
                } else {
                    recipient = newRecipient(address, Type.MAILBOX);
                }
            }
            if (recipient.setExistent(existent)) {
                recipient.append(address);
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static boolean isValidType(String type) {
        try {
            Type.valueOf(type);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
    
    public static boolean set(String userEmail, String recipientEmail, String type) {
        try {
            return set(userEmail, recipientEmail, Type.valueOf(type));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
    
    public static boolean set(String userEmail, String recipientEmail, Type type) {
        if (type == null) {
            return false;
        } else if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else if (recipient.setType(type)) {
                recipient.append(address);
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static boolean isTrap(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else {
                return recipient.getType() == Type.TRAP;
            }
        }
    }
    
    public static boolean isInexistent(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else {
                return recipient.getType() == Type.INEXISTENT;
            }
        }
    }
    
    public static boolean isPrivate(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else {
                return recipient.getType() == Type.PRIVATE;
            }
        }
    }
    
    public static boolean isRestrict(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else {
                return recipient.getType() == Type.RESTRICT;
            }
        }
    }
    
    public static boolean isAbuse(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false;
            } else {
                return recipient.getType() == Type.ABUSE;
            }
        }
    }
    
    public static boolean isHacked(String userEmail, String recipientEmail) {
        if ((userEmail = normalizeEmail(userEmail)) == null) {
            return false;
        } else if ((recipientEmail = normalizeEmail(recipientEmail)) == null) {
            return false;
        } else {
            String address = userEmail + ':' + recipientEmail;
            Recipient recipient = getRecipient(address);
            if (recipient == null) {
                return false; 
            } else {
                return recipient.getType() == Type.HACKED;
            }
        }
    }
    
    private static final File FILE = new File("./data/recipient.txt");
    private static Writer WRITER = null;
    private static final LinkedList<String> LIST = new LinkedList<>();
    private static final Semaphore SEMAPHORE = new Semaphore(0);
    
    private static void appendLine(String line) {
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
                            String type = tokenizer.nextToken();
                            String address = tokenizer.nextToken();
                            address = address.replaceAll("[\\s\\t]+", "");
                            int index = address.indexOf(':');
                            String userEmail;
                            String recipient;
                            if (index > 0) {
                                userEmail = address.substring(0, index);
                                recipient = address.substring(index + 1);
                            } else {
                                userEmail = address;
                                recipient = null;
                            }
                            float xiSum = Float.parseFloat(tokenizer.nextToken());
                            float xi2Sum = Float.parseFloat(tokenizer.nextToken());
                            int last = Integer.parseInt(tokenizer.nextToken());
                            String flag = tokenizer.nextToken();
                            byte min = Byte.parseByte(tokenizer.nextToken());
                            byte max = Byte.parseByte(tokenizer.nextToken());
                            long lockUntil = 0L;
                            if (tokenizer.hasMoreTokens()) {
                                lockUntil = Long.parseLong(tokenizer.nextToken());
                            }
                            if (recipient == null) {
                                if (flag.equals("HARMFUL")) {
                                    flag = "UNDESIRABLE";
                                } else if (flag.equals("BENEFICIAL")) {
                                    flag = "DESIRABLE";
                                }
                                loadUser(
                                        address, xiSum, xi2Sum, last,
                                        flag, min, max, lockUntil
                                );
                            } else {
                                loadRecipient(
                                        address, type, xiSum, xi2Sum,
                                        last, flag, min, max, lockUntil
                                );
                            }
                        } else if (token.equals("QUEUE")) {
                            String userEmail = tokenizer.nextToken();
                            String recipientEmail = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            String[] address = {userEmail, recipientEmail};
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
    
    private synchronized static void loadUser(
            String address,
            float xiSum,
            float xi2Sum,
            int last,
            String flag,
            byte minimum,
            byte maximum,
            long lockUntil
    ) {
        if (address != null) {
            Recipient recipient = MAP.get(address);
            if (recipient == null) {
                recipient = new Recipient();
                MAP.put(address, recipient);
            }
            recipient.reputation.set(
                    xiSum, xi2Sum, last, flag, minimum, maximum
            );
            recipient.lockUntil = lockUntil;
        }
    }
    
    private synchronized static void loadRecipient(
            String address,
            String type,
            float xiSum,
            float xi2Sum,
            int last,
            String flag,
            byte minimum,
            byte maximum,
            long lockUntil
    ) {
        if (address != null) {
            try {
                Recipient recipient = MAP.get(address);
                if (recipient == null) {
                    recipient = new Recipient(Type.valueOf(type));
                    MAP.put(address, recipient);
                }
                recipient.reputation.set(
                        xiSum, xi2Sum, last, flag, minimum, maximum
                );
                recipient.lockUntil = lockUntil;
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
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
                    for (String address : getAddressKeySet()) {
                        Recipient recipient = getRecipient(address);
                        if (recipient == null) {
                            dropRecipient(address);
                        } else if (recipient.isExpired()) {
                            dropRecipient(address);
                        } else {
                            Type type = recipient.getType();
                            Reputation reputation = recipient.getReputation();
                            float[] xiResult = reputation.getXiSum();
                            Object flag = reputation.getFlagObject();
                            byte[] extremes = reputation.getExtremes();
                            int last = reputation.getLast();
                            long lockUntil = recipient.getLockUntil();
                            writer.write("REP ");
                            writer.write(type == null ? "USER" : type.name());
                            writer.write(' ');
                            writer.write(address);
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
                            writer.write(' ');
                            writer.write(Long.toString(lockUntil));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
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
    
    public static boolean addHarmful(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addHarmful(userEmail, recipientEmail);
    }
    
    public static boolean addHarmful(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) -4);
        }
    }
    
    public static boolean addUndesirable(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addUndesirable(userEmail, recipientEmail);
    }
    
    public static boolean addUndesirable(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) -2);
        }
    }
    
    public static boolean addUnacceptable(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addUnacceptable(userEmail, recipientEmail);
    }
    
    public static boolean addUnacceptable(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) -1);
        }
    }
    
    public static boolean addAcceptable(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addAcceptable(userEmail, recipientEmail);
    }
    
    public static boolean addAcceptable(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) 1);
        }
    }
    
    public static boolean addDesirable(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addDesirable(userEmail, recipientEmail);
    }
    
    public static boolean addDesirable(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) 2);
        }
    }
    
    public static boolean addBeneficial(Client client, User user, String recipientEmail) {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return addBeneficial(userEmail, recipientEmail);
    }
    
    public static boolean addBeneficial(String userEmail, String recipientEmail) {
        if (userEmail == null) {
            return false;
        } else if (recipientEmail == null) {
            return false;
        } else {
            String[] address = {userEmail, recipientEmail};
            return addOperation(address, (byte) 4);
        }
    }
    
    private static boolean addOperation(String[] address, Byte value) {
        if (address == null) {
            return false;
        } else if (value == null) {
            return false;
        } else if (address.length != 2) {
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
            super("ABUSETHRD");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private synchronized void offer(SimpleImmutableEntry<String[],Byte> entry) {
            QUEUE.offer(entry);
            notify();
        }
        
        private synchronized SimpleImmutableEntry<String[],Byte> poll() {
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
                while (Core.isRunning() && continueRun()) {
                    processQueue();
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }
        
        private void processQueue() {
            SimpleImmutableEntry<String[],Byte> entry;
            while (Core.isRunning() && (entry = poll()) != null) {
                String[] address = entry.getKey();
                Byte value = entry.getValue();
                String userEmail = normalizeEmail(address[0]);
                String recipientEmail = normalizeEmail(address[1]);
                if (userEmail != null && recipientEmail != null && value != null) {
                    Recipient recipient = addValue(userEmail, null, value);
                    Reputation reputation = recipient.getReputation();
                    if (reputation.hasFlag()) {
                        String addressKey = userEmail + ":" + recipientEmail;
                        recipient = addValue(addressKey, reputation, value);
                        Flag flag = recipient.getFlag();
                        if (value == -4 && (flag == UNDESIRABLE || flag == HARMFUL)) {
                            if (recipient.changeType(INEXISTENT, TRAP)) {
                                recipient.append(addressKey);
                            }
                        }
                    }
                }
            }
        }
        
        private Recipient addValue(String address, Reputation reputation, byte value) {
            if (address == null) {
                return null;
            } else {
                if (reputation == null) {
                    if (value == -4) {
                        value = -2;
                    } else if (value == 4) {
                        value = 2;
                    }
                }
                Recipient recipient = newRecipient(address, reputation);
                Type type = recipient.getType();
                reputation = recipient.getReputation();
                Flag oldFlag = reputation.getFlag();
                reputation.add(value, POPULATION);
                Flag newFlag = reputation.refreshFlag(POPULATION, false);
                byte[] extremes = reputation.getExtremes();
                long lockUntil = recipient.getLockUntil();
                if (newFlag != oldFlag) {
                    float[] xisArray = reputation.getXiSum();
                    int last = reputation.getLast();
                    if (type == null) {
                        appendLine(
                                "REP USER " + address + " "
                                        + xisArray[0] + " " + xisArray[1] + " "
                                        + last + " " + newFlag + " "
                                        + extremes[0] + " " + extremes[1] + " "
                                        + lockUntil
                        );
                    } else {
                        appendLine(
                                "REP " + type.name() + " " + address + " "
                                        + xisArray[0] + " " + xisArray[1]
                                        + " " + last + " " + newFlag + " "
                                        + extremes[0] + " " + extremes[1] + " "
                                        + lockUntil
                        );
                    }
                }
                return recipient;
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String[],Byte> entry;
                while ((entry = poll()) != null) {
                    String[] address = entry.getKey();
                    Byte value = entry.getValue();
                    if (value != null) {
                        String userEmail = normalizeEmail(address[0]);
                        String recipientEmail = normalizeEmail(address[1]);
                        writer.write("QUEUE ");
                        writer.write(userEmail);
                        writer.write(' ');
                        writer.write(recipientEmail);
                        writer.write(' ');
                        writer.write(Byte.toString(value));
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
}
