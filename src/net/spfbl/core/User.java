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

import com.sun.mail.smtp.SMTPSendFailedException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeUtility;
import javax.naming.NamingException;
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.http.ServerHTTP;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um usuário do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class User implements Serializable, Comparable<User> {
    
    private static final long serialVersionUID = 1L;

    private final String email;
    private String name;
    private boolean trusted = false;
    private boolean local = false;
    private boolean usingHeader = false;

    /**
     * Atributos para OTP.
     */
    private String otp_secret = null; // Chave oficial.
    private String otp_transition = null; // Chave de transição.
    private byte otp_fail = 0;
    private Integer otp_sucess = null;
    private long otp_last = 0;
    
    private User(String email, String name) throws ProcessException {
        if (Domain.isEmail(email) && simplify(name) != null) {
            this.email = email.toLowerCase();
            this.name = simplify(name);
        } else {
            throw new ProcessException("INVALID USER");
        }
    }
    
    public void setName(String name) throws ProcessException {
        if (simplify(name) != null && !this.name.equals(simplify(name))) {
            this.name = simplify(name);
            CHANGED = true;
        } else {
            throw new ProcessException("INVALID NAME");
        }
    }
    
    public boolean setTrusted(boolean trusted) {
        if (this.trusted == trusted) {
            return false;
        } else {
            this.trusted = trusted;
            return CHANGED = true;
        }
    }
    
    public boolean setLocal(boolean local) {
        if (this.local == local) {
            return false;
        } else {
            this.local = local;
            return CHANGED = true;
        }
    }
    
    public String getEmail() {
        return email;
    }
    
    public InternetAddress getAdminInternetAddress() {
        try {
            return new InternetAddress(email, name);
        } catch (UnsupportedEncodingException ex) {
            return null;
        }
    }
    
    public String getDomain() {
        int index = email.indexOf('@') + 1;
        return email.substring(index);
    }
    
    public boolean isTrusted() {
        return trusted;
    }
    
    public boolean isLocal() {
        return local;
    }
    
    public boolean isUsingHeader() {
        return usingHeader;
    }
    
    public boolean isPostmaster() {
        return email.startsWith("postmaster@");
    }
    
    public boolean isSameDomain(String address) {
        if (address == null) {
            return false;
        } else {
            int index1 = email.indexOf('@') + 1;
            int index2 = address.indexOf('@') + 1;
            String domain1 = email.substring(index1);
            String domain2 = address.substring(index2);
            return domain1.equals(domain2);
        }
    }
    
    public boolean isEmail(String email) {
        return this.email.equals(email);
    }
    
    public boolean hasSecretOTP() {
        return otp_secret != null;
    }
    
    public boolean hasTransitionOTP() {
        return otp_transition != null;
    }
    
    public String newSecretOTP() {
        CHANGED = true;
        return otp_transition = Core.generateSecretOTP();
    }
    
    public long getFailTime() {
        long thresholdTime = (long) Math.pow(2, otp_fail);
        long idleTime = System.currentTimeMillis() - otp_last;
        if (idleTime < 1000) {
            return 1000;
        } else {
            return thresholdTime - idleTime;
        }
        
    }
    
    public boolean tooManyFails() {
        long thresholdTime = (long) Math.pow(2, otp_fail);
        long idleTime = System.currentTimeMillis() - otp_last;
        if (idleTime < 1000) {
            return false;
        } else {
            return thresholdTime > idleTime;
        }
    }
    
    public boolean isValidOTP(Integer code) {
        if (code == null) {
            return false;
        } else if (code.equals(otp_sucess)) {
            return false;
        } else if (Core.isValidOTP(otp_transition, code)) {
            otp_secret = otp_transition;
            otp_transition = null;
            otp_fail = 0;
            otp_sucess = code;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return true;
        } else if (Core.isValidOTP(otp_secret, code)) {
            otp_transition = null;
            otp_fail = 0;
            otp_sucess = code;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return true;
        } else if (otp_fail < Byte.MAX_VALUE) {
            otp_fail++;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return false;
        } else {
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return false;
        }
    }
    
    public String getName() {
        return name;
    }
    
    public String getContact() {
        return name + " <" + email + ">";
    }
    
    public InternetAddress getInternetAddress() throws UnsupportedEncodingException {
        return new InternetAddress(email, name);
    }
    
    public InternetAddress[] getInternetAddresses() throws UnsupportedEncodingException {
        InternetAddress[] internetAddresses = new InternetAddress[1];
        internetAddresses[0] = getInternetAddress();
        return internetAddresses;
    }
    
    private static String simplify(String text) {
        if (text == null) {
            return null;
        } else {
            char[] charArray = text.toCharArray();
            for (int i = 0; i < charArray.length; i++) {
                char character = charArray[i];
                if (character == '\n') {
                    charArray[i] = '\n';
                } else if (character == '“') {
                    charArray[i] = '"';
                } else if (character == '”') {
                    charArray[i] = '"';
                } else if (Character.isISOControl(character)) {
                    charArray[i] = ' ';
                }
            }
            text = new String(charArray);
            while (text.contains("  ")) {
                text = text.replace("  ", " ");
            }
            while (text.contains(" \n")) {
                text = text.replace(" \n", "\n");
            }
            while (text.contains("\n ")) {
                text = text.replace("\n ", "\n");
            }
            text = text.trim();
            if (text.length() == 0) {
                return null;
            } else {
                return text;
            }
        }
    }
    
    public synchronized boolean dropQuery(long time) {
        return queryMap.remove(time) != null;
    }
    
    private synchronized void dropExpiredQuery() {
        if (queryMap != null) {
            long threshold = System.currentTimeMillis() - 604800000;
            TreeSet<Long> timeSet = new TreeSet<Long>();
            SortedMap<Long,Query> headMap = queryMap.headMap(threshold);
            timeSet.addAll(headMap.keySet());
            for (long time : timeSet) {
                if (queryMap.remove(time) != null) {
                    CHANGED = true;
                }
            }
        }
    }
    
    private static final int QUERY_MAX = 4096;
    
    private synchronized void hairCutQuery() {
        if (queryMap != null && queryMap.size() > QUERY_MAX) {
            Long time = 0L;
            Query query;
            do {
                if ((time = queryMap.higherKey(time)) == null) {
                    break;
                } else if ((query = queryMap.get(time)) != null && !query.isHolding()) {
                    if (queryMap.remove(time) != null) {
                        CHANGED = true;
                    }
                }
            } while (queryMap.size() > QUERY_MAX);
        }
    }

    
    public static void dropAllExpiredQuery() {
        for (User user : getSet()) {
            user.dropExpiredQuery();
            user.hairCutQuery();
        }
    }
    
    /**
     * Mapa de usuário com busca de hash O(1).
     */
    private static final HashMap<String,User> MAP = new HashMap<String,User>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public synchronized static User create(String email,
            String name) throws ProcessException {
        if (MAP.containsKey(email)) {
            return null;
        } else {
            User user = new User(email, name);
            MAP.put(email, user);
            CHANGED = true;
            return user;
        }
    }
    
    public synchronized static TreeSet<User> getSet() {
        TreeSet<User> userSet = new TreeSet<User>();
        userSet.addAll(MAP.values());
        return userSet;
    }
    
    public synchronized static User drop(String email) {
        User user = MAP.remove(email);
        if (user != null) {
            CHANGED = true;
        }
        return user;
    }
    
    public static TreeSet<User> dropAll() {
        TreeSet<User> userSet = new TreeSet<User>();
        for (User user : getSet()) {
            String email = user.getEmail();
            user = drop(email);
            if (email != null) {
                userSet.add(user);
            }
        }
        return userSet;
    }
    
    public synchronized static User get(String email) {
        if (email == null) {
            return null;
        } else {
            return MAP.get(email);
        }
    }
    
    public static boolean exists(String email) {
        if (email == null) {
            return false;
        } else {
            return MAP.containsKey(email);
        }
    }
    
    public static boolean exists(String... emailSet) {
        if (emailSet == null) {
            return false;
        } else {
            for (String email : emailSet) {
                if (exists(email)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static synchronized HashMap<String,User> getMap() {
        HashMap<String,User> map = new HashMap<String,User>();
        map.putAll(MAP);
        return map;
    }
    
    public synchronized static void store() {
        if (CHANGED) {
            try {
                storeDB();
//                Server.logTrace("storing user.map");
                long time = System.currentTimeMillis();
                HashMap<String,User> map = getMap();
                File file = new File("./data/user.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
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
    
    public static synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/user.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof User) {
                        User user = (User) value;
                        MAP.put(key, user);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    @Override
    public int hashCode() {
        return email.hashCode();
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof User) {
            User other = (User) o;
            return this.email.equals(other.email);
        } else {
            return false;
        }
    }
    
    @Override
    public int compareTo(User other) {
        if (other == null) {
            return -1;
        } else {
            return this.toString().compareTo(other.toString());
        }
    }
    
    @Override
    public String toString() {
        if (queryMap == null) {
            return name + " <" + email + "> 0";
        } else {
            return name + " <" + email + "> " + queryMap.size();
        }
    }
    
    /**
     * Registro de consultas.
     */
    private TreeMap<Long,Query> queryMap = null;
    
    public User.Query addQuery(
            long time,
            Client client,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
    ) {
        SPF.Qualifier qualifierEnum;
        try {
            qualifierEnum = SPF.Qualifier.valueOf(qualifier);
        } catch (Exception ex) {
            qualifierEnum = null;
        }
        if (client == null) {
            return addQuery(time, this.getDomain(), ip, helo, hostname, sender,
                    qualifierEnum, recipient, tokenSet, result
            );
        } else {
            return addQuery(time, client.getDomain(), ip, helo, hostname, sender,
                    qualifierEnum, recipient, tokenSet, result
            );
        }
    }
    
    public User.Query addQuery(
            long time,
            String client,
            String ip,
            String helo,
            String hostname,
            String sender,
            SPF.Qualifier qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
    ) {
        try {
            Query query = new Query(
                    client,
                    ip,
                    helo,
                    hostname,
                    sender,
                    qualifier,
                    recipient,
                    tokenSet,
                    result
            );
            putQuery(time, query);
            return query;
        } catch (ProcessException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public synchronized TreeSet<Long> getQueryKeySet(
            Long begin, String filter
    ) {
        TreeSet<Long> keySet = new TreeSet<Long>();
        if (queryMap != null) {
            if (filter == null || filter.length() == 0) {
                keySet.addAll(queryMap.keySet());
            } else {
                for (Long time : queryMap.keySet()) {
                    Query query = queryMap.get(time);
                    if (query.match(filter)) {
                        keySet.add(time);
                    }
                }
            }
        }
        if (begin != null) {
            TreeSet<Long> tailSet = new TreeSet<Long>();
            tailSet.addAll(keySet.tailSet(begin));
            keySet.removeAll(tailSet);
        }
        return keySet;
    }
    
    public void setResult(long time, String result) {
        if (result != null) {
            Query query = getQuery(time);
            if (query != null) {
                query.setResult(result);
            }
        }
    }
    
    public Query getQuery(String time) {
        try {
            return getQuery(Long.parseLong(time));
        } catch (NumberFormatException ex) {
            return null;
        }
    }
    
    public synchronized Query getQuery(long time) {
        if (queryMap == null) {
            return null;
        } else {
            return queryMap.get(time);
        }
    }
    
    public synchronized TreeSet<Long> getTimeSet() {
        if (queryMap == null) {
            return new TreeSet<Long>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<Long>();
            timeSet.addAll(queryMap.keySet());
            return timeSet;
        }
    }
    
    private synchronized void putQuery(long time, Query query) {
        if (queryMap == null) {
            queryMap = new TreeMap<Long,Query>();
        }
        queryMap.put(time, query);
        CHANGED = true;
    }
    
    public String blockByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuery(time);
                if (query != null && query.isMessage(messageID)) {
                    if (query.isWhiteSender() && query.isGreen()) {
                        if (query.complain(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.blockSender(time)) {
                        return "BLOCKED " + query.getBlockSender();
                    } else {
                        return "ALREADY BLOCKED";
                    }
                }
            }
            return "MESSAGE NOT FOUND";
        }
    }
    
    public String whiteByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuery(time);
                if (query != null && query.isMessage(messageID)) {
                    String block = query.getBlock();
                    if (block == null) {
                        Situation situation = query.getSituation(true);
                        if (situation == Situation.ORIGIN) {
                            return "INVALID SENDER";
                        } else if (query.white(time, situation)) {
                            switch (situation) {
                                case IP:
                                    return "ADDED " + query.getSenderSimplified(false, true) + ";" + query.getIP();
                                case ZONE:
                                    return "ADDED " + query.getSenderSimplified(false, true) + ";" + query.getOriginDomain(false);
                                case AUTHENTIC:
                                    return "ADDED " + query.getSenderSimplified(false, true) + ";PASS";
                                default:
                                    return "ERROR: FATAL";
                            }
                        } else {
                            return "ALREADY EXISTS";
                        }
                    } else {
                        return "BLOCKED AS " + block;
                    }
                }
            }
            return "NOT FOUND";
        }
    }
    
    public enum Situation {
        
        NONE,
        ORIGIN,
        IP,
        ZONE,
        AUTHENTIC,
        SAME,
        DOMAIN,
        RECIPIENT,
        ALL
        
    }
    
    public static boolean isExpiredHOLD(long time) {
        long expireTime = Core.getDeferTimeHOLD() * 60000L;
        long thresholdTime = System.currentTimeMillis() - expireTime;
        return time < thresholdTime;
    }
    
    public static void sendHoldingWarning() {
        for (User user : getSet()) {
            if (user.isUsingHeader()) {
                HashSet<String> keySet = new HashSet<String>();
                TreeSet<Long> timeSet = user.getTimeSet();
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long deferTimeHOLD = Core.getDeferTimeHOLD() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeMiddle = System.currentTimeMillis() - deferTimeRED;
                long timeBegin = System.currentTimeMillis() - deferTimeHOLD;
                int count = 0;
                for (long time : timeSet.subSet(timeBegin, timeEnd)) {
                    Query query = user.getQuery(time);
                    if (
                            query != null &&
                            query.hasSubject() &&
                            query.isNotAdvisedLocal() &&
                            query.isResult("HOLD") &&
                            keySet.add(query.getComplainKey())
                            ) {
                        if (query.isHoldingFull()) {
                            if (query.adviseSenderHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            } else if (!query.isSenderAdvised() && !query.isPass() && query.adviseAdminHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            } else if (!query.isSenderAdvised() && query.adviseRecipientHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            } else if (time < timeMiddle && !query.isPass() && query.adviseAdminHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            } else if (time < timeMiddle && query.adviseRecipientHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            } else if (time < timeMiddle && query.adviseAdminHOLD(time)) {
                                CHANGED = true;
                                Server.logDebug("retention warning sent by e-mail.");
                            }
                        }
                        if (++count > 1024) {
                            break;
                        }
                    }
                }
            }
        }
    }
    
    public static void sendSuspectWarning() {
        for (User user : getSet()) {
            if (user.isUsingHeader()) {
                HashSet<String> keySet = new HashSet<String>();
                TreeSet<Long> timeSet = user.getTimeSet();
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeBegin = System.currentTimeMillis() - deferTimeRED;
                int count = 0;
                for (long time : timeSet.subSet(timeBegin, timeEnd)) {
                    Query query = user.getQuery(time);
                    if (query != null &&
                            query.hasSubject() &&
                            query.hasMessageID() &&
                            query.isNotAdvised() &&
                            query.isResult("ACCEPT") &&
                            keySet.add(query.getComplainKey()) &&
                            query.isSuspectFull()
                            ) {
                        if (query.adviseRecipientSPAM(time)) {
                            CHANGED = true;
                            Server.logDebug("suspect warning sent by e-mail.");
                        }
                        if (++count > 1024) {
                            break;
                        }
                    }
                }
            }
        }
    }
    
    public static void sendBlockedWarning() {
        for (User user : getSet()) {
            if (user.isUsingHeader()) {
                HashSet<String> keySet = new HashSet<String>();
                TreeSet<Long> timeSet = user.getTimeSet();
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeBegin = System.currentTimeMillis() - deferTimeRED;
                int count = 0;
                for (long time : timeSet.subSet(timeBegin, timeEnd)) {
                    Query query = user.getQuery(time);
                    if (query != null &&
                            query.isNotAdvised() &&
                            query.isResult("BLOCK") &&
                            keySet.add(query.getComplainKey())
                            ) {
                        if (query.adviseSenderBLOCK(time)) {
                            CHANGED = true;
                            Server.logDebug("reject warning sent by e-mail.");
                            if (++count > 32) {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    public boolean sendTOTP() {
        return sendTOTP(Locale.US);
    }
    
    public boolean sendTOTP(Locale locale) {
        if (!Core.hasSMTP()) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            Server.logError("no admin e-mail to send TOTP.");
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (NoReply.contains(getEmail(), true)) {
            return false;
        } else {
            return ServerHTTP.enviarOTP(locale, this);
        }
    }
    
    private static void storeDB() {
        try {
            long time2 = System.currentTimeMillis();
            Connection connection = Core.getConnectionMySQL();
            if (connection != null) {
                try {
                    String command = "INSERT INTO user_query "
                            + "(time, user, client, ip, helo, hostname, "
                            + "sender, qualifier, recipient, tokenSet, complainKey, "
                            + "result, mailFrom, replyto, subject, "
                            + "messageID, unsubscribe, linkMap, malware, "
                            + "adminAdvised, senderAdvised, recipientAdvised)\n"
                            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                            + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n"
                            + "ON DUPLICATE KEY UPDATE result = ?, mailFrom = ?, "
                            + "replyto = ?, subject = ?, messageID = ?, "
                            + "unsubscribe = ?, linkMap = ?, malware = ?, "
                            + "adminAdvised = ?, senderAdvised = ?, "
                            + "recipientAdvised = ?";
                    PreparedStatement statement = connection.prepareStatement(command);
                    try {
                        for (User user : getSet()) {
                            for (long time : user.getTimeSet()) {
                                Query query = user.getQuery(time);
                                try {
                                    if (query != null) {
                                        query.storeDB(statement, time);
                                    }
                                } catch (SQLException ex) {
                                    Server.logError(ex);
                                }
                            }
                        }
                        Server.logMySQL(time2, "user_query stored");
                    } finally {
                        statement.close();
                    }
                } finally {
                    connection.close();
                }
            }
        } catch (SQLException ex) {
            Server.logError(ex);
        }
    }
    
    public class Query implements Serializable {
        
        private static final long serialVersionUID = 1L;
        
        private String client;
        private String ip;
        private String helo;
        private String hostname = null;
        private String sender;
        private SPF.Qualifier qualifier;
        private String recipient;
        private final TreeSet<String> tokenSet = new TreeSet<String>();
        private String result;
        private String from = null;
        private String replyto = null;
        private String subject = null;
        private String messageID = null;
        private URL unsubscribe = null;
        private TreeMap<String,Boolean> linkMap = null;
        private String malware = null;
        
        private boolean adminAdvised = false;
        private boolean senderAdvised = false;
        private boolean recipientAdvised = false;
        
        private boolean STORED = false;
        
        private Query(ResultSet rs) throws SQLException, MalformedURLException {
            this.client = rs.getString("client");
            this.ip = rs.getString("ip");
            this.helo = rs.getString("helo");
            this.hostname = rs.getString("hostname");
            this.sender = rs.getString("sender");
            this.qualifier = SPF.Qualifier.get(rs.getString("qualifier"));
            this.recipient = rs.getString("recipient");
            this.tokenSet.addAll(Core.getTreeSet(rs.getString("tokenSet"), ";"));
            this.result = rs.getString("result");
            this.from = rs.getString("from");
            this.replyto = rs.getString("replyto");
            this.subject = rs.getString("subject");
            this.messageID = rs.getString("messageID");
            this.unsubscribe = new URL(rs.getString("unsubscribe"));
            this.linkMap.putAll(Core.getTreeMapBoolean(rs.getString("linkMap"), ";"));
            this.malware = rs.getString("malware");
            this.adminAdvised = rs.getBoolean("adminAdvised");
            this.senderAdvised = rs.getBoolean("senderAdvised");
            this.recipientAdvised = rs.getBoolean("recipientAdvised");
            this.STORED = true;
        }
        
        private void storeDB(PreparedStatement statement, long time) throws SQLException {
            if (!STORED) {
                statement.setLong(1, time);
                statement.setString(2, getEmail());
                statement.setString(3, client);
                statement.setString(4, ip);
                statement.setString(5, helo);
                statement.setString(6, hostname);
                statement.setString(7, sender);
                statement.setString(8, SPF.Qualifier.name(qualifier));
                statement.setString(9, recipient);
                statement.setString(10, Core.getSequence(tokenSet, ";"));
                statement.setString(11, getComplainKey());
                statement.setString(12, result);
                statement.setString(13, from);
                statement.setString(14, replyto);
                statement.setString(15, subject);
                statement.setString(16, messageID);
                statement.setString(17, getUnsubscribeString());
                statement.setString(18, Core.getSequence(linkMap, ";"));
                statement.setString(19, malware);
                statement.setBoolean(20, adminAdvised);
                statement.setBoolean(21, senderAdvised);
                statement.setBoolean(22, recipientAdvised);
                statement.setString(23, result);
                statement.setString(24, from);
                statement.setString(25, replyto);
                statement.setString(26, subject);
                statement.setString(27, messageID);
                statement.setString(28, getUnsubscribeString());
                statement.setString(29, Core.getSequence(linkMap, ";"));
                statement.setString(30, malware);
                statement.setBoolean(31, adminAdvised);
                statement.setBoolean(32, senderAdvised);
                statement.setBoolean(33, recipientAdvised);
                statement.executeUpdate();
                STORED = true;
                CHANGED = true;
            }
        }
        
        private Query(
                String client,
                String ip,
                String helo,
                String hostname,
                String sender,
                SPF.Qualifier qualifier,
                String recipient,
                TreeSet<String> tokenSet,
                String result
        ) throws ProcessException {
            if (!Domain.isHostname(client)) {
                throw new ProcessException("INVALID CLIENT");
            } else if (!Subnet.isValidIP(ip)) {
                throw new ProcessException("INVALID IP");
            } else if (sender != null && !sender.contains("@")) {
                throw new ProcessException("INVALID SENDER");
            } else if (recipient != null && !Domain.isEmail(recipient)) {
                throw new ProcessException("INVALID RECIPIENT");
            } else if (tokenSet == null) {
                throw new ProcessException("INVALID TOKEN SET");
            } else if (result == null) {
                throw new ProcessException("INVALID RESULT");
            } else {
               this.client = Domain.normalizeHostname(client, false);
               this.ip = Subnet.normalizeIP(ip);
               this.helo = helo == null ? null : helo.toLowerCase();
               this.hostname = Domain.normalizeHostname(hostname, false);
               this.hostname = this.hostname == null ? "" : this.hostname;
               this.sender = sender;
               this.qualifier = qualifier;
               this.recipient = recipient;
               this.tokenSet.addAll(tokenSet);
               this.result = result;
               this.STORED = false;
               CHANGED = true;
            }
        }
        
        public String getClient() {
            return client;
        }
        
        public TreeSet<String> getClientEmailSet() {
            TreeSet<String> emailSet = new TreeSet<String>();
            for (Client clientLocal : Client.getClientSet(client)) {
                String email = clientLocal.getEmail();
                if (email != null) {
                    emailSet.add(email);
                }
            }
            return emailSet;
        }

        public String getIP() {
            return ip;
        }

        public String getHELO() {
            if (helo == null) {
                return "";
            } else {
                return helo;
            }
        }
        
        public String getOrigin(boolean pontuacao) {
            String host = getValidHostname();
            if (host == null) {
                return ip;
            } else {
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getOriginDomain(boolean pontuacao) {
            String host = getValidHostname();
            if (host == null) {
                host = helo;
            }
            try {
                return Domain.extractDomain(host, pontuacao);
            } catch (ProcessException ex) {
                return null;
            }
        }
        
        public String getUnblockURL() throws ProcessException {
            return Core.getUnblockURL(
                    getEmail(),
                    getIP(),
                    getMailFrom(),
                    getValidHostname(),
                    getRecipient()
            );
        }
        
        public TreeSet<String> getSenderMXDomainSet() throws NamingException {
            String host = getSenderHostname(false);
            TreeSet<String> mxSet = new TreeSet<String>();
            if (host != null) {
                for (String mx : Reverse.getMXSet(host)) {
                    try {
                        String domain = Domain.extractDomain(mx, false);
                        if (domain != null) {
                            mxSet.add(domain);
                        }
                    } catch (ProcessException ex) {
                    }
                }
            }
            return mxSet;
        }
        
        public ArrayList<String> getSenderMXSet() {
            try {
                return Reverse.getMXSet(getSenderHostname(false));
            } catch (NamingException ex) {
                return null;
            }
        }
        
        public String getSenderHostname(boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else {
                int index = trueSender.indexOf('@');
                String host = trueSender.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getSenderDomain(boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else {
                int index = trueSender.indexOf('@');
                try {
                    String host = trueSender.substring(index + 1);
                    return Domain.extractDomain(host, pontuacao);
                } catch (ProcessException ex) {
                    if (pontuacao) {
                        return '.' + trueSender.substring(index);
                    } else {
                        return trueSender.substring(index);
                    }
                }
            }
        }
        
        public String getMailFrom() {
            return sender;
        }
        
        public String getSender() {
            if (sender == null) {
                return from == null ? replyto : from;
            } else if (NoReply.contains(sender, true)) {
                if (Domain.isValidEmail(from) && !NoReply.contains(from, true)) {
                    return from;
                } else if (Domain.isValidEmail(replyto) && !NoReply.contains(replyto, true)) {
                    return replyto;
                } else {
                    return sender;
                }
            } else if (Provider.containsMX(sender) && Domain.isValidEmail(sender)) {
                return sender;
            } else if (Provider.containsDomain(getValidHostname()) && Provider.containsDomain(sender)) {
                if (from == null && replyto == null) {
                    return sender;
                } else if (replyto == null) {
                    return from;
                } else if (sender.equals(from)) {
                    return replyto;
                } else {
                    return from;
                }
            } else if (Domain.isValidEmail(sender)) {
                return sender;
            } else if (Domain.isValidEmail(from)) {
                return from;
            } else if (Domain.isValidEmail(replyto)) {
                return replyto;
            } else if (Domain.isEmail(sender)) { // Temporário.
                return sender;
            } else if (Domain.isEmail(from)) {
                return from;
            } else if (Domain.isEmail(replyto)) {
                return replyto;
            } else {
                return null;
            }
        }
        
        public String getSenderSimplified(boolean byDomain, boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else if (trueSender.startsWith("mailer-daemon@")) {
                return trueSender;
            } else if (Provider.containsMX(trueSender)) {
                if (Domain.isValidEmail(trueSender)) {
                    return trueSender;
                } else {
                    int index = trueSender.indexOf('@');
                    return trueSender.substring(index);
                }
            } else if (byDomain) {
                int index = trueSender.indexOf('@');
                try {
                    String host = trueSender.substring(index + 1);
                    return Domain.extractDomain(host, pontuacao);
                } catch (ProcessException ex) {
                    return trueSender.substring(index);
                }
            } else {
                int index = trueSender.indexOf('@');
                return trueSender.substring(index);
            }
        }

        public String getQualifierName() {
            if (qualifier == null) {
                return "NONE";
            } else {
                String trueSender = getSender();
                if (trueSender == null) {
                    return "NONE";
                } else if (trueSender.equals(sender)) {
                    return qualifier.name();
                } else {
                    return "NONE";
                }
            }
        }
        
        public String getValidHostname() {
            if (hostname != null) {
                return hostname.length() == 0 ? null : hostname;
            } else if (SPF.matchHELO(ip, helo)) {
                return hostname = helo;
            } else {
                String host = Reverse.getValidHostname(ip);
                if (host == null) {
                    hostname = "";
                    return null;
                } else if (Generic.containsGenericDomain(host)) {
                    hostname = "";
                    return null;
                } else {
                    return hostname = Domain.normalizeHostname(host, false);
                }
            } 
        }
        
        public String getValidHostDomain() {
            try {
                String host = getValidHostname();
                return Domain.extractDomain(host, false);
            } catch (ProcessException ex) {
                return null;
            }
        }
        
        public String getValidator(boolean authentic) {
            if (getSender() == null) {
                return null;
            } else if (authentic && getQualifierName().equals("PASS")) {
                return "PASS";
            } else {
                String domain = getValidHostDomain();
                if (domain == null) {
                    return ip;
                } else {
                    return domain;
                }
            }
        }
        
        public User getUser() {
            return User.this;
        }
        
        public String getUserEmail() {
            return User.this.getEmail();
        }

        public String getRecipient() {
            return recipient;
        }

        public String getResult() {
            return result;
        }
        
        public boolean isResult(String result) {
            return this.result.equals(result);
        }
        
        public boolean isMessage(String MessageID) {
            if (MessageID == null || MessageID.length() == 0) {
                return false;
            } else {
                return MessageID.equals(this.messageID);
            }
        }
        
        private String getComplainKey() {
            String key = getSenderSimplified(true, true);
            if (key == null) {
                key = getOriginDomain(true);
                if (key == null) {
                    key = getOrigin(true);
                }
            }
            return key;
        }
        
        public void processComplainForWhite() {
            String complainKey = getComplainKey();
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuery(time);
                if (query != null && complainKey.equals(query.getComplainKey())) {
                    if (query.isWhite()) {
                        query.clearBlock();
                        if (!query.hasMalware()) {
                            SPF.setHam(time, query.getTokenSet());
                        }
                    }
                }
            }
        }
        
        public void processComplainForBlock() {
            String complainKey = getComplainKey();
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuery(time);
                if (query != null && complainKey.equals(query.getComplainKey())) {
                    if (query.isBlock()) {
                        query.clearWhite();
                        complain(time);
                    }
                }
            }
        }
        
        public void clearWhite() {
            try {
                White.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                White.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        
        public void clearBlock() {
            try {
                Block.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                Block.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            if (linkMap != null) {
                for (String link : linkMap.keySet()) {
                    Block.clearHREF(User.this, link, email);
                }
            }
        }
        
        public String getBlockSender() {
            Situation situation;
            String senderLocal = getSender();
            if (senderLocal == null) {
                return null;
            } else if (senderLocal.equals(sender)) {
                situation = getSituation(true);
            } else {
                situation = Situation.NONE;
            }
            switch (situation) {
                case AUTHENTIC:
                case NONE:
                    return User.this.getEmail() + ':' + getSenderSimplified(true, true);
                case ZONE:
                case IP:
                    return User.this.getEmail() + ':' + getSenderDomain(true) + ";NOTPASS";
                case SAME:
                    String validator = getValidator(false);
                    if (validator == null) {
                        return null;
                    } else {
                        return User.this.getEmail() + ':' + getSenderSimplified(true, true) + ";" + validator;
                    }
                case DOMAIN:
                    String senderSimplified = getSenderSimplified(true, true);
                    if (senderSimplified == null) {
                        return null;
                    } else {
                        return User.this.getEmail() + ':' + senderSimplified;
                    }
                case ORIGIN:
                case ALL:
                    String domain = this.getOriginDomain(false);
                    if (domain == null) {
                        return null;
                    } else {
                        return User.this.getEmail() + ':' + "@;" + domain;
                    }
                default:
                    return null;
            }
        }
        
        public boolean blockSender(long time) {
            Situation situation;
            String senderLocal = getSender();
            if (senderLocal == null) {
                return false;
            } else if (senderLocal.equals(sender)) {
                situation = getSituation(true);
            } else {
                situation = Situation.NONE;
            }
            return block(time, situation);
        }
        
        public boolean block(long time, String situationName) {
            try {
                Situation situation = Situation.valueOf(situationName);
                return block(time, situation);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean complain(long time) {
            return SPF.setSpam(time, tokenSet);
        }
        
        public boolean block(long time, Situation situation) {
            try {
                clearWhite();
                complain(time);
                switch (situation) {
                    case AUTHENTIC:
                    case NONE:
                        return Block.add(User.this, getSenderSimplified(true, true));
                    case ZONE:
                    case IP:
                        return Block.add(User.this, getSenderDomain(true) + ";NOTPASS");
                    case SAME:
                        String validator = getValidator(false);
                        if (validator == null) {
                            return false;
                        } else {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";" + validator);
                        }
                    case DOMAIN:
                        String senderSimplified = getSenderSimplified(true, true);
                        if (senderSimplified == null) {
                            return false;
                        } else {
                            if (SPF.isRed(senderSimplified)) {
                                if (Block.addExact(senderSimplified)) {
                                    Server.logDebug("new BLOCK '" + senderSimplified + "' added by '" + email + "'.");
                                    Peer.sendBlockToAll(senderSimplified);
                                }
                            }
                            return Block.add(User.this, senderSimplified);
                        }
                    case ORIGIN:
                    case ALL:
                        String domain = this.getOriginDomain(false);
                        if (domain == null) {
                            return false;
                        } else {
                            return Block.add(User.this, "@;" + domain);
                        }
                    case RECIPIENT:
                        String recipientAddr = getRecipient();
                        if (recipientAddr == null) {
                            return false;
                        } else {
                            return Trap.addInexistent(User.this, recipientAddr);
                        }
                    default:
                        return false;
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean white(long time, String situationName) {
            try {
                Situation situation = Situation.valueOf(situationName);
                return white(time, situation);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean whiteSender(long time) {
            Situation situation;
            String senderLocal = getSender();
            if (senderLocal == null) {
                return false;
            } else if (senderLocal.equals(sender)) {
                situation = getSituation(true);
            } else {
                situation = getSituation(false);
            }
            return white(time, situation);
        }
        
        public boolean white(long time, Situation situation) {
            try {
                if (situation == null) {
                    return false;
                } else {
                    String domain;
                    clearBlock();
                    SPF.setHam(time, tokenSet);
                    switch (situation) {
                        case ORIGIN:
                            return White.add(User.this, "@;" + getOrigin(false));
                        case IP:
                            return White.add(User.this, getSenderSimplified(false, true) + ";" + getIP());
                        case ZONE:
                            domain = getValidHostDomain();
                            if (domain == null) {
                                return false;
                            } else {
                                return White.add(User.this, getSenderSimplified(false, true) + ";" + domain);
                            }
                        case AUTHENTIC:
                            return White.add(User.this, getSenderSimplified(false, true) + ";PASS");
                        case SAME:
                            String validator = getValidator(false);
                            if (validator == null) {
                                return false;
                            } else {
                                return White.add(User.this, getSenderSimplified(false, true) + ";" + validator);
                            }
                        case RECIPIENT:
                            String recipientAddr = getRecipient();
                            if (recipientAddr == null) {
                                return false;
                            } else {
                                return Trap.clear(getClientEmailSet(), User.this, recipientAddr);
                            }
                        default:
                            return false;
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean hasSender() {
            return sender != null;
        }
        
        public boolean hasRecipient() {
            return recipient != null;
        }
        
        public boolean hasMessageID() {
            return messageID != null;
        }
        
        public boolean hasSubject() {
            return subject != null;
        }
        
        public boolean hasMalware() {
            return malware != null;
        }
        
        public boolean isHolding() {
            return result.equals("HOLD");
        }
        
        public boolean isHoldingFull() {
            if (!isHolding()) {
                return false;
            } else if (isWhiteSender()) {
                return false;
            } else if (isBlockSender()) {
                return false;
            } else {
                return true;
            }
        }
        
        public boolean isSuspectFull() {
            if (!isResult("ACCEPT")) {
                return false;
            } else if (!hasMessageID()) {
                return false;
            } else if (!hasSubject()) {
                return false;
            } else if (isWhiteSender()) {
                return false;
            } else if (isBlockSender()) {
                return false;
            } else if (hasTokenRed()) {
                return true;
            } else if (isAnyLinkRED()) {
                return true;
            } else if (hasClusterRed()) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean isAdminAdvised() {
            return adminAdvised;
        }
        
        public boolean isSenderAdvised() {
            return senderAdvised;
        }
        
        public boolean isRecipientAdvised() {
            return recipientAdvised;
        }
        
        public boolean isNotAdvised() {
            return !senderAdvised && !recipientAdvised && !adminAdvised;
        }
        
        public boolean isNotAdvisedLocal() {
            return !recipientAdvised && !adminAdvised;
        }
        
        public boolean isWhite() {
            if (sender != null && White.find(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient) != null) {
                return true;
            } else if (from != null && White.find(null, User.this, ip, from, getValidHostname(), "NONE", recipient) != null) {
                return true;
            } else if (replyto != null && White.find(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient) != null) {
                return true;
            } else {
                return White.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient) != null;
            }
        }
        
        public boolean isWhiteSender() {
            return White.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient) != null;
        }
        
        public String getWhite() {
            String white;
            if (sender != null && (white = White.find(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient)) != null) {
                return white;
            } else if (from != null && (white = White.find(null, User.this, ip, from, getValidHostname(), "NONE", recipient)) != null) {
                return white;
            } else if (replyto != null && (white = White.find(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient)) != null) {
                return white;
            } else {
                return White.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
            }
        }
        
        public boolean isBlock() {
            if (sender != null && Block.find(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient, false, true, true, true) != null) {
                return true;
            } else if (from != null && Block.find(null, User.this, ip, from, getValidHostname(), "NONE", recipient, false, true, true, true) != null) {
                return true;
            } else if (replyto != null && Block.find(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient, false, true, true, true) != null) {
                return true;
            } else {
                return Block.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient, false, true, true, true) != null;
            }
        }
        
        public boolean isBlockSender() {
            return Block.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient, false, false, false, false) != null;
        }
        
        public boolean isAnyLinkBLOCK() {
            boolean blocked = false;
            for (String token : getLinkKeySet()) {
                if (Block.findHREF(User.this, token) != null) {
                    setLinkBlocked(token);
                    blocked = true;
                }
            }
            return blocked;
        }
        
        public boolean isAnyLinkRED() {
            for (String token : getLinkKeySet()) {
                if (SPF.isRed(token)) {
                    return true;
                } else if (Block.find(User.this, token, false, false, false) != null) {
                    return true;
//                } else if (Domain.isHostname(token)) {
//                    String listed = Reverse.getListedHost(token, "multi.uribl.com", "127.0.0.2", "127.0.0.4", "127.0.0.8");
//                    if (listed != null) {
//                        Server.logDebug("host " + token + " is listed in 'multi.uribl.com;" + listed + "'.");
//                        return true;
//                    }
//                } else if (Subnet.isValidIP(token)) {
//                    String listed = Reverse.getListedIP(token, "multi.uribl.com", "127.0.0.2", "127.0.0.4", "127.0.0.8");
//                    if (listed != null) {
//                        Server.logDebug("host " + token + " is listed in 'multi.uribl.com;" + listed + "'.");
//                        return true;
//                    }
                }
            }
            return false;
        }
        
        public String getBlock() {
            String block;
            if (sender != null && (block = Block.find(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient, false, true, true, true)) != null) {
                return block;
            } else if (from != null && (block = Block.find(null, User.this, ip, from, getValidHostname(), "NONE", recipient, false, true, true, true)) != null) {
                return block;
            } else if (replyto != null && (block = Block.find(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient, false, true, true, true)) != null) {
                return block;
            } else {
                return Block.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient, false, true, true, true);
            }
        }
        
        public boolean isInexistent(Client client) {
            if (recipient == null) {
                return false;
            } else {
                return Trap.containsAnything(client, User.this, recipient);
            }
        }
        
        public boolean isRoutable() {
            if (recipient == null) {
                return true;
            } else {
                return getTrapTime() == null;
            }
        }
        
        public boolean isToPostmaster() {
            if (recipient == null) {
                return false;
            } else {
                return recipient.startsWith("postmaster@");
            }
        }
        
        public Long getTrapTime() {
            Long timeUser = Trap.getTime(User.this, recipient);
            for (String clientEmail : getClientEmailSet()) {
                Long timeClient = Trap.getTime(clientEmail, recipient);
                if (timeClient != null) {
                    if (timeUser == null) {
                        timeUser = timeClient;
                    } else {
                        timeUser = Math.min(timeClient, timeUser);
                    }
                }
            }
            return timeUser;
        }
        
        public boolean isSenderWhite() {
            String validator = getValidator(true);
            if (validator == null) {
                return false;
            } else {
                return White.containsExtact(User.this, getSenderSimplified(false, true) + ';' + validator);
            }
        }
        
        public boolean isOriginWhite() {
            return White.containsExtact(User.this, "@;" + getOrigin(false));
        }
        
        public boolean isSenderBlock(boolean validation) {
            if (validation) {
                return Block.containsExact(User.this, getSenderDomain(true) + ";NOTPASS");
            } else {
                return Block.containsExact(User.this, getSenderSimplified(true, true));
            }
        }
        
        public boolean isOriginBlock() {
            return Block.containsExact(User.this, "@;" + getOrigin(false));
        }
        
        public boolean isOriginDomainBlock() {
            String domain = getOriginDomain(false);
            if (domain == null) {
                return false;
            } else {
                return Block.containsExact(User.this, "@;" + domain);
            }
        }
        
        public boolean isSenderRed() {
            String tueSender = getSender();
            if (tueSender == null) {
                return false;
            } else if (getQualifierName().equals("PASS")) {
                String token;
                if (Provider.containsMX(tueSender)) {
                    token = tueSender;
                } else {
                    int index = tueSender.indexOf('@');
                    token = tueSender.substring(index);
                }
                Distribution distribution = SPF.getDistribution(token);
                if (distribution == null) {
                    return false;
                } else {
                    return distribution.isRed();
                }
            } else {
                return false;
            }
        }
        
        public boolean isSenderGreen() {
            String tueSender = getSender();
            if (tueSender == null) {
                return false;
            } else if (getQualifierName().equals("PASS")) {
                String token;
                if (Provider.containsMX(tueSender)) {
                    token = tueSender;
                } else {
                    int index = tueSender.indexOf('@');
                    token = tueSender.substring(index);
                }
                Distribution distribution = SPF.getDistribution(token);
                if (distribution == null) {
                    return true;
                } else {
                    return distribution.isGreen();
                }
            } else {
                return false;
            }
        }
        
        public boolean isPass() {
            return qualifier  == SPF.Qualifier.PASS;
        }
        
        public boolean isFail() {
            return qualifier  == SPF.Qualifier.FAIL;
        }
        
        public boolean isSoftfail() {
            return qualifier  == SPF.Qualifier.SOFTFAIL;
        }
        
        public boolean hasTokenRed() {
            return SPF.hasRed(tokenSet);
        }
        
        public boolean hasClusterRed() {
            return Analise.isCusterRED(ip, sender, hostname);
        }
        
        public boolean hasYellow() {
            return SPF.hasYellow(tokenSet);
        }
        
        public boolean isGreen() {
            return SPF.isGreen(tokenSet);
        }
        
        public boolean isSenderGood() {
            if (isPass()) {
                String mx = Domain.extractHost(sender, true);
                return SPF.isGood(Provider.containsExact(mx) ? sender : mx);
            } else {
                return false;
            }
        }
        
        public TreeSet<String> getLinkSet() {
            if (linkMap == null) {
                return null;
            } else {
                TreeSet<String> resultSet = new TreeSet<String>();
                resultSet.addAll(linkMap.keySet());
                return resultSet;
            }
        }
        
        public TreeSet<String> getTokenSet() {
            TreeSet<String> resultSet = new TreeSet<String>();
            resultSet.addAll(tokenSet);
            return resultSet;
        }
        
        public String getMalware() {
            return malware;
        }
        
        public boolean setResult(String result) {
            if (result == null) {
                return false;
            } else if (result.equals("MALWARE")) {
                this.malware = "FOUND";
                this.result = "REJECT";
                this.STORED = false;
                return CHANGED = true;
            } else if (!result.equals(this.result)) {
                this.result = result;
                this.STORED = false;
                return CHANGED = true;
            } else {
                return false;
            }
        }
        
        private boolean match(String filter) {
            if (filter == null) {
                return false;
            } else if (filter.equals("retida") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("REJECT")) {
                return true;
            } else if (SubnetIPv4.isValidIPv4(filter)) {
                filter = SubnetIPv4.normalizeIPv4(filter);
                return filter.equals(getIP());
            } else if (SubnetIPv6.isValidIPv6(filter)) {
                filter = SubnetIPv6.normalizeIPv6(filter);
                return filter.equals(getIP());
            } else if (Domain.isValidEmail(filter)) {
                if (filter.equals(getMailFrom())) {
                    return true;
                } else if (filter.equals(getFrom())) {
                    return true;
                } else if (filter.equals(getReplyTo())) {
                    return true;
                } else if (filter.equals(getRecipient())) {
                    return true;
                } else {
                    return false;
                }
            } else if (Domain.isHostname(filter)) {
                String hostname = getValidHostname();
                String mailForm = "." + Domain.extractHost(getMailFrom(), false);
                String from = "." + Domain.extractHost(getFrom(), false);
                String replyto = "." + Domain.extractHost(getReplyTo(), false);
                String recipient = "." + Domain.extractHost(getRecipient(), false);
                filter = Domain.normalizeHostname(filter, true);
                if (hostname != null && hostname.endsWith(filter)) {
                    return true;
                } else if (mailForm != null && mailForm.endsWith(filter)) {
                    return true;
                } else if (from != null && from.endsWith(filter)) {
                    return true;
                } else if (replyto != null && replyto.endsWith(filter)) {
                    return true;
                } else if (recipient != null && recipient.endsWith(filter)) {
                    return true;
                } else {
                    return false;
                }
            } else if (filter.startsWith("@") && Domain.isHostname(filter.substring(1))) {
                String mailForm = Domain.extractHost(getMailFrom(), true);
                String from = Domain.extractHost(getFrom(), true);
                String replyto = Domain.extractHost(getReplyTo(), true);
                String recipient = Domain.extractHost(getRecipient(), true);
                filter = Domain.normalizeHostname(filter, true);
                if (mailForm != null && mailForm.endsWith(filter)) {
                    return true;
                } else if (from != null && from.endsWith(filter)) {
                    return true;
                } else if (replyto != null && replyto.endsWith(filter)) {
                    return true;
                } else if (recipient != null && recipient.endsWith(filter)) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        public String getFrom() {
            return from;
        }
        
        public String getReplyTo() {
            return replyto;
        }
        
        public String getSubject() {
            return subject;
        }
        
        public String getMessageID() {
            return messageID;
        }
        
        public URL getUnsubscribeURL() {
            return unsubscribe;
        }
        
        public String getUnsubscribeString() {
            if (unsubscribe == null) {
                return null;
            } else {
                return unsubscribe.toExternalForm();
            }
        }
        
        private void setLinkBlocked(String link) {
            if (linkMap == null) {
                linkMap = new TreeMap<String,Boolean>();
            }
            linkMap.put(link, true);
            STORED = false;
            CHANGED = true;
        }
        
        public boolean hasLinkBlocked() {
            for (String link : getLinkKeySet()) {
                if (isLinkBlocked(link)) {
                    return true;
                }
            }
            return false;
        }
        
        public boolean isLinkBlocked(String link) {
            if (link == null) {
                return false;
            } else if (linkMap == null) {
                return false;
            } else {
                Boolean blocked = linkMap.get(link);
                if (blocked == null) {
                    return false;
                } else {
                    return blocked;
                }
            }
        }
        
        public boolean hasMiscellaneousSymbols() {
            return Core.hasMiscellaneousSymbols(subject);
        }
        
        private TreeSet<String> getLinkKeySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            if (linkMap != null) {
                keySet.addAll(linkMap.keySet());
            }
            return keySet;
        }
        
        public boolean addLink(String link) {
            if (link == null) {
                return false;
            } else {
                if (this.linkMap == null) {
                    this.linkMap = new TreeMap<String,Boolean>();
                }
                boolean blocked = false;
                if (isToPostmaster()) {
                    this.linkMap.put(link, false);
                } else if (Block.findHREF(User.this, link) == null) {
                    this.linkMap.put(link, false);
                } else {
                    this.linkMap.put(link, true);
                    blocked = true;
                }
                STORED = false;
                CHANGED = true;
                return blocked;
            }
        }
        
        public boolean setLinkSet(TreeSet<String> linkSet) {
            if (linkSet == null) {
                return false;
            } else {
                if (this.linkMap == null) {
                    this.linkMap = new TreeMap<String,Boolean>();
                }
                boolean blocked = false;
                for (String link : linkSet) {
                    if (isToPostmaster()) {
                        this.linkMap.put(link, false);
                    } else if (Block.findHREF(User.this, link) == null) {
                        this.linkMap.put(link, false);
                    } else {
                        this.linkMap.put(link, true);
                        blocked = true;
                    }
                }
                STORED = false;
                CHANGED = true;
                return blocked;
            }
        }
        
        public boolean setMalware(String malware) {
            if (malware == null) {
                return false;
            } else if ((malware = malware.length() == 0 ? "FOUND" : malware).equals(this.malware)) {
                return false;
            } else {
                this.malware = malware;
                this.result = "REJECT";
                this.STORED = false;
                return CHANGED = true;
            }
        }
        
        public boolean needHeader() {
            if (!User.this.usingHeader) {
                return false;
            } else if (Generic.containsGenericSoft(sender)) {
                return false;
            } else if (Provider.containsMX(sender) && Domain.isValidEmail(sender)) {
                return false;
            } else {
                return Provider.containsDomain(getValidHostname()) && Provider.containsDomain(sender);
            }
        }
        
        public String setHeader(
                String from,
                String replyto,
                String subject,
                String messageID,
                String unsubscribe
        ) {
            User.this.usingHeader = true;
            if (from == null || from.length() == 0) {
                if (this.from != null) {
                    this.from = null;
                    this.STORED = false;
                    CHANGED = true;
                }
            } else if (Domain.isEmail(from = from.toLowerCase()) && !from.equals(this.from)) {
                this.from = from;
                this.STORED = false;
                CHANGED = true;
            }
            if (replyto == null || replyto.length() == 0) {
                if (this.replyto != null) {
                    this.replyto = null;
                    this.STORED = false;
                    CHANGED = true;
                }
            } else if (Domain.isEmail(replyto = replyto.toLowerCase()) && !replyto.equals(this.replyto)) {
                this.replyto = replyto;
                this.STORED = false;
                CHANGED = true;
            }
            if (subject == null || subject.length() == 0) {
                if (this.subject != null) {
                    this.subject = null;
                    this.STORED = false;
                    CHANGED = true;
                }
            } else {
                try {
                    subject = MimeUtility.decodeText(subject);
                } catch (UnsupportedEncodingException ex) {
                }
                if (!subject.equals(this.subject)) {
                    this.subject = subject;
                    this.STORED = false;
                    CHANGED = true;
                }
            }
            if (messageID == null || messageID.length() == 0) {
                if (this.messageID != null) {
                    this.messageID = null;
                    this.STORED = false;
                    CHANGED = true;
                }
            } else {
                int index = messageID.indexOf('<');
                if (index >= 0) {
                    messageID = messageID.substring(index+1);
                    index = messageID.indexOf('>');
                    if (index > 0) {
                        messageID = messageID.substring(0, index);
                        if (!messageID.equals(this.messageID)) {
                            this.messageID = messageID;
                            this.STORED = false;
                            CHANGED = true;
                        }
                    }
                }
            }
            boolean reject = false;
            if (unsubscribe != null && unsubscribe.length() > 0) {
                try {
                    int index = unsubscribe.indexOf('<');
                    if (index >= 0) {
                        unsubscribe = unsubscribe.substring(index+1);
                        index = unsubscribe.indexOf('>');
                        if (index > 0) {
                            unsubscribe = unsubscribe.substring(0, index);
                            URL url = new URL(unsubscribe);
                            reject = addLink(url.getHost());
                            if (!url.equals(this.unsubscribe)) {
                                this.unsubscribe = url;
                                this.STORED = false;
                                CHANGED = true;
                            }
                        }
                    }
                } catch (MalformedURLException ex) {
                    Server.logTrace("malformed unsubscribe URL: " + unsubscribe);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            if (isWhite()) {
                clearBlock();
                return this.result = "WHITE";
            } else if (isToPostmaster()) {
                return null;
            } else if (isBlock()) {
                clearWhite();
                return this.result = "BLOCK";
            } else if (reject) {
                return this.result = "REJECT";
            } else {
                return null;
            }
        }
        
        public boolean isSpam(long time) {
            for (String token : tokenSet) {
                Distribution distribution = SPF.getDistribution(token);
                if (distribution != null && distribution.isSpam(time)) {
                    return true;
                }
            }
            return false;
        }
        
        public Situation getSituation(boolean authentic) {
            String validator = getValidator(true);
            if (validator == null) {
                return Situation.ORIGIN;
            } else if (authentic && validator.equals("PASS")) {
                return Situation.AUTHENTIC;
            } else if (Subnet.isValidIP(validator)) {
                return Situation.IP;
            } else {
                return Situation.ZONE;
            }
        }
        
        public Situation getOriginWhiteSituation() {
            if (isOriginWhite()) {
                return Situation.ORIGIN;
            } else if (isWhite()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public Situation getSenderWhiteSituation() {
            if (isSenderWhite()) {
                String validator = getValidator(true);
                if (validator == null) {
                    return Situation.ORIGIN;
                } else if (validator.equals("PASS")) {
                    return Situation.AUTHENTIC;
                } else if (Subnet.isValidIP(validator)) {
                    return Situation.IP;
                } else {
                    return Situation.ZONE;
                }
            } else if (isOriginWhite()) {
                return Situation.ORIGIN;
            } else if (isWhite()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public Situation getOriginBlockSituation() {
            if (isOriginDomainBlock()) {
                return Situation.ALL;
            } else if (isOriginBlock()) {
                return Situation.ORIGIN;
            } else if (isBlock()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public Situation getSenderBlockSituation() {
            String validator = getValidator(false);
            if (validator == null && isOriginDomainBlock()) {
                return Situation.ALL;
            } else if (isSenderBlock(false)) {
                return Situation.DOMAIN;
            } else if (isSenderBlock(true)) {
                if (validator == null) {
                    return Situation.ORIGIN;
                } else if (Subnet.isValidIP(validator)) {
                    return Situation.IP;
                } else {
                    return Situation.ZONE;
                }
            } else if (isOriginBlock()) {
                return Situation.ORIGIN;
            } else if (isBlock()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public synchronized boolean adviseRecipientHOLD(long time) {
            if (recipientAdvised) {
                return false;
            } else if (!Core.hasSMTP()) {
                return false;
            } else {
                String mailFrom = getMailFrom();
                String recipientLocal = getRecipient();
                if (mailFrom != null &&
                        Domain.isValidEmail(mailFrom) &&
                        Domain.isValidEmail(recipientLocal) &&
                        !NoReply.contains(recipientLocal, true)
                        ) {
                    try {
                        String url = Core.getUnholdURL(User.this, time);
                        if (url == null) {
                            return false;
                        } else {
                            Server.logDebug("sending retention release by e-mail.");
                            String subjectLocal = getSubject();
                            if (subjectLocal == null) {
                                if (recipientLocal.endsWith(".br") || recipientLocal.endsWith(".pt")) {
                                    subjectLocal = "Aviso de retenção de mensagem";
                                } else {
                                    subjectLocal = "Message retention warning";
                                }
                            }
                            String qualifierLocal = getQualifierName();
                            InternetAddress[] recipients = InternetAddress.parse(recipientLocal);
                            Properties props = System.getProperties();
                            Session session = Session.getDefaultInstance(props);
                            MimeMessage message = new MimeMessage(session);
                            message.setHeader("Date", Core.getEmailDate());
                            message.setFrom(Core.getAdminInternetAddress());
                            message.addRecipients(Message.RecipientType.TO, recipients);
                            message.setReplyTo(User.this.getInternetAddresses());
                            message.setSubject(subjectLocal);
                            Locale locale = Locale.UK;
                            if (recipientLocal.endsWith(".br")) {
                                locale = new Locale("pt", "BR");
                            } else if (recipientLocal.endsWith(".pt")) {
                                locale = new Locale("pt", "PT");
                            }
                            // Corpo da mensagem.
                            StringBuilder builder = new StringBuilder();
                            builder.append("<!DOCTYPE html>\n");
                            builder.append("<html lang=\"");
                            builder.append(locale.getLanguage());
                            builder.append("\">\n");
                            builder.append("  <head>\n");
                            builder.append("    <meta charset=\"UTF-8\">\n");
                            builder.append("    <title>");
                            builder.append(subject);
                            builder.append("</title>\n");
                            ServerHTTP.loadStyleCSS(builder);
                            builder.append("  </head>\n");
                            builder.append("  <body>\n");
                            builder.append("    <div id=\"container\">\n");
                            builder.append("      <div id=\"divlogo\">\n");
                            builder.append("        <img src=\"cid:logo\">\n");
                            builder.append("      </div>\n");
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagem");
                                ServerHTTP.buildText(builder, "Uma mensagem enviada por " + mailFrom + " foi retida por suspeita de SPAM.");
                                if (!qualifierLocal.equals("PASS")) {
                                    ServerHTTP.buildText(builder, "<b>Atenção! Este remetente não pôde ser autenticado. Isso significa que não há garantia desta mensagem ser genuína!</b>");
                                    String hostDomain = getValidHostDomain();
                                    if (hostDomain == null) {
                                        ServerHTTP.buildText(builder, "<b>Não é possível determinar com segurança qual servidor disparou esta mensagem.</b>");
                                    } else {
                                        ServerHTTP.buildText(builder, "A mensagem foi disparada por um servidor no domínio " + hostDomain + ".");
                                    }
                                }
                                ServerHTTP.buildText(builder, "Se você considera esta mensagem legítima, acesse esta URL para efetivar a sua liberação:");
                            } else {
                                ServerHTTP.buildMessage(builder, "Message retention warning");
                                ServerHTTP.buildText(builder, "A message sent from " + mailFrom + " was retained under suspicion of SPAM.");
                                if (!qualifierLocal.equals("PASS")) {
                                    ServerHTTP.buildText(builder, "<b>Attention! This sender could not be authenticated. This means that there is no guarantee that this message will be genuine!");
                                    String hostDomain = getValidHostDomain();
                                    if (hostDomain == null) {
                                        ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                    } else {
                                        ServerHTTP.buildText(builder, "The message was fired by a server in domain " + hostDomain + ".");
                                    }
                                }
                                ServerHTTP.buildText(builder, "If you consider this message legitimate, access this URL to complete its release:");
                            }
                            ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                            if (!User.this.isEmail(recipientLocal)) {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    ServerHTTP.buildText(builder, "Para maiores informações, entre em contato com o seu setor de TI.");
                                } else {
                                    ServerHTTP.buildText(builder, "For more information, contact your post administrator.");
                                }
                            }
                            ServerHTTP.buildFooter(builder, locale);
                            builder.append("    </div>\n");
                            builder.append("  </body>\n");
                            builder.append("</html>\n");
                            // Making HTML part.
                            MimeBodyPart htmlPart = new MimeBodyPart();
                            htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                            // Making QRcode part.
                            MimeBodyPart logoPart = new MimeBodyPart();
                            File logoFile = ServerHTTP.getWebFile("logo.png");
                            logoPart.attachFile(logoFile);
                            logoPart.setContentID("<logo>");
                            logoPart.setDisposition(MimeBodyPart.INLINE);
                            // Join both parts.
                            MimeMultipart content = new MimeMultipart();
                            content.addBodyPart(htmlPart);
                            content.addBodyPart(logoPart);
                            // Set multiplart content.
                            message.setContent(content);
                            message.saveChanges();
                            // Enviar mensagem.
                            return recipientAdvised = Core.sendMessage(message);
                        }
                    } catch (SMTPSendFailedException ex) {
                        return false;
                    } catch (Exception ex) {
                        Server.logError(ex);
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        
        public synchronized boolean adviseRecipientSPAM(long time) {
            if (recipientAdvised || !Core.hasSMTP()) {
                return false;
            } else {
                String mailFrom = getMailFrom();
                String recipientLocal = getRecipient();
                String subjectLocal = getSubject();
                if (mailFrom != null && subjectLocal != null && Domain.isValidEmail(recipientLocal) && !NoReply.contains(recipientLocal, true)) {
                    try {
                        String url = Core.getBlockURL(User.this, time);
                        if (url == null) {
                            return false;
                        } else {
                            Server.logDebug("sending suspect alert by e-mail.");
                            String messageidLocal = getMessageID();
                            InternetAddress[] recipients = InternetAddress.parse(recipientLocal);
                            Properties props = System.getProperties();
                            Session session = Session.getDefaultInstance(props);
                            MimeMessage message = new MimeMessage(session);
                            message.setHeader("Date", Core.getEmailDate());
                            message.setFrom(Core.getAdminInternetAddress());
                            message.addRecipients(Message.RecipientType.TO, recipients);
                            message.setReplyTo(User.this.getInternetAddresses());
                            message.setSubject(subjectLocal);
                            if (messageidLocal != null) {
                                message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                            }
                            Locale locale = Locale.UK;
                            if (recipientLocal.endsWith(".br")) {
                                locale = new Locale("pt", "BR");
                            } else if (recipientLocal.endsWith(".pt")) {
                                locale = new Locale("pt", "PT");
                            }
                            // Corpo da mensagem.
                            StringBuilder builder = new StringBuilder();
                            builder.append("<!DOCTYPE html>\n");
                            builder.append("<html lang=\"");
                            builder.append(locale.getLanguage());
                            builder.append("\">\n");
                            builder.append("  <head>\n");
                            builder.append("    <meta charset=\"UTF-8\">\n");
                            builder.append("    <title>");
                            builder.append(subject);
                            builder.append("</title>\n");
                            ServerHTTP.loadStyleCSS(builder);
                            builder.append("  </head>\n");
                            builder.append("  <body>\n");
                            builder.append("  <body>\n");
                            builder.append("    <div id=\"container\">\n");
                            builder.append("      <div id=\"divlogo\">\n");
                            builder.append("        <img src=\"cid:logo\">\n");
                            builder.append("      </div>\n");
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                ServerHTTP.buildMessage(builder, "Alerta de suspeita de SPAM");
                                ServerHTTP.buildText(builder, "Esta mensagem, cujo assunto foi preservado e havia sido enviada por " + mailFrom + ", foi entregue em sua caixa postal por haver nenhuma suspeita sobre ela.");
                                ServerHTTP.buildText(builder, "Informações mais recentes levantam forte suspeita de que esta mensagem seria SPAM.");
                                ServerHTTP.buildText(builder, "Se você concorda com esta nova interpretação, acesse esta URL para bloquear o remetente e para contribuir para o combate de SPAM na Internet:");
                            } else {
                                ServerHTTP.buildMessage(builder, "SPAM suspected alert");
                                ServerHTTP.buildText(builder, "This message, whose subject was preserved and sent by " + mailFrom + ", was delivered to your mailbox because there was no suspicion about it.");
                                ServerHTTP.buildText(builder, "More recent information raises strong suspicion that this message would be SPAM.");
                                ServerHTTP.buildText(builder, "If you agree with this new interpretation, access this URL to block the sender and contribute to the fight against spam on the Internet:");
                            }
                            ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                            if (!User.this.isEmail(recipientLocal)) {
                                String abuseEmail = Core.getAbuseEmail();
                                if (abuseEmail != null) {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        ServerHTTP.buildText(builder, "Se você receber qualquer mensagem de SPAM, poderá encaminhar a mensagem de SPAM para " + abuseEmail + ".");
                                        ServerHTTP.buildText(builder, "Este remetente poderá ser bloqueado automaticamente no caso de recebermos muitas denuncias contra ele.");
                                    } else {
                                        ServerHTTP.buildText(builder, "If you receive any SPAM message, you can forward the SPAM message to " + abuseEmail + ".");
                                        ServerHTTP.buildText(builder, "This sender may be automatically blocked if we receive too many complaints against him.");
                                    }
                                }
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    ServerHTTP.buildText(builder, "Para maiores informações, entre em contato com o seu setor de TI.");
                                } else {
                                    ServerHTTP.buildText(builder, "For more information, contact your post administrator.");
                                }
                            }
                            ServerHTTP.buildFooter(builder, locale);
                            builder.append("    </div>\n");
                            builder.append("  </body>\n");
                            builder.append("</html>\n");
                            // Making HTML part.
                            MimeBodyPart htmlPart = new MimeBodyPart();
                            htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                            // Making QRcode part.
                            MimeBodyPart logoPart = new MimeBodyPart();
                            File logoFile = ServerHTTP.getWebFile("logo.png");
                            logoPart.attachFile(logoFile);
                            logoPart.setContentID("<logo>");
                            logoPart.setDisposition(MimeBodyPart.INLINE);
                            // Join both parts.
                            MimeMultipart content = new MimeMultipart();
                            content.addBodyPart(htmlPart);
                            content.addBodyPart(logoPart);
                            // Set multiplart content.
                            message.setContent(content);
                            message.saveChanges();
                            // Enviar mensagem.
                            return recipientAdvised = Core.sendMessage(message);
                        }
                    } catch (SMTPSendFailedException ex) {
                        return false;
                    } catch (Exception ex) {
                        Server.logError(ex);
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        
        private synchronized boolean adviseSenderHOLD(long time) {
            String mailFrom = getMailFrom();
            String recipientLocal = getRecipient();
            if (senderAdvised) {
                return false;
            } else if (!Core.hasSMTP()) {
                return false;
            } else if (!isPass()) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!Domain.isValidEmail(mailFrom)) {
                return false;
            } else if (!NoReply.contains(mailFrom, true)) {
                return false;
            } else if (Generic.containsGeneric(mailFrom)) {
                return false;
            } else {
                try {
                    String url = Core.getHoldingURL(User.this, time);
                    if (url == null) {
                        return false;
                    } else {
                        Server.logDebug("sending retention warning by e-mail.");
                        Locale locale = Locale.UK;
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (mailFrom.endsWith(".br")) {
                                locale = new Locale("pt", "BR");
                                subjectLocal = "Aviso de retenção de mensagem";
                            } else if (mailFrom.endsWith(".pt")) {
                                locale = new Locale("pt", "PT");
                                subjectLocal = "Aviso de retenção de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String messageidLocal = getMessageID();
                        InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                        Properties props = System.getProperties();
                        Session session = Session.getDefaultInstance(props);
                        MimeMessage message = new MimeMessage(session);
                        message.setHeader("Date", Core.getEmailDate());
                        message.setFrom(Core.getAdminInternetAddress());
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(User.this.getInternetAddresses());
                        message.setSubject(subjectLocal);
                        if (messageidLocal != null) {
                            message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                        }
                        // Corpo da mensagem.
                        StringBuilder builder = new StringBuilder();
                        builder.append("<!DOCTYPE html>\n");
                        builder.append("<html lang=\"");
                        builder.append(locale.getLanguage());
                        builder.append("\">\n");
                        builder.append("  <head>\n");
                        builder.append("    <meta charset=\"UTF-8\">\n");
                        builder.append("    <title>");
                        builder.append(subject);
                        builder.append("</title>\n");
                        ServerHTTP.loadStyleCSS(builder);
                        builder.append("  </head>\n");
                        builder.append("  <body>\n");
                        builder.append("    <div id=\"container\">\n");
                        builder.append("      <div id=\"divlogo\">\n");
                        builder.append("        <img src=\"cid:logo\">\n");
                        builder.append("      </div>\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagem");
                            ServerHTTP.buildText(builder, "Esta mensagem, que foi enviada para " + recipientLocal + " foi retida por suspeita de SPAM.");
                            ServerHTTP.buildText(builder, "Se você considera isto um engano, acesse esta URL para solicitar a sua liberação:");
                        } else {
                            ServerHTTP.buildMessage(builder, "Message retention warning");
                            ServerHTTP.buildText(builder, "This message, which was sent to " + recipientLocal + " was retained under suspicion of SPAM.");
                            ServerHTTP.buildText(builder, "If you consider this a mistake, access this URL to request its release:");
                        }
                        ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                        ServerHTTP.buildFooter(builder, locale);
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making QRcode part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart();
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        return senderAdvised = Core.sendMessage(message);
                    }
                } catch (SMTPSendFailedException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        private synchronized boolean adviseSenderBLOCK(long time) {
            String mailFrom = getMailFrom();
            String recipientLocal = getRecipient();
            if (senderAdvised) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!Core.hasSMTP()) {
                return false;
            } else if (!isSenderGreen()) {
                return false;
            } else if (!Domain.isValidEmail(mailFrom)) {
                return false;
            } else if (NoReply.contains(mailFrom, true)) {
                return false;
            } else if (Generic.containsGeneric(mailFrom)) {
                return false;
            } else if (isSenderWhite()) {
                return false;
            } else if (isSenderBlock(false)) {
                senderAdvised = true;
                return false;
            } else {
                try {
                    String url = getUnblockURL();
                    if (url == null) {
                        return false;
                    } else {
                        Server.logDebug("sending blocked warning by e-mail.");
                        Locale locale = Locale.UK;
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (mailFrom.endsWith(".br")) {
                                locale = new Locale("pt", "BR");
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else if (mailFrom.endsWith(".pt")) {
                                locale = new Locale("pt", "PT");
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String messageidLocal = getMessageID();
                        InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                        Properties props = System.getProperties();
                        Session session = Session.getDefaultInstance(props);
                        MimeMessage message = new MimeMessage(session);
                        message.setHeader("Date", Core.getEmailDate());
                        message.setFrom(Core.getAdminInternetAddress());
                        message.addRecipients(Message.RecipientType.TO, recipients);
//                        message.addRecipients(Message.RecipientType.BCC, InternetAddress.parse("leandro@spfbl.net")); // Temporário.
                        message.setReplyTo(User.this.getInternetAddresses());
                        message.setSubject(subjectLocal);
                        if (messageidLocal != null) {
                            message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                        }
                        // Corpo da mensagem.
                        StringBuilder builder = new StringBuilder();
                        builder.append("<!DOCTYPE html>\n");
                        builder.append("<html lang=\"");
                        builder.append(locale.getLanguage());
                        builder.append("\">\n");
                        builder.append("  <head>\n");
                        builder.append("    <meta charset=\"UTF-8\">\n");
                        builder.append("    <title>");
                        builder.append(subject);
                        builder.append("</title>\n");
                        ServerHTTP.loadStyleCSS(builder);
                        builder.append("  </head>\n");
                        builder.append("  <body>\n");
                        builder.append("    <div id=\"container\">\n");
                        builder.append("      <div id=\"divlogo\">\n");
                        builder.append("        <img src=\"cid:logo\">\n");
                        builder.append("      </div>\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildMessage(builder, "Aviso de bloqueio de mensagem");
                            ServerHTTP.buildText(builder, "A mensagem, que foi enviada para " + recipientLocal + " foi rejeitada por bloqueio manual.");
                            ServerHTTP.buildText(builder, "Se você considera isto um engano, acesse esta URL para solicitar o desbloqueio:");
                        } else {
                            ServerHTTP.buildMessage(builder, "Message block warning");
                            ServerHTTP.buildText(builder, "The message, which was sent to " + recipientLocal + " was rejected by manual block.");
                            ServerHTTP.buildText(builder, "If you consider this a mistake, access this URL to request unblock:");
                        }
                        ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                        ServerHTTP.buildFooter(builder, locale);
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making QRcode part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart();
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (senderAdvised = Core.sendMessage(message)) {
                            blockSender(time);
                        }
                        return senderAdvised;
                    }
                } catch (SMTPSendFailedException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }

        private synchronized boolean adviseAdminHOLD(long time) {
            if (adminAdvised) {
                return false;
            } else if (!Core.hasSMTP()) {
                return false;
            } else {
                try {
                    String senderLocal = getSender();
                    String userEmail = getEmail();
                    String unholdURL = Core.getUnholdURL(User.this, time);
                    String blockURL = Core.getBlockURL(User.this, time);
                    if (senderLocal == null) {
                        return false;
                    } else if (unholdURL == null) {
                        return false;
                    } else if (blockURL == null) {
                        return false;
                    } else if (!Domain.isValidEmail(senderLocal)) {
                        return false;
                    } else if (NoReply.contains(userEmail, true)) {
                        return false;
                    } else {
                        Server.logDebug("sending retention warning by e-mail.");
                        Locale locale = Locale.UK;
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (userEmail.endsWith(".br")) {
                                locale = new Locale("pt", "BR");
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else if (userEmail.endsWith(".pt")) {
                                locale = new Locale("pt", "PT");
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String qualifierLocal = getQualifierName();
                        String recipientLocal = getRecipient();
                        String messageidLocal = getMessageID();
                        TreeSet<String> linkSet = getLinkSet();
                        InternetAddress[] recipients = User.this.getInternetAddresses();
                        Properties props = System.getProperties();
                        Session session = Session.getDefaultInstance(props);
                        MimeMessage message = new MimeMessage(session);
                        message.setHeader("Date", Core.getEmailDate());
                        message.setFrom(Core.getAdminInternetAddress());
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(InternetAddress.parse(senderLocal));
                        message.setSubject(subjectLocal);
                        if (messageidLocal != null) {
                            message.setHeader("Message-ID", messageidLocal);
                        }
                        // Corpo da mensagem.
                        StringBuilder builder = new StringBuilder();
                        builder.append("<!DOCTYPE html>\n");
                        builder.append("<html lang=\"");
                        builder.append(locale.getLanguage());
                        builder.append("\">\n");
                        builder.append("  <head>\n");
                        builder.append("    <meta charset=\"UTF-8\">\n");
                        builder.append("    <title>");
                        builder.append(subject);
                        builder.append("</title>\n");
                        ServerHTTP.loadStyleCSS(builder);
                        builder.append("  </head>\n");
                        builder.append("  <body>\n");
                        builder.append("    <div id=\"container\">\n");
                        builder.append("      <div id=\"divlogo\">\n");
                        builder.append("        <img src=\"cid:logo\">\n");
                        builder.append("      </div>\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagem");
                            ServerHTTP.buildText(builder, "Uma mensagem enviada de " + senderLocal + " para "  + recipientLocal + "foi retida por suspeita de SPAM.");
                            if (recipientAdvised) {
                                ServerHTTP.buildText(builder, "O destinatário já foi avisado sobre a retenção, porém ele não liberou a mensagem ainda.");
                            } else if (senderAdvised) {
                                ServerHTTP.buildText(builder, "O remetente já foi avisado sobre a retenção, porém ele não solicitou a liberação da mensagem ainda.");
                            }
                            if (!qualifierLocal.equals("PASS")) {
                                ServerHTTP.buildText(builder, "<b>Atenção! Este remetente não pôde ser autenticado. Isso significa que a mensagem pode ser uma fraude!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>Não é possível determinar com segurança qual servidor disparou esta mensagem.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "A mensagem foi disparada por um servidor no domínio " + hostDomain + ".");
                                }
                            }
                            if (linkSet != null && !linkSet.isEmpty()) {
                                ServerHTTP.buildText(builder, "Os seguintes elementos foram encontrados dentro da mensagem:");
                                builder.append("    <ul>\n");
                                for (String link : linkSet) {
                                    builder.append("    <li>");
                                    if (isLinkBlocked(link)) {
                                        builder.append("<b><font color=\"DarkRed\">");
                                        builder.append(link);
                                        builder.append("</font></b>");
                                    } else {
                                        builder.append(link);
                                    }
                                    builder.append("</li>\n");
                                }
                                builder.append("    </ul>\n");
                            }
                            ServerHTTP.buildText(builder, "Se você considera esta mensagem legítima, acesse esta URL para solicitar a sua liberação:");
                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                            ServerHTTP.buildText(builder, "Se você considera esta mensagem SPAM, acesse esta URL para bloquear o remetente:");
                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                        } else {
                            ServerHTTP.buildMessage(builder, "Message retention warning");
                            ServerHTTP.buildText(builder, "A message sent from " + senderLocal + " to " + recipientLocal + " was retained under suspicion of SPAM.");
                            if (recipientAdvised) {
                                ServerHTTP.buildText(builder, "The recipient has been warned about retention, but he did not release the message yet.");
                            } else if (senderAdvised) {
                                ServerHTTP.buildText(builder, "The sender has already been advised of the retention, but he has not requested to release the message yet.");
                            }
                            if (!qualifierLocal.equals("PASS")) {
                                ServerHTTP.buildText(builder, "<b>Attention! This sender could not be authenticated. That means the message can be a fraud!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "<p>The message was fired by a server in domain " + hostDomain + ".");
                                }
                            }
                            if (linkSet != null && !linkSet.isEmpty()) {
                                ServerHTTP.buildText(builder, "The following elements have been found inside message:");
                                builder.append("    <ul>\n");
                                for (String link : linkSet) {
                                    builder.append("    <li>");
                                    if (isLinkBlocked(link)) {
                                        builder.append("<b><font color=\"DarkRed\">");
                                        builder.append(link);
                                        builder.append("</font></b>");
                                    } else {
                                        builder.append(link);
                                    }
                                    builder.append("</li>\n");
                                }
                                builder.append("    </ul>\n");
                            }
                            ServerHTTP.buildText(builder, "If you consider this message legitimate, access this URL to request its release:");
                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                            ServerHTTP.buildText(builder, "If you consider this SPAM message, access this URL to block the sender:");
                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                        }

                        ServerHTTP.buildFooter(builder, locale);
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making QRcode part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart();
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        return adminAdvised = Core.sendMessage(message);
                    }
                } catch (SMTPSendFailedException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        @Override
        public String toString() {
            return client + ": " + (helo == null ? ip : helo + " [" + ip + "]")
                    + (getSender() == null ? "" : " " + getSender())
                    + " " + getQualifierName() + " > " + recipient + " = " + result;
        }
    }
}
