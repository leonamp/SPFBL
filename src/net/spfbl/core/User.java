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

import com.mysql.jdbc.exceptions.MySQLTimeoutException;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.util.MailConnectException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeUtility;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
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
import org.apache.commons.lang3.LocaleUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/**
 * Representa um usuário do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class User implements Serializable, Comparable<User> {
    
    private static final long serialVersionUID = 1L;

    private final String email;
    private String name;
    private Locale locale;
//    private boolean local = false;
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
        if (Domain.isValidEmail(email) && simplify(name) != null) {
            this.email = email.toLowerCase();
            this.name = simplify(name);
            this.locale = Core.getDefaultLocale(email);
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
    
//    public boolean setLocal(boolean local) {
//        if (this.local == local) {
//            return false;
//        } else {
//            this.local = local;
//            return CHANGED = true;
//        }
//    }
    
    /**
     * Change locale of user.
     * @param token locale pattern.
     * @return true if value was changed.LocaleUtils.toLocale(language);
     */
    public boolean setLocale(String token) {
        if (token == null) {
            return false;
        } else {
            Locale newLocale = LocaleUtils.toLocale(token);
            if (newLocale == null) {
                return false;
            } else if (newLocale.equals(this.locale)) {
                return false;
            } else {
                this.locale = newLocale;
                return CHANGED = true;
            }
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
    
//    public boolean isLocal() {
//        return local;
//    }
    
    public boolean isUsingHeader() {
        return usingHeader;
    }
    
    public boolean isPostmaster() {
        return email.startsWith("postmaster@");
    }
    
    public boolean isAdmin() {
        return Core.isAdminEmail(email);
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
    
    public static Locale getLocale(String address) {
        if (address == null) {
            return null;
        } else {
            address = address.toLowerCase();
            User user = User.get(address);
            if (user == null) {
                int index = address.indexOf('@');
                String postmaster = "postmaster" + address.substring(index);
                user = User.get(postmaster);
            }
            if (user == null) {
                return Core.getDefaultLocale(address);
            } else {
                return user.getLocale();
            }
        }
    }

    public Locale getLocale() {
        return locale;
    }
    
    private Date getDate(String text) {
        if (text == null) {
            return null;
        } else if (text.length() == 0) {
            return null;
        } else {
            try {
                return DateFormat.getDateInstance(DateFormat.SHORT, locale).parse(text);
            } catch (ParseException ex) {
                return null;
            }
        }
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
        if (queryMap == null) {
            return false;
        } else {
            return queryMap.remove(time) != null;
        }
    }
    
    public synchronized Set<Long> headSet(long threshold) {
        if (queryMap == null) {
            return new TreeSet<>();
        } else {
            TreeSet<Long> set = new TreeSet<>();
            set.addAll(queryMap.headMap(threshold).keySet());
            return set;
        }
    }
    
    private void dropExpiredQuery() {
        long threshold = System.currentTimeMillis() - 604800000;
        for (long time : headSet(threshold)) {
            Query query = getQuery(time);
            if (query != null) {
                query.setResult("GREYLIST", "REJECT");
                query.setResult("LISTED", "REJECT");
                query.setResult("HOLD", "REJECT");
                storeDB(time, query);
            }
            if (dropQuery(time)) {
                CHANGED = true;
            }
        }
    }
    
    private static final int QUERY_MAX = 1024;
    
    private synchronized void hairCutQuery() {
        if (queryMap != null && queryMap.size() > QUERY_MAX) {
            Long time = 0L;
            Query query;
            do {
                if ((time = queryMap.higherKey(time)) == null) {
                    break;
                } else if ((query = queryMap.get(time)) != null && query.isFinished()) {
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
    private static final HashMap<String,User> MAP = new HashMap<>();
    
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
        TreeSet<User> userSet = new TreeSet<>();
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
        TreeSet<User> userSet = new TreeSet<>();
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
        HashMap<String,User> map = new HashMap<>();
        map.putAll(MAP);
        return map;
    }
    
    protected static boolean autoUpdateKeys() {
        Connection connection = Core.aquireConnectionMySQL();
        if (connection == null) {
            return false;
        } else {
            try {
                long begin1 = System.currentTimeMillis();
                String command = "SELECT * FROM user_query\n"
                        + "WHERE whiteKey IS NULL OR blockKey IS NULL\n"
                        + "LIMIT 100000";
                try {
                    PreparedStatement prepareStatement = connection.prepareStatement(
                            "UPDATE user_query\n"
                                    + "SET whiteKey = ?, blockKey = ?\n"
                                    + "WHERE time = ?"
                    );
                    Statement statement = connection.createStatement();
                    statement.setQueryTimeout(60);
                    ResultSet rs = statement.executeQuery(command);
                    while (rs.next()) {
                        long time = rs.getLong("time");
                        User user = User.get(rs.getString("user"));
                        if (user != null) {
                            long begin2 = System.currentTimeMillis();
                            try {
                                Query query = user.getQuery(rs);
                                prepareStatement.setString(1, query.getWhiteKey());
                                prepareStatement.setString(2, query.getBlockKey());
                                prepareStatement.setLong(3, time);
                                prepareStatement.setQueryTimeout(60);
                                prepareStatement.executeUpdate();
                            } catch (MySQLTimeoutException ex) {
                                Server.logMySQL(begin2, prepareStatement, ex);
                            }
                        }
                    }
                    return true;
                } catch (MySQLTimeoutException ex) {
                    Server.logMySQL(begin1, command, ex);
                    return false;
                } catch (SQLException ex) {
                    Server.logError(ex);
                    return false;
                }
            } finally {
                Core.releaseConnectionMySQL();
            }
        }
    }
    
//    protected static boolean autoUpdateDates() {
//        Connection connection = Core.aquireConnectionMySQL();
//        try {
//            if (connection == null) {
//                return false;
//            } else {
//                try {
//                    Statement statement = connection.createStatement();
//                    statement.executeUpdate(
//                            "UPDATE user_query\n"
//                                    + "SET date = FROM_UNIXTIME(time DIV 1000)\n"
//                                    + "WHERE date IS NULL\n"
//                                    + "LIMIT 100000"
//                    );
//                    return true;
//                } catch (SQLException ex) {
//                    Server.logError(ex);
//                    return false;
//                }
//            }
//        } finally {
//            Core.releaseConnectionMySQL(connection);
//        }
//    }
    
    private static TreeMap<Long,User> getWhiteInductionMap() {
        Connection connection = Core.aquireConnectionMySQL();
        if (connection == null) {
            return null;
        } else {
            try {
                long begin = System.currentTimeMillis();
                String command = "SELECT MAX(time) AS time, user\n"
                        + "FROM user_query\n"
                        + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 3456000) * 1000)\n"
                        + "GROUP BY user, whiteKey\n"
                        + "HAVING MAX(result * 1) = 2\n"
                        + "AND COUNT(*) > 32\n"
                        + "AND STD(time) / 86400000 > 7";
                try {
                    TreeMap<Long,User> whiteMap = new TreeMap<>();
                    Statement statement = connection.createStatement();
                    statement.setQueryTimeout(600);
                    ResultSet rs = statement.executeQuery(command);
                    while (rs.next()) {
                        long time = rs.getLong(1);
                        User user = User.get(rs.getString(2));
                        if (user != null) {
                            whiteMap.put(time, user);
                        }
                    }
                    return whiteMap;
                } catch (MySQLTimeoutException ex) {
                    Server.logMySQL(begin, command, ex);
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            } finally {
                Core.releaseConnectionMySQL();
            }
        }
    }
    
    protected static void autoInductionWhite() {
        Server.logTrace("starting auto white.");
        TreeMap<Long,User> whiteMap = getWhiteInductionMap();
        if (whiteMap != null) {
            for (long time : whiteMap.keySet()) {
                User user = whiteMap.get(time);
                Query query = user.getQuerySafe(time);
                if (query != null && !query.isBlockKey() && query.whiteKey(time)) {
                    Server.logDebug("new WHITE '" + query.getUserEmail() + ":" + query.getWhiteKey() + "' added by 'RECURRENCE'.");
                }
            }
        }
    }
    
    private static TreeMap<Long,User> getBlockInductionMap() {
        Connection connection = Core.aquireConnectionMySQL();
        if (connection == null) {
            return null;
        } else {
            try {
                long begin = System.currentTimeMillis();
                String command = "SELECT MAX(time) AS time, user\n"
                        + "FROM user_query\n"
                        + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 3456000) * 1000)\n"
                        + "GROUP BY user, blockKey\n"
                        + "HAVING MIN(result * 1) BETWEEN 3 AND 12\n"
                        + "AND MAX(result * 1) > 6\n"
                        + "AND COUNT(*) > 32\n"
                        + "AND STD(time) / 86400000 > 7";
                try {
                    TreeMap<Long,User> blockMap = new TreeMap<>();
                    Statement statement = connection.createStatement();
                    statement.setQueryTimeout(600);
                    ResultSet rs = statement.executeQuery(command);
                    while (rs.next()) {
                        long time = rs.getLong(1);
                        User user = User.get(rs.getString(2));
                        if (user != null) {
                            blockMap.put(time, user);
                        }
                    }
                    return blockMap;
                } catch (MySQLTimeoutException ex) {
                    Server.logMySQL(begin, command, ex);
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            } finally {
                Core.releaseConnectionMySQL();
            }
        }
   }
    
    protected static void autoInductionBlock() {
        Server.logTrace("starting auto block.");
        TreeMap<Long,User> blockMap = getBlockInductionMap();
        if (blockMap != null) {
            for (long time : blockMap.keySet()) {
                User user = blockMap.get(time);
                Query query = user.getQuerySafe(time);
                if (query != null && !query.isWhiteKey() && query.blockKey(time)) {
                    Server.logDebug("new BLOCK '" + query.getUserEmail() + ":" + query.getBlockKey() + "' added by 'RECURRENCE'.");
                }
            }
        }
    }
    
    public synchronized static void store() {
        if (CHANGED) {
            try {
                storeDB();
                long time = System.currentTimeMillis();
                HashMap<String,User> map = getMap();
                File file = new File("./data/user.map");
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
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
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof User) {
                        User user = (User) value;
                        if (user.locale == null) {
                            user.locale = Core.getDefaultLocale(user.email);
                        }
                        for (long time2 : user.getTimeSet()) {
                            Query query = user.getQuery(time2);
                            if (query.date != null && Math.abs(time2 - query.date.getTime()) > 31104000000L) {
                                query.date = null;
                            }
                            if (query.CHANGED == null) {
                                query.CHANGED = new BinarySemaphore(!query.STORED);
                            } else if (query.CHANGED.acquireIf(true)) {
                                query.CHANGED.release(true);
                            } else if (query.CHANGED.acquireIf(false)) {
                                query.CHANGED.release(false);
                            } else {
                                query.CHANGED.release(true);
                            }
                        }
                        MAP.put(key, user);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static void clearFalseBlock() {
        for (User user : User.getSet()) {
            for (long time : user.getTimeSet()) {
                User.Query query = user.getQuery(time);
                if (query != null && query.isWhite()) {
                    query.clearBlock();
                }
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
        if (locale == null) {
            return name + " <" + email + ">";
        } else {
            return name + " <" + email + "> " + locale;
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
            storeDB(time, query);
            return query;
        } catch (ProcessException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static final int QUERY_MAX_ROWS = 512;
    
    public TreeMap<Long,Query> getQueryMap(
            Long begin, String filter
    ) {
        TreeMap<Long,Query> queryLocalMap;
        if (isAdmin()) {
            queryLocalMap = getAllQueryHeadMap(begin);
        } else {
            queryLocalMap = getQueryHeadMap(begin);
        }
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        while (resultMap.size() < (QUERY_MAX_ROWS + 1)) {
            Entry<Long,Query> entry = queryLocalMap.pollLastEntry();
            if (entry == null) {
                break;
            } else {
                long time = entry.getKey();
                Query query = entry.getValue();
                if (filter == null) {
                    resultMap.put(time, query);
                } else if (filter.length() == 0) {
                    resultMap.put(time, query);
                } else if (query.matchAll(time, filter)) {
                    resultMap.put(time, query);
                }
            }
        }
        if (Core.hasMySQL() && resultMap.size() < (QUERY_MAX_ROWS + 1)) {
            Date date = null;
            String ipParam = null;
            String emailParam = null;
            String domainParam = null;
            boolean rejectedParam = false;
            boolean holdParam = false;
            if (filter != null) {
                filter = filter.toLowerCase();
                StringTokenizer tokenizer = new StringTokenizer(filter, ",");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    token = token.trim();
                    date = getDate(token);
                    ipParam = Subnet.isValidIP(token) ? Subnet.normalizeIP(token) : ipParam;
                    emailParam = Domain.isValidEmail(token) ? token : emailParam;
                    domainParam = Domain.hasTLD(token) ? Domain.normalizeHostname(token, true) : domainParam;
                    switch (token) {
                        case "rejeitada": case "rejeitado": case "rejected":
                        case "rejeitadas": case "rejeitados": case "rejecteds":
                            rejectedParam = true;
                            break;
                        case "retida": case "retido": case "hold":
                        case "retidas": case "retidos": case "holds":
                            holdParam = true;
                            break;
                    }
                }
            }
            if (!holdParam) {
                long end;
                if (begin == null) {
                    if (date == null) {
                        end = System.currentTimeMillis() - 3456000000L;
                    } else {
                        begin = date.getTime() + 86399999;
                        end = date.getTime();
                    }
                } else {
                    end = begin - 3456000000L;
                }
                String command = "SELECT * FROM user_query\n"
                        + (begin == null ? "WHERE time > " + end + "\n"
                        : "WHERE time BETWEEN " + end + " AND " + begin + "\n")
                        + (isAdmin() ? "" : "AND user = '" + getEmail() + "'\n")
                        + (rejectedParam ? "AND result IN('BLOCK','REJECT')\n" : "")
                        + (ipParam == null ? "" : "AND ip = '" + ipParam + "'\n")
                        + (emailParam == null ? "" : ""
                        + "AND (sender = '" + emailParam + "' "
                        + "OR mailFrom = '" + emailParam + "' "
                        + "OR replyto = '" + emailParam + "' "
                        + "OR recipient = '" + emailParam + "')\n")
                        + (domainParam == null ? "" : ""
                        + "AND (helo = '" + domainParam.substring(1) + "' "
                        + "OR hostname = '" + domainParam.substring(1) + "' "
                        + "OR sender LIKE '%@" + domainParam.substring(1) + "' "
                        + "OR mailFrom LIKE '%@" + domainParam.substring(1) + "' "
                        + "OR replyto LIKE '%@" + domainParam.substring(1) + "' "
                        + "OR recipient LIKE '%@" + domainParam.substring(1) + "' "
                        + "OR helo LIKE '%" + domainParam + "' "
                        + "OR hostname LIKE '%" + domainParam + "' "
                        + "OR sender LIKE '%" + domainParam + "' "
                        + "OR mailFrom LIKE '%" + domainParam + "' "
                        + "OR replyto LIKE '%" + domainParam + "' "
                        + "OR recipient LIKE '%" + domainParam + "'"
                        + ")\n")
                        + "ORDER BY time DESC\n"
                        + "LIMIT " + (QUERY_MAX_ROWS + 1);
                try {
                    Connection connection = Core.newConnectionMySQL();
                    if (connection != null) {
                        try {
                            long beginTime = System.currentTimeMillis();
                            try (Statement statement = connection.createStatement()) {
                                statement.setQueryTimeout(60);
                                ResultSet rs = statement.executeQuery(command);
                                while (rs.next()) {
                                    try {
                                        long time = rs.getLong("time");
                                        Query query = resultMap.get(time);
                                        if (query == null) {
                                            query = new Query(rs);
                                            resultMap.put(time, query);
                                        }
                                    } catch (Exception ex) {
                                        Server.logError(ex);
                                    }
                                }
                            } catch (MySQLTimeoutException ex) {
                                Server.logMySQL(beginTime, command, ex);
                            } catch (SQLException ex) {
                                Server.logError(ex);
                            }
                        } finally {
                            connection.close();
                        }
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        return resultMap;
    }
    
    public void setResult(long time, String result) {
        if (result != null) {
            Query query = getQuerySafe(time);
            if (query != null && query.setResult(result)) {
                storeDB(time, query);
            }
        }
    }
    
    public static Entry<Long,Query> getQueryEntry(String ticket) {
        try {
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray.length > 8) {
                long date = byteArray[7] & 0xFF;
                date <<= 8;
                date += byteArray[6] & 0xFF;
                date <<= 8;
                date += byteArray[5] & 0xFF;
                date <<= 8;
                date += byteArray[4] & 0xFF;
                date <<= 8;
                date += byteArray[3] & 0xFF;
                date <<= 8;
                date += byteArray[2] & 0xFF;
                date <<= 8;
                date += byteArray[1] & 0xFF;
                date <<= 8;
                date += byteArray[0] & 0xFF;
                if (System.currentTimeMillis() - date > 432000000) {
                    return null;
                } else {
                    ticket = Core.decodeHuffman(byteArray, 8);
                    StringTokenizer tokenizer = new StringTokenizer(ticket, " ");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        if (token.endsWith(":")) {
                            int endIndex = token.length() - 1;
                            token = token.substring(0, endIndex);
                            if (Domain.isValidEmail(token)) {
                                User user = User.get(token);
                                if (user == null) {
                                    return null;
                                } else {
                                    Query query = user.getQuery(date);
                                    if (query == null) {
                                        return null;
                                    } else {
                                        return new AbstractMap.SimpleEntry<>(date, query);
                                    }
                                }
                            }
                        }
                    }
                    return null;
                }
            } else {
                return null;
            }
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    private Query getQuery(ResultSet rs) throws SQLException {
        return new Query(rs);
    }
    
    public Query getQuerySafe(long time) {
        Query query = getQuery(time);
        if (query == null && Core.hasMySQL()) {
            long time2 = System.currentTimeMillis();
            String command = "SELECT * FROM user_query\n"
                    + "WHERE time = " + time
                    + (isAdmin() ? "" : "\nAND user = '" + getEmail() + "'");
            Connection connection = Core.aquireConnectionMySQL();
            if (connection != null) {
                try {
                    try (Statement statement = connection.createStatement()) {
                        statement.setQueryTimeout(3);
                        ResultSet rs = statement.executeQuery(command);
                        if (rs.next()) {
                            query = new Query(rs);
                            Server.logMySQL(time2, command, "FOUND");
                        } else {
                            Server.logMySQL(time2, command, "NOT FOUND");
                        }
                    } catch (SQLException ex) {
                        Server.logMySQL(time2, command, ex);
                    }
                } finally {
                    Core.releaseConnectionMySQL();
                }
            }
        }
        return query;
    }
    
    public Object[] getDeferedQuery(
            String ip,
            String hostname,
            String sender,
            String recipient,
            String newResult
    ) {
        ip = Subnet.normalizeIP(ip);
        hostname = Domain.normalizeHostname(hostname, false);
        long deferTimeRED = Core.getDeferTimeRED() * 60000L;
        long timeBegin = System.currentTimeMillis() - deferTimeRED;
        for (long time : getTimeTail(timeBegin).descendingSet()) {
            User.Query query = getQuery(time);
            if (query != null) {
                String oldResult = query.getResult();
                if (oldResult.equals("GREYLIST") || oldResult.equals("LISTED")) {
                    if (query.isOrigin(ip, hostname) && query.isMailFromTo(sender, recipient)) {
                        if (query.setResult(oldResult, newResult)) {
                            Object[] resultSet = new Object[2];
                            resultSet[0] = time;
                            resultSet[1] = query;
                            storeDB(time, query);
                            return resultSet;
                        }
                    }
                }
            }
        }
        return null;
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
            return new TreeSet<>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<>();
            timeSet.addAll(queryMap.keySet());
            return timeSet;
        }
    }
    
    public synchronized TreeSet<Long> getTimeSet(long begin, long end) {
        if (queryMap == null) {
            return new TreeSet<>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<>();
            timeSet.addAll(queryMap.subMap(begin, end).keySet());
            return timeSet;
        }
    }
    
    public synchronized TreeSet<Long> getTimeTail(long from) {
        if (queryMap == null) {
            return new TreeSet<>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<>();
            timeSet.addAll(queryMap.tailMap(from).keySet());
            return timeSet;
        }
    }
    
    public synchronized TreeSet<Long> getTimeHead(long from) {
        if (queryMap == null) {
            return new TreeSet<>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<>();
            timeSet.addAll(queryMap.headMap(from).keySet());
            return timeSet;
        }
    }
    
    public static TreeMap<Long,Query> getAllQueryHeadMap(Long begin) {
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        for (User user : User.getSet()) {
            resultMap.putAll(user.getQueryHeadMap(begin));
        }
        return resultMap;
    }
    
    public synchronized TreeMap<Long,Query> getQueryHeadMap(Long begin) {
        if (queryMap == null) {
            return new TreeMap<>();
        } else if (begin == null) {
            TreeMap<Long,Query> resultMap = new TreeMap<>();
            resultMap.putAll(queryMap);
            return resultMap;
        } else {
            TreeMap<Long,Query> resultMap = new TreeMap<>();
            resultMap.putAll(queryMap.headMap(begin));
            return resultMap;
        }
    }
    
    private synchronized void putQuery(long time, Query query) {
        if (queryMap == null) {
            queryMap = new TreeMap<>();
        }
        queryMap.put(time, query);
        CHANGED = true;
    }
    
    public String blockByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuerySafe(time);
                if (query != null && query.isMessage(messageID)) {
                    if (query.isWhiteKey() && query.isGreen()) {
                        if (query.complain(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.hasTokenRed()) {
                        if (query.blockKey(time)) {
                            return "BLOCKED " + query.getBlockKey();
                        } else {
                            return "ALREADY BLOCKED";
                        }
                    } else if (query.blockForRecipient(time)) {
                        return "BLOCKED " + query.getBlockKey() + ">" + query.getRecipient();
                    } else {
                        return "ALREADY BLOCKED";
                    }
                }
            }
            return "MESSAGE NOT FOUND";
        }
    }
    
    public static String whiteAllByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            for (User user : User.getSet()) {
                String result = user.whiteByMessageID(messageID);
                if (!result.equals("NOT FOUND")) {
                    return result;
                }
            }
            return "NOT FOUND";
        }
    }
    
    public String whiteByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuerySafe(time);
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
    
    private static String normalizeLink(String token) {
        if (token == null) {
            return null;
        } else if (Subnet.isValidIP(token)) {
            return Subnet.normalizeIP(token);
        } else if (Domain.isValidEmail(token)) {
            return token.toLowerCase();
        } else if (Domain.isOfficialTLD(token)) {
            return null;
        } else if (Domain.isHostname(token)) {
            return Domain.normalizeHostname(token, false);
        } else {
            return null;
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
        MALWARE,
        ALL
        
    }
    
    public static boolean isExpiredHOLD(long time) {
        long expireTime = Core.getDeferTimeHOLD() * 60000L;
        long thresholdTime = System.currentTimeMillis() - expireTime;
        return time < thresholdTime;
    }
    
    public static void sendHoldingWarning() {
//        Server.logTrace("sendHoldingWarning started.");
        for (User user : getSet()) {
            if (user.isUsingHeader()) {
                TreeSet<String> whiteKeySet = new TreeSet<>();
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long deferTimeHOLD = Core.getDeferTimeHOLD() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeUser = System.currentTimeMillis() - deferTimeRED;
                long timeBegin = System.currentTimeMillis() - deferTimeHOLD;
                for (long time : user.getTimeSet(timeBegin, timeEnd)) {
                    Query query = user.getQuery(time);
                    if (query != null && query.isNotAdvisedAdmin() && query.isHoldingFull()) {
                        
                        
//                        if (time < timeUser && query.adviseUserHOLD(time)) {
////                            Server.logTrace("adviseUserHOLD sent.");
//                        } else if (query.adviseSenderHOLD(time)) {
////                            Server.logTrace("adviseSenderHOLD sent.");
//                        } else if (query.adviseAdminHOLD(time)) {
////                            Server.logTrace("adviseAdminHOLD sent.");
//                        }
                        
                        if (time < timeUser) {
                            String whiteKey = query.getWhiteKey();
                            if (!whiteKeySet.contains(whiteKey)) {
                                if (query.adviseUserHOLD(time)) {
                                    whiteKeySet.add(whiteKey);
                                }
                            }
                        } else if (!query.adviseSenderHOLD(time)) {
                            query.adviseAdminHOLD(time);
                        }
                        
                    }
                }
            }
        }
//        Server.logTrace("sendHoldingWarning finished.");
    }
    
    public static void sendWarningMessages() {
        for (User user : getSet()) {
            long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
            long deferTimeRED = Core.getDeferTimeRED() * 60000L;
            long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
            long timeBegin = System.currentTimeMillis() - deferTimeRED;
            for (long time : user.getTimeSet(timeBegin, timeEnd)) {
                Query query = user.getQuery(time);
                if (query != null) {
                    boolean drop = Core.hasMySQL();
                    if (query.isResult("HOLD")) {
                        drop = false;
                    } else if (query.isResult("GREYLIST")) {
                        drop = false;
                    } else if (query.isResult("LISTED")) {
                        drop = false;
                    } else if (query.isResult("ACCEPT")) {
                        if (query.hasSubject()) {
                            drop = false;
                            if (query.isSuspectFull() && query.adviseRecipientSPAM(time)) {
                                Server.logDebug("suspect warning sent by e-mail.");
                            }
                        }
                    } else if (query.isResult("BLOCK")) {
                        if (query.adviseSenderBLOCK(time)) {
                            Server.logDebug("reject warning sent by e-mail.");
                        }
                    }
                    if (drop) {
                        // Drop from memory because 
                        // it was stored in MySQL.
                        user.dropQuery(time);
                    }
                }
            }
        }
    }
    
    public static void storeAndDropFinished() {
        if (Core.hasMySQL()) {
            for (User user : getSet()) {
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long timeBegin = System.currentTimeMillis() - deferTimeRED;
                for (long time : user.getTimeHead(timeBegin)) {
                    Query query = user.getQuery(time);
                    if (query != null) {
                        boolean store = true;
                        if (query.isResult("HOLD")) {
                            store = false;
                        } else if (query.isResult("LISTED")) {
                            store = query.setResult("LISTED", "REJECT");
                        } else if (query.isResult("GREYLIST")) {
                            store = query.setResult("GREYLIST", "REJECT");
                        }
                        if (store && query.storeDB(time)) {
                            // Drop from memory because 
                            // it was stored in MySQL.
                            user.dropQuery(time);
                        }
                    }
                }
            }
        }
    }
    
    public boolean sendTOTP() {
        if (!Core.hasOutputSMTP()) {
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
    
    private static final String MYSQL_STORE_COMMAND_2_7_6 =
            "INSERT INTO user_query "
            + "(time, user, client, ip, helo, hostname, "
            + "sender, qualifier, recipient, tokenSet, "
            + "complainKey, whiteKey, blockKey, "
            + "result, mailFrom, replyto, subject, "
            + "messageID, unsubscribe, linkMap, malware, "
            + "adminAdvised, senderAdvised, recipientAdvised)\n"
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE "
            + "whiteKey = ?, blockKey = ?, "
            + "result = ?, mailFrom = ?, "
            + "replyto = ?, subject = ?, messageID = ?, "
            + "unsubscribe = ?, linkMap = ?, malware = ?, "
            + "adminAdvised = ?, senderAdvised = ?, "
            + "recipientAdvised = ?";
    
    private static final String MYSQL_STORE_COMMAND_2_8_0 =
            "INSERT INTO user_query "
            + "(time, user, client, ip, helo, hostname, "
            + "sender, qualifier, recipient, tokenSet, "
            + "complainKey, whiteKey, blockKey, "
            + "result, mailFrom, replyto, subject, "
            + "messageID, date, unsubscribe, linkMap, malware, body, "
            + "adminAdvised, senderAdvised, recipientAdvised)\n"
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE "
            + "whiteKey = ?, blockKey = ?, "
            + "result = ?, mailFrom = ?, "
            + "replyto = ?, subject = ?, messageID = ?, "
            + "date = ?, unsubscribe = ?, "
            + "linkMap = ?, malware = ?, body = ?, "
            + "adminAdvised = ?, senderAdvised = ?, "
            + "recipientAdvised = ?";
    
    private static void storeDB() {
        try {
            long time2 = System.currentTimeMillis();
            Connection connection = Core.aquireConnectionMySQL();
            if (connection != null) {
                try {
                    try {
                        PreparedStatement statement
                                = connection.prepareStatement(
                                        MYSQL_STORE_COMMAND_2_8_0
                                );
                        try {
                            statement.setQueryTimeout(60);
                            connection.setAutoCommit(true);
                            for (User user : getSet()) {
                                for (long time : user.getTimeSet()) {
                                    Query query = user.getQuery(time);
                                    if (query != null) {
                                        query.storeDB_2_8_0(statement, time);
                                    }
                                }
                            }
                            Server.logMySQL(time2, "user_query stored");
                        } finally {
                            connection.setAutoCommit(false);
                            statement.close();
                        }
                    } catch (SQLException ex) {
                        PreparedStatement statement
                                = connection.prepareStatement(
                                        MYSQL_STORE_COMMAND_2_7_6
                                );
                        try {
                            connection.setAutoCommit(true);
                            for (User user : getSet()) {
                                for (long time : user.getTimeSet()) {
                                    Query query = user.getQuery(time);
                                    if (query != null) {
                                        query.storeDB_2_7_6(statement, time);
                                    }
                                }
                            }
                            Server.logMySQL(time2, "user_query stored");
                        } finally {
                            connection.setAutoCommit(false);
                            statement.close();
                        }
                    }
                } finally {
                    Core.releaseConnectionMySQL();
                }
            }
        } catch (SQLException ex) {
            Server.logError(ex);
        }
    }
    
    private static StoreThread STORE_THREAD = null;
    
    private static synchronized StoreThread getStoreThread() {
        if (Core.hasMySQL()) {
            if (STORE_THREAD == null) {
                STORE_THREAD = new StoreThread();
                STORE_THREAD.start();
            }
            return STORE_THREAD;
        } else {
            return null;
        }
    }
    
    public static void storeDB(long time, Query query) {
        StoreThread storeThread = getStoreThread();
        if (storeThread != null) {
            storeThread.put(time, query);
        }
    }
    
    protected static synchronized void interrupt() {
        if (STORE_THREAD != null) {
            STORE_THREAD.interrupt();
        }
    }
    
    private static class StoreThread extends Thread {
        
        private final TreeMap<Long,Query> QUEUE = new TreeMap<>();
        private boolean run = true;
        
        private synchronized Entry<Long,Query> pollFirstEntry() {
            return QUEUE.pollFirstEntry();
        }
        
        private synchronized Query put(long time, Query query) {
            if (query == null) {
                return null;
            } else {
                return QUEUE.put(time, query);
            }
        }
        
        private boolean continueRun() {
            return run;
        }
        
        @Override
        public void interrupt() {
            run = false;
        }
        
        @Override
        public void run() {
            try {
                Thread.currentThread().setName("USRTHREAD");
                Entry<Long, Query> entry;
                while (continueRun()) {
                    try {
                        while ((entry = pollFirstEntry()) != null) {
//                            Server.logTrace("pollFirstEntry()");
                            Query query = entry.getValue();
                            long time = entry.getKey();
//                            Server.logTrace("waitHeader()");
                            query.waitHeader();
//                            Server.logTrace("aquireConnectionMySQL()");
                            Connection connection = Core.aquireConnectionMySQL();
                            if (connection == null) {
//                                Server.logTrace("put(time, query)");
                                put(time, query);
                            } else {
                                try {
                                    try {
                                        PreparedStatement statement
                                                = connection.prepareStatement(
                                                        MYSQL_STORE_COMMAND_2_8_0
                                                );
                                        statement.setQueryTimeout(60);
//                                        Server.logTrace("storeDB_2_8_0(statement, time)");
                                        query.storeDB_2_8_0(statement, time);
                                    } catch (SQLException ex) {
                                        Server.logError(ex);
                                        try {
                                            PreparedStatement statement
                                                    = connection.prepareStatement(
                                                            MYSQL_STORE_COMMAND_2_7_6
                                                    );
//                                            Server.logTrace("storeDB_2_7_6(statement, time)");
                                            query.storeDB_2_7_6(statement, time);
                                        } catch (SQLException ex2) {
                                            Server.logError(ex2);
                                        }
                                    }
                                } finally {
//                                    Server.logTrace("releaseConnectionMySQL()");
                                    Core.releaseConnectionMySQL();
                                }
                            }
                        }
//                        Server.logTrace("sleep(1000)");
                        Thread.sleep(1000);
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
            } finally {
                Server.logTrace("thread closed.");
            }
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
        private final TreeSet<String> tokenSet = new TreeSet<>();
        private String result;
        private String from = null;
        private String replyto = null;
        private String subject = null;
        private String messageID = null;
        private Timestamp date = null;
        private URL unsubscribe = null;
        private TreeMap<String,Boolean> linkMap = null;
        private String malware = null;
        private byte[] body = null;
        
        private boolean adminAdvised = false;
        private boolean senderAdvised = false;
        private boolean recipientAdvised = false;
        
        private boolean STORED = false; // Obsoleto.
        private BinarySemaphore CHANGED; // Mudar para final depois da transição.
        
        private Query(ResultSet rs) throws SQLException {
            this.client = rs.getString("client");
            this.ip = rs.getString("ip");
            this.helo = rs.getString("helo");
            this.hostname = rs.getString("hostname");
            this.sender = rs.getString("sender");
            this.qualifier = SPF.Qualifier.get(rs.getString("qualifier"));
            this.recipient = rs.getString("recipient");
            this.loadTokenSet(rs.getString("tokenSet"));
            this.result = rs.getString("result");
            this.from = rs.getString("mailFrom");
            this.replyto = rs.getString("replyto");
            this.subject = rs.getString("subject");
            this.messageID = rs.getString("messageID");
            this.date = rs.getTimestamp("date");
            this.unsubscribe = Core.getURL(rs.getString("unsubscribe"));
            this.loadLinkMap(rs.getString("linkMap"));
            this.malware = rs.getString("malware");
            this.body = rs.getBytes("body");
            this.adminAdvised = rs.getBoolean("adminAdvised");
            this.senderAdvised = rs.getBoolean("senderAdvised");
            this.recipientAdvised = rs.getBoolean("recipientAdvised");
            this.STORED = true;
            this.CHANGED = new BinarySemaphore(false);
        }
        
        private boolean loadTokenSet(String text) {
            TreeSet<String> set = Core.getTreeSet(text, ";");
            if (set == null) {
                return false;
            } else {
                tokenSet.addAll(set);
                return true;
            }
        }
        
        private boolean loadLinkMap(String text) {
            TreeMap<String,Boolean> map = Core.getTreeMapBoolean(text, ";");
            if (map == null) {
                return false;
            } else if(linkMap == null) {
                linkMap = map;
                return true;
            } else {
                linkMap.putAll(map);
                return true;
            }
        }
        
        private boolean storeDB(long time) {
            try {
                Connection connection = Core.aquireConnectionMySQL();
                if (connection == null) {
                    return false;
                } else {
                    try {
                        try {
                            PreparedStatement statement
                                    = connection.prepareStatement(
                                            MYSQL_STORE_COMMAND_2_8_0
                                    );
                            try {
                                statement.setQueryTimeout(60);
                                connection.setAutoCommit(true);
                                return storeDB_2_8_0(statement, time);
                            } finally {
                                connection.setAutoCommit(false);
                                statement.close();
                            }
                        } catch (SQLException ex) {
                            PreparedStatement statement
                                    = connection.prepareStatement(
                                            MYSQL_STORE_COMMAND_2_7_6
                                    );
                            try {
                                connection.setAutoCommit(true);
                                return storeDB_2_7_6(statement, time);
                            } finally {
                                connection.setAutoCommit(false);
                                statement.close();
                            }
                        }
                    } finally {
                        Core.releaseConnectionMySQL();
                    }
                }
            } catch (SQLException ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        private boolean storeDB_2_7_6(PreparedStatement statement, long time) {
            if (this.CHANGED.acquireIf(true)) {
                long start = System.currentTimeMillis();
                try {
                    String whiteKey = getWhiteKey();
                    String blockKey = getBlockKey();
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
                    statement.setString(12, whiteKey);
                    statement.setString(13, blockKey);
                    statement.setString(14, result);
                    statement.setString(15, from);
                    statement.setString(16, replyto);
                    statement.setString(17, subject);
                    statement.setString(18, messageID);
                    statement.setString(19, getUnsubscribeString());
                    statement.setString(20, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(21, malware);
                    statement.setBoolean(22, adminAdvised);
                    statement.setBoolean(23, senderAdvised);
                    statement.setBoolean(24, recipientAdvised);
                    statement.setString(25, whiteKey);
                    statement.setString(26, blockKey);
                    statement.setString(27, result);
                    statement.setString(28, from);
                    statement.setString(29, replyto);
                    statement.setString(30, subject);
                    statement.setString(31, messageID);
                    statement.setString(32, getUnsubscribeString());
                    statement.setString(33, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(34, malware);
                    statement.setBoolean(35, adminAdvised);
                    statement.setBoolean(36, senderAdvised);
                    statement.setBoolean(37, recipientAdvised);
                    statement.setQueryTimeout(60);
                    int update = statement.executeUpdate();
                    this.STORED = true;
                    this.CHANGED.release(false);
                    User.CHANGED = true;
                    if (update == 0) {
                        Server.logMySQL(start, statement, "NOT UPDATED");
                    } else {
                        Server.logMySQL(start, statement, "UPDATED");
                    }
                    return true;
                } catch (SQLException ex) {
                    this.STORED = false;
                    this.CHANGED.release(true);
                    Server.logMySQL(start, statement, ex);
                    return false;
                } catch (Exception ex) {
                    this.STORED = false;
                    this.CHANGED.release(true);
                    Server.logError(ex);
                    return false;
                }
            } else {
                return true;
            }
        }
        
        private boolean storeDB_2_8_0(PreparedStatement statement, long time) {
            if (this.CHANGED.acquireIf(true)) {
                long start = System.currentTimeMillis();
                try {
                    String whiteKey = getWhiteKey();
                    String blockKey = getBlockKey();
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
                    statement.setString(12, whiteKey);
                    statement.setString(13, blockKey);
                    statement.setString(14, result);
                    statement.setString(15, from);
                    statement.setString(16, replyto);
                    statement.setString(17, subject);
                    statement.setString(18, messageID);
                    statement.setTimestamp(19, date);
                    statement.setString(20, getUnsubscribeString());
                    statement.setString(21, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(22, malware);
                    statement.setBytes(23, body);
                    statement.setBoolean(24, adminAdvised);
                    statement.setBoolean(25, senderAdvised);
                    statement.setBoolean(26, recipientAdvised);
                    statement.setString(27, whiteKey);
                    statement.setString(28, blockKey);
                    statement.setString(29, result);
                    statement.setString(30, from);
                    statement.setString(31, replyto);
                    statement.setString(32, subject);
                    statement.setString(33, messageID);
                    statement.setTimestamp(34, date);
                    statement.setString(35, getUnsubscribeString());
                    statement.setString(36, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(37, malware);
                    statement.setBytes(38, body);
                    statement.setBoolean(39, adminAdvised);
                    statement.setBoolean(40, senderAdvised);
                    statement.setBoolean(41, recipientAdvised);
                    statement.setQueryTimeout(60);
                    int update = statement.executeUpdate();
                    this.STORED = true;
                    this.CHANGED.release(false);
                    User.CHANGED = true;
                    if (update == 0) {
                        Server.logMySQL(start, statement, "NOT UPDATED");
                    } else {
                        Server.logMySQL(start, statement, "UPDATED");
                    }
                    return true;
                } catch (SQLException ex) {
                    this.STORED = false;
                    this.CHANGED.release(true);
                    Server.logMySQL(start, statement, ex);
                    return false;
                } catch (Exception ex) {
                    this.STORED = false;
                    this.CHANGED.release(true);
                    Server.logError(ex);
                    return false;
                }
            } else {
                return true;
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
            } else if (recipient != null && !Domain.isValidEmail(recipient)) {
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
               this.CHANGED = new BinarySemaphore(true);
               User.CHANGED = true;
            }
        }
        
        public String getClient() {
            return client;
        }
        
        public TreeSet<String> getClientEmailSet() {
            TreeSet<String> emailSet = new TreeSet<>();
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
                    User.this.getLocale(),
                    getEmail(),
                    getIP(),
                    getMailFrom(),
                    getValidHostname(),
                    getRecipient()
            );
        }
        
        public TreeSet<String> getSenderMXDomainSet() throws NamingException {
            String host = getSenderHostname(false);
            TreeSet<String> mxSet = new TreeSet<>();
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
        
        private String getMailFromHostnameSafe(boolean pontuacao) {
            String hostnameLocal = getMailFromHostname(pontuacao);
            if (hostnameLocal == null) {
                return "";
            } else {
                return hostnameLocal;
            }
        }
        
        public String getMailFromHostname(boolean pontuacao) {
            String senderLocal = getMailFrom();
            if (senderLocal == null) {
                return null;
            } else {
                int index = senderLocal.indexOf('@');
                String host = senderLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getFromHostname(boolean pontuacao) {
            String fromLocal = getFrom();
            if (fromLocal == null) {
                return null;
            } else {
                int index = fromLocal.indexOf('@');
                String host = fromLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        private String getFromHostnameSafe(boolean pontuacao) {
            String hostnameLocal = getFromHostname(pontuacao);
            if (hostnameLocal == null) {
                return "";
            } else {
                return hostnameLocal;
            }
        }
        
        private String getReplyToHostnameSafe(boolean pontuacao) {
            String hostnameLocal = getReplyToHostname(pontuacao);
            if (hostnameLocal == null) {
                return "";
            } else {
                return hostnameLocal;
            }
        }
        
        public String getReplyToHostname(boolean pontuacao) {
            String replyLocal = getReplyTo();
            if (replyLocal == null) {
                return null;
            } else {
                int index = replyLocal.indexOf('@');
                String host = replyLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        private String getRecipientHostnameSafe(boolean pontuacao) {
            String hostnameLocal = getRecipientHostname(pontuacao);
            if (hostnameLocal == null) {
                return null;
            } else {
                return hostnameLocal;
            }
        }
        
        public String getRecipientHostname(boolean pontuacao) {
            String recipientLocal = getRecipient();
            if (recipientLocal == null) {
                return null;
            } else {
                int index = recipientLocal.indexOf('@');
                String host = recipientLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
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
            } else if (Provider.containsMX(sender) && Domain.isValidEmail(sender)) {
                return sender;
//            } else if (Provider.containsDomain(getValidHostname()) && Provider.containsDomain(sender)) {
//                if (from == null && replyto == null) {
//                    return sender;
//                } else if (replyto == null) {
//                    return from;
//                } else if (sender.equals(from)) {
//                    return replyto;
//                } else {
//                    return from;
//                }
            } else if (Provider.containsDomain(getValidHostname()) && Domain.isValidEmail(sender) && !Provider.containsDomain(sender)) {
                return sender;
            } else if (Provider.containsDomain(getValidHostname()) && Domain.isValidEmail(from) && !Provider.containsDomain(from)) {
                return from;
            } else if (Provider.containsDomain(getValidHostname()) && Domain.isValidEmail(replyto) && !Provider.containsDomain(replyto)) {
                return replyto;
            } else if (Domain.isValidEmail(sender)) {
                return sender;
            } else if (Domain.isValidEmail(from)) {
                return from;
            } else if (Domain.isValidEmail(replyto)) {
                return replyto;
            } else if (Domain.isMailFrom(sender)) {
                return sender;
            } else if (Domain.isMailFrom(from)) {
                return from;
            } else if (Domain.isMailFrom(replyto)) {
                return replyto;
            } else {
                return sender;
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
        
        private String getValidHostnameSafe() {
            if (hostname != null) {
                return hostname;
            } else if (SPF.matchHELO(ip, helo)) {
                return hostname = helo;
            } else {
                String host = Reverse.getValidHostname(ip);
                if (host == null) {
                    return hostname = "";
                } else if (Generic.containsGenericDomain(host)) {
                    return hostname = "";
                } else {
                    return hostname = Domain.normalizeHostname(host, false);
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
        
        public boolean isClient(Client client) {
            if (client == null) {
                return false;
            } else {
                return client.isDomain(this.client);
            }
        }
        
        public boolean isIP(String ip) {
            if (ip == null) {
                return false;
            } else {
                return ip.equals(this.ip);
            }
        }
        
        public boolean isHostname(String hostname) {
            if (hostname == null) {
                return false;
            } else {
                return hostname.equals(this.hostname);
            }
        }
        
        public boolean isOrigin(String ip, String hostname) {
            if (hostname == null) {
                return isIP(ip);
            } else {
                return isHostname(hostname);
            }
        }
        
        public boolean isSender(String sender) {
            if (sender == null) {
                return false;
            } else {
                return sender.equals(this.sender);
            }
        }
        
        public boolean isMailFromTo(String sender, String recipient) {
            if (isMailFrom(sender)) {
                return isRecipient(recipient);
            } else {
                return false;
            }
        }
        
        public boolean isMailFrom(String sender) {
            if (sender == null) {
                return this.sender == null;
            } else {
                return sender.equals(this.sender);
            }
        }
        
        public boolean isRecipient(String recipient) {
            if (recipient == null) {
                return false;
            } else {
                return recipient.equals(this.recipient);
            }
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
        
        public boolean isBlockKey() {
            String blockKey = getBlockKey();
            return Block.containsExact(User.this, blockKey);
        }
        
        public String getBlockKey() {
            String key = getBlockSender();
            if (key == null) {
                key = getValidHostDomain();
                if (key == null) {
                    key = getValidHostname();
                    if (key == null) {
                        key = "mailer-daemon@;" + getIP();
                    } else {
                        key = "mailer-daemon@" + key;
                    }
                } else {
                    key = "mailer-daemon@" + key;
                }
            }
            return key;
        }
        
        public boolean isWhiteKey() {
            String whiteKey = getWhiteKey();
            return White.containsExtact(User.this, whiteKey);
        }
        
        private String getWhiteKey() {
            String key = getWhiteSender();
            if (key == null) {
                key = getValidHostDomain();
                if (key == null) {
                    key = getValidHostname();
                    if (key == null) {
                        key = "mailer-daemon@;" + getIP();
                    } else {
                        key = "mailer-daemon@" + key;
                    }
                } else {
                    key = "mailer-daemon@" + key;
                }
            }
            return key;
        }
        
        public void processComplainForWhite() {
            String whiteKey = getWhiteKey();
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuerySafe(time);
                if (query != null && whiteKey.equals(query.getWhiteKey())) {
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
            String blockKey = getBlockKey();
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuerySafe(time);
                if (query != null && blockKey.equals(query.getBlockKey())) {
                    if (query.isBlock()) {
                        query.clearWhite();
                        complain(time);
                    }
                }
            }
        }
        
        public void clearWhite() {
            try {
                String mailFrom = getMailFrom();
                String qualifierLocal = qualifier == null ? "NONE" : qualifier.name();
                if (mailFrom == null) {
                    String domain = this.getOriginDomain(false);
                    if (domain == null) {
                        mailFrom = null;
                        qualifierLocal = "NONE";
                    } else {
                        mailFrom = "mailer-daemon@" + domain;
                        qualifierLocal = "NONE";
                    }
                }
                White.clear(null, User.this, ip, mailFrom, getValidHostname(), qualifierLocal, recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
//            try {
//                White.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
//            } catch (ProcessException ex) {
//                Server.logError(ex);
//            }
            try {
                White.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                White.clear(null, User.this, ip, from, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                White.clear(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                White.clear(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        
        public void clearBlock() {
            try {
                String mailFrom = getMailFrom();
                String qualifierLocal = qualifier == null ? "NONE" : qualifier.name();
                if (mailFrom == null) {
                    String domain = this.getOriginDomain(false);
                    if (domain == null) {
                        mailFrom = null;
                        qualifierLocal = "NONE";
                    } else {
                        mailFrom = "mailer-daemon@" + domain;
                        qualifierLocal = "NONE";
                    }
                }
                Block.clear(null, User.this, ip, mailFrom, getValidHostname(), qualifierLocal, recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
//            try {
//                Block.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
//            } catch (ProcessException ex) {
//                Server.logError(ex);
//            }
            try {
                Block.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                Block.clear(null, User.this, ip, from, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                Block.clear(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                Block.clear(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            if (linkMap != null) {
                for (String link : linkMap.keySet()) {
                    Block.clearHREF(User.this, link, email);
                }
            }
        }
        
//        public String getBlockSender() {
//            Situation situation;
//            String senderLocal = getSender();
//            if (senderLocal == null) {
//                return null;
//            } else if (senderLocal.equals(senderLocal)) {
//                situation = getSituation(true);
//            } else {
//                situation = Situation.NONE;
//            }
//            switch (situation) {
//                case AUTHENTIC:
//                case NONE:
//                    return getSenderSimplified(true, true);
//                case ZONE:
//                case IP:
//                    return getSenderDomain(true) + ";NOTPASS";
//                case SAME:
//                    String validator = getValidator(false);
//                    if (validator == null) {
//                        return null;
//                    } else {
//                        return getSenderSimplified(true, true) + ";" + validator;
//                    }
//                case DOMAIN:
//                    String senderSimplified = getSenderSimplified(true, true);
//                    if (senderSimplified == null) {
//                        return null;
//                    } else {
//                        return senderSimplified;
//                    }
//                case ORIGIN:
//                case ALL:
//                    String domain = this.getOriginDomain(false);
//                    if (domain == null) {
//                        return "mailer-daemon@;" + getIP();
//                    } else {
//                        return "mailer-daemon@" + domain;
//                    }
//                default:
//                    return null;
//            }
//        }
        
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
                    return getSenderSimplified(true, true);
                case NONE:
                    return getSenderSimplified(true, true) + ";NONE";
                case ZONE:
                case IP:
                    return getSenderDomain(true) + ";NOTPASS";
                case SAME:
                    String validator = getValidator(false);
                    if (validator == null) {
                        return getSenderSimplified(true, true);
                    } else {
                        return getSenderSimplified(true, true) + ";" + validator;
                    }
                case DOMAIN:
                    String senderSimplified = getSenderSimplified(true, true);
                    if (senderSimplified == null) {
                        return null;
                    } else {
                        return senderSimplified;
                    }
                case ORIGIN:
                case ALL:
                    String domain = getOriginDomain(false);
                    if (domain == null) {
                        return "mailer-daemon@;" + getIP();
                    } else {
                        return "mailer-daemon@" + domain;
                    }
                default:
                    return null;
            }
        }
        
        public boolean blockKey(long time) {
            try {
                clearWhite();
                complain(time);
                return Block.addExact(getUserEmail() + ":" + getBlockKey());
            } catch (ProcessException ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean blockForRecipient(long time) {
            if (recipient == null) {
                return false;
            } else {
                return Block.addSafe(
                        User.this,
                        getBlockKey() + ">" + recipient
                );
            }
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
                            return Block.addExact(getUserEmail() + ":mailer-daemon@;" + getIP());
                        } else {
                            return Block.addExact(getUserEmail() + ":mailer-daemon@" + domain);
                        }
                    case RECIPIENT:
                        String recipientAddr = getRecipient();
                        if (recipientAddr == null) {
                            return false;
                        } else {
                            return Trap.addInexistent(User.this, recipientAddr);
                        }
                    case MALWARE:
                        String malwareLocal = getMalware();
                        if (malwareLocal == null) {
                            return false;
                        } else {
                            return Ignore.dropExact(getEmail() + ":MALWARE=" + malwareLocal);
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
        
        public String getWhiteSender() {
            Situation situation;
            String senderLocal = getSender();
            if (senderLocal == null) {
                return null;
            } else if (senderLocal.equals(sender)) {
                situation = getSituation(true);
            } else {
                situation = getSituation(false);
            }
            String domain;
            switch (situation) {
                case IP:
                    return getSenderSimplified(false, true) + ";" + getIP();
                case ZONE:
                    domain = getValidHostDomain();
                    if (domain == null) {
                        return null;
                    } else {
                        return getSenderSimplified(false, true) + ";" + domain;
                    }
                case AUTHENTIC:
                    return getSenderSimplified(false, true) + ";PASS";
                case SAME:
                    String validator = getValidator(false);
                    if (validator == null) {
                        return null;
                    } else {
                        return getSenderSimplified(false, true) + ";" + validator;
                    }
                default:
                    return null;
            }
        }
        
        public boolean whiteKey(long time) {
            try {
                clearBlock();
                SPF.setHam(time, tokenSet);
                return White.addExact(getUserEmail() + ":" + getWhiteKey());
            } catch (ProcessException ex) {
                Server.logError(ex);
                return false;
            }
        }
        
//        public boolean whiteSender(long time) {
//            Situation situation;
//            String senderLocal = getSender();
//            if (senderLocal == null) {
//                situation = Situation.ORIGIN;
//            } else if (senderLocal.equals(senderLocal)) {
//                situation = getSituation(true);
//            } else {
//                situation = getSituation(false);
//            }
//            return white(time, situation);
//        }
        
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
                            domain = getValidHostDomain();
                            if (domain == null) {
                                return White.addExact(getUserEmail() + ":mailer-daemon@;" + getIP());
                            } else {
                                return White.addExact(getUserEmail() + ":mailer-daemon@" + domain + ";" + domain);
                            }
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
                        case MALWARE:
                            String malwareLocal = getMalware();
                            if (malwareLocal == null) {
                                return false;
                            } else if (Ignore.addExact(getEmail() + ":MALWARE=" + malwareLocal)) {
                                Server.logInfo("false positive MALWARE '" + malwareLocal + "' detected by '" + getEmail() + "'.");
                                return true;
                            } else {
                                return false;
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
        
        public boolean hasMailFrom() {
            return sender != null;
        }
        
        public boolean hasRecipient() {
            return recipient != null;
        }
        
        public boolean hasMessageID() {
            return messageID != null;
        }
        
        public boolean hasHeaderFrom() {
            return from != null;
        }
        
        public boolean hasSubject() {
            return subject != null;
        }
        
        public boolean ignoreMalware() {
            if (malware == null) {
                return false;
            } else {
                return Ignore.containsExact(getEmail() + ":MALWARE=" + malware);
            }
        }
        
        public boolean hasMalware() {
            return malware != null;
        }
        
        public boolean isHolding() {
            return result.equals("HOLD");
        }
        
        public boolean isFinished() {
            return !result.equals("HOLD") && !result.equals("LISTED") && !result.equals("GREYLIST");
        }
        
        public boolean isDelivered() {
            return result.equals("WHITE") || result.equals("ACCEPT");
        }
        
        public boolean isHoldingFull() {
            if (!isHolding()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isAnyLinkBLOCK()) {
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
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (hasTokenRed()) {
                return true;
            } else if (isAnyLinkRED()) {
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
        
        public boolean isNotAdvisedAdmin() {
            return !adminAdvised;
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
        
//        public boolean isWhiteSender() {
//            return White.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient) != null;
//        }
        
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
        
//        public boolean isBlockSender() {
//            if (Core.isAbuseEmail(recipient)) {
//                return Block.containsExact(
//                        User.this,
//                        getSenderSimplified(true, true) + ">" + recipient
//                );
//            } else {
//                return Block.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient, false, false, false, false) != null;
//            }
//        }
        
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
                } else if (Subnet.isValidIP(token)) { /////////// test
                    return true;
                } else if (Generic.containsGenericSoft(token)) {
                   return true;
                } else if (Block.find(User.this, token, false, false, false) != null) {
                    return true;
                } else if (Domain.isHostname(token)) {
                    if (token.contains(".xn--")) {
                        // IDNA encoding.
                       return true;
                    } else {
                        String listed = Reverse.getListedHost(token, "multi.uribl.com", "127.0.0.2", "127.0.0.4", "127.0.0.8");
                        if (listed != null) {
                            Server.logDebug("host " + token + " is listed in 'multi.uribl.com;" + listed + "'.");
                            return true;
                        }
                    }
//                } else if (Subnet.isValidIP(token)) {
//                    String listed = Reverse.getListedIP(token, "multi.uribl.com", "127.0.0.2", "127.0.0.4", "127.0.0.8");
//                    if (listed != null) {
//                        Server.logDebug("href " + token + " is listed in 'multi.uribl.com;" + listed + "'.");
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
        
        public boolean isToAdmin() {
            return Core.isAdminEmail(recipient);
        }
        
        public boolean isToAbuse() {
            return Core.isAbuseEmail(recipient);
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
        
//        public boolean isSenderWhite() {
//            String validator = getValidator(true);
//            if (validator == null) {
//                return false;
//            } else {
//                return White.containsExtact(User.this, getSenderSimplified(false, true) + ';' + validator);
//            }
//        }
        
        public boolean isOriginWhite() {
            String domain = getOriginDomain(false);
            if (domain == null) {
                return White.containsExtact(User.this, "mailer-daemon@;" + getIP());
            } else {
                return White.containsExtact(User.this, "mailer-daemon@" + domain + ";" + domain);
            }
        }
        
        public boolean isSenderBlock() {
            if (isSenderBlock(false)) {
                return true;
            } else {
                Situation situation;
                String senderLocal = getSender();
                if (senderLocal == null) {
                    return false;
                } else if (senderLocal.equals(sender)) {
                    situation = getSituation(true);
                } else {
                    situation = Situation.NONE;
                }
                if (situation == Situation.AUTHENTIC) {
                    return false;
                } else {
                    return isSenderBlock(true);
                }
            }
        }
        
        public boolean isSenderBlock(boolean validation) {
            if (validation) {
                return Block.containsExact(User.this, getSenderDomain(true) + ";NOTPASS");
            } else {
                return Block.containsExact(User.this, getSenderSimplified(true, true));
            }
        }
        
        public boolean isOriginBlock() {
            String domain = getOriginDomain(false);
            if (domain == null) {
                return Block.containsExact(User.this, "mailer-daemon@;" + getIP());
            } else {
                return Block.containsExact(User.this, "mailer-daemon@" + domain);
            }
        }
        
//        public boolean isOriginDomainBlock() {
//            String domain = getOriginDomain(false);
//            if (domain == null) {
//                return false;
//            } else {
//                return Block.containsExact(User.this, "mailer-daemon@" + domain);
//            }
//        }
        
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
        
        public boolean isSenderTrustable() {
            if (isPass()) {
                return true;
            } else if (Provider.containsDomain(getValidHostname())) {
                return true;
            } else {
                String domainSender = getSenderDomain(false);
                if (domainSender == null) {
                    return false;
                } else {
                    String domainHostname = getValidHostDomain();
                    return domainSender.equals(domainHostname);
                }
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
        
        public boolean hasTokenYellow() {
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
                TreeSet<String> resultSet = new TreeSet<>();
                resultSet.addAll(linkMap.keySet());
                return resultSet;
            }
        }
        
        public TreeSet<String> getTokenSet() {
            TreeSet<String> resultSet = new TreeSet<>();
            resultSet.addAll(tokenSet);
            return resultSet;
        }
        
        public String getMalware() {
            return malware;
        }
        
        public boolean setResult(String oldResult, String newResult) {
            if (oldResult == null) {
                return false;
            } else if (newResult == null) {
                return false;
            } else {
                boolean changed;
                if (CHANGED.acquireIf(true)) {
                    changed = true;
                } else if (CHANGED.acquireIf(false)) {
                    changed = false;
                } else {
                    return false;
                }
                if (newResult.equals(this.result)) {
                    this.CHANGED.release(changed);
                    return true;
                } else if (oldResult.equals(this.result)) {
                    this.result = newResult;
                    this.STORED = false;
                    this.CHANGED.release(true);
                    return User.CHANGED = true;
                } else {
                    this.CHANGED.release(changed);
                    return false;
                }
            }
        }
        
        public boolean setResult(String result) {
            if (result == null) {
                return false;
            } else if (result.equals("MALWARE")) {
                this.CHANGED.acquire();
                this.malware = "FOUND";
                this.result = "REJECT";
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            } else if (!result.equals(this.result)) {
                this.CHANGED.acquire();
                this.result = result;
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            } else {
                return false;
            }
        }
        
        private boolean matchAll(long time, String filter) {
            if (filter == null) {
                return false;
            } else if (filter.length() == 0) {
                return false;
            } else {
                filter = filter.toLowerCase();
                StringTokenizer tokenizer = new StringTokenizer(filter, ",");
                int count = tokenizer.countTokens();
                if (count == 0) {
                    return false;
                } else {
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        token = token.trim();
                        if (matchSingle(time, token)) {
                            count--;
                        }
                    }
                    return count == 0;
                }
            }
        }
        
        private boolean matchSingle(long time, String filter) {
            if (filter == null) {
                return false;
            } else if (filter.equals("retida") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("retido") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("hold") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitado") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejected") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejeitado") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejected") && isResult("REJECT")) {
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
            } else if (Domain.hasTLD(filter)) {
                filter = Domain.normalizeHostname(filter, true);
                if (filter.endsWith("." + getHELO())) {
                    return true;
                } else if (filter.endsWith("." + getValidHostnameSafe())) {
                    return true;
                } else if (filter.endsWith("." + getMailFromHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getFromHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getReplyToHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getRecipientHostnameSafe(false))) {
                    return true;
                } else {
                    return false;
                }
            } else {
                Date date = getDate(filter);
                if (date == null) {
                    return false;
                } else if (time < date.getTime()) {
                    return false;
                } else {
                    return time < date.getTime() + 86400000;
                }
            }
        }
        
        public String getFrom() {
            return from;
        }
        
        public String getReplyTo() {
            return replyto;
        }
        
        public Timestamp getMessageDate() {
            return date;
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
        
        private boolean setLinkBlocked(String link) {
            if ((link = normalizeLink(link)) == null) {
                return false;
            } else {
                this.CHANGED.acquire();
                if (linkMap == null) {
                    linkMap = new TreeMap<>();
                }
                this.linkMap.put(link, true);
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            }
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
        
        public boolean isInvalidDate(long time) {
            if (date == null) {
                return false;
            } else {
                return Math.abs(time - date.getTime()) > 259200000;
            }
        }
        
        private TreeSet<String> getLinkKeySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (linkMap != null) {
                keySet.addAll(linkMap.keySet());
            }
            return keySet;
        }
        
        public boolean addLink(String link) {
            if ((link = normalizeLink(link)) == null) {
                return false;
            } else {
                this.CHANGED.acquire();
                try {
                    if (this.linkMap == null) {
                        this.linkMap = new TreeMap<>();
                    }
                    boolean blocked = false;
                    if (isToPostmaster()) {
                        this.linkMap.put(link, false);
                    } else if (isToAdmin()) {
                        this.linkMap.put(link, false);
                    } else if (isToAbuse()) {
                        this.linkMap.put(link, false);
                    } else if (Block.findHREF(User.this, link) == null) {
                        this.linkMap.put(link, false);
                    } else {
                        this.linkMap.put(link, true);
                        blocked = true;
                    }
                    this.STORED = false;
                    User.CHANGED = true;
                    return blocked;
                } finally {
                    this.CHANGED.release(true);
                }
            }
        }
        
        public boolean setLinkSet(TreeSet<String> linkSet) {
            if (linkSet == null) {
                return false;
            } else {
                this.CHANGED.acquire();
                try {
                    if (this.linkMap == null) {
                        this.linkMap = new TreeMap<>();
                    }
                    boolean blocked = false;
                    for (String link : linkSet) {
                        if ((link = normalizeLink(link)) != null) {
                            if (isToPostmaster()) {
                                this.linkMap.put(link, false);
                            } else if (isToAdmin()) {
                                this.linkMap.put(link, false);
                            } else if (isToAbuse()) {
                                this.linkMap.put(link, false);
                            } else if (Block.findHREF(User.this, link) == null) {
                                this.linkMap.put(link, false);
                            } else {
                                this.linkMap.put(link, true);
                                blocked = true;
                            }
                        }
                    }
                    this.STORED = false;
                    User.CHANGED = true;
                    return blocked;
                } finally {
                    this.CHANGED.release(true);
                }
            }
        }
        
        public String setMalware(String malware) {
            if (malware == null) {
                return null;
            } else if ((malware = malware.length() == 0 ? "FOUND" : malware).equals(this.malware)) {
                return null;
            } else if (isToAbuse()) {
                this.CHANGED.acquire();
                this.malware = malware;
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return "ACCEPT";
            } else if (Ignore.containsExact(getEmail() + ":MALWARE=" + malware)) {
                this.CHANGED.acquire();
                this.malware = malware;
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return "ACCEPT";
            } else {
                this.CHANGED.acquire();
                this.malware = malware;
                this.result = "REJECT";
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return "REJECT";
            }
        }
        
        public String getTextPlainBody(int limit) {
            if (body == null) {
                return null;
            } else {
                try {
                    ByteArrayOutputStream baOS = new ByteArrayOutputStream();
                    ByteArrayInputStream baIS = new ByteArrayInputStream(body);
                    try (GZIPInputStream gzipIS = new GZIPInputStream(baIS)) {
                        int code;
                        while ((code = gzipIS.read()) != -1) {
                            baOS.write(code);
                        }
                    }
                    String html = baOS.toString();
                    Document document = Jsoup.parse(html);
                    document.normalise();
                    String text = document.text();
                    text = text.replace('\n', ' ');
                    text = text.replace('\r', ' ');
                    text = text.replaceAll("(^\\h*)|(\\h*$)", "");
                    while (text.contains("  ")) {
                        text = text.replace("  ", " ");
                    }
                    text = text.trim();
                    if (text.length() < 8) {
                        text = null;
                    } else if (text.length() > limit) {
                        limit = text.lastIndexOf(' ', limit);
                        text = text.substring(0, limit);
                        text = text.trim() + "...";
                    }
                    return text;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        }
        
        public boolean hasBody() {
            return body != null;
        }
        
        public boolean setBody(byte[] data) {
            if (data == null) {
                return false;
            } else {
                this.CHANGED.acquire();
                this.body = data;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return true;
            }
        }
        
        public boolean needHeader() {
            if (User.this.usingHeader) {
                String hostnameLocal = getValidHostname();
                String senderLocal = getMailFrom();
                if (hostnameLocal == null) {
                    return false;
                } else if (senderLocal == null) {
                    return false;
                } else if (Generic.containsGenericSoft(hostnameLocal)) {
                    return false;
                } else if (Generic.containsGenericSoft(senderLocal)) {
                    return false;
                } else if (isSenderRed()) {
                    return false;
                } else if (isBlockKey()) {
                    return false;
                } else if (isSenderBlock()) {
                    return false;
                } else if (Block.containsWHOIS(User.this, getSender())) {
                    return false;
                } else {
                    return true;
                }
            } else {
                return false;
            }
        }
        
        private boolean waitHeader() {
            if (isResult("BLOCK")) {
                return false;
            } else if (isResult("FAIL")) {
                return false;
            } else if (isResult("GREYLIST")) {
                return false;
            } else if (isResult("INEXISTENT")) {
                return false;
            } else if (isResult("INVALID")) {
                return false;
            } else if (isResult("REJECT")) {
                return false;
            } else if (isResult("NXDOMAIN")) {
                return false;
            } else if (hasSubject()) {
                return true;
            } else if (hasMessageID()) {
                return true;
            } else if (isUsingHeader()) {
                waitHeader(3000);
                return hasSubject() || hasMessageID();
            } else {
                return false;
            }
        }
        
        private synchronized void waitHeader(int timeout) {
            try {
                wait(timeout);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
//        public String setHeader(
//                long time,
//                Client client,
//                String from,
//                String replyto,
//                String subject,
//                String messageID,
//                String date,
//                String unsubscribe,
//                Action actionBLOCK,
//                Action actionRED
//        ) {
//            this.CHANGED.acquire();
//            try {
//                User.this.usingHeader = true;
//                if (from == null || from.length() == 0) {
//                    if (this.from != null) {
//                        this.from = null;
//                        User.CHANGED = true;
//                    }
//                } else if (Domain.isMailFrom(from = from.toLowerCase()) && !from.equals(this.from)) {
//                    this.from = from;
//                    User.CHANGED = true;
//                }
//                if (replyto == null || replyto.length() == 0) {
//                    if (this.replyto != null) {
//                        this.replyto = null;
//                        User.CHANGED = true;
//                    }
//                } else if (Domain.isMailFrom(replyto = replyto.toLowerCase()) && !replyto.equals(this.replyto)) {
//                    this.replyto = replyto;
//                    User.CHANGED = true;
//                }
//                if (subject == null || subject.length() == 0) {
//                    if (this.subject != null) {
//                        this.subject = null;
//                        User.CHANGED = true;
//                    }
//                } else {
//                    try {
//                        subject = MimeUtility.decodeText(subject);
//                        subject = subject.trim();
//                    } catch (UnsupportedEncodingException ex) {
//                    }
//                    while (subject.contains("  ")) {
//                        subject = subject.replace("  ", " ");
//                    }
//                    if (subject.length() == 0) {
//                        if (this.subject != null) {
//                            this.subject = null;
//                            User.CHANGED = true;
//                        }
//                    } else if (!subject.equals(this.subject)) {
//                        this.subject = subject;
//                        User.CHANGED = true;
//                    }
//                }
//                if (messageID == null || messageID.length() == 0) {
//                    if (this.messageID != null) {
//                        this.messageID = null;
//                        User.CHANGED = true;
//                    }
//                } else {
//                    int index = messageID.indexOf('<');
//                    if (index >= 0) {
//                        messageID = messageID.substring(index + 1);
//                        index = messageID.indexOf('>');
//                        if (index > 0) {
//                            messageID = messageID.substring(0, index);
//                            if (!messageID.equals(this.messageID)) {
//                                this.messageID = messageID;
//                                User.CHANGED = true;
//                            }
//                        }
//                    }
//                }
//                boolean reject = false;
//                if (date == null) {
//                    this.date = new Timestamp(time);
//                    User.CHANGED = true;
//                } else if (date.length() == 0) {
//                    this.date = null;
//                } else {
//                    try {
//                        Date emailDate = Core.parseEmailDateSafe(date);
//                        if (Math.abs(time - emailDate.getTime()) > 31104000000L) {
//                            this.date = null;
//                            reject = true;
//                        } else if (this.date == null || this.date.getTime() != emailDate.getTime()) {
//                            this.date = new Timestamp(emailDate.getTime());
//                            User.CHANGED = true;
//                        }
//                    } catch (ParseException ex) {
//                        this.date = null;
//                        reject = true;
//                    }
//                }
//                if (unsubscribe != null && unsubscribe.length() > 0) {
//                    try {
//                        int index = unsubscribe.indexOf('<');
//                        if (index >= 0) {
//                            unsubscribe = unsubscribe.substring(index + 1);
//                            index = unsubscribe.indexOf('>');
//                            if (index > 0) {
//                                unsubscribe = unsubscribe.substring(0, index);
//                                URL url = new URL(unsubscribe);
//                                if (addLink(url.getHost())) {
//                                    reject = true;
//                                }
//                                if (!url.equals(this.unsubscribe)) {
//                                    this.unsubscribe = url;
//                                    User.CHANGED = true;
//                                }
//                            }
//                        }
//                    } catch (MalformedURLException ex) {
//                        Server.logTrace("malformed unsubscribe URL: " + unsubscribe);
//                    } catch (Exception ex) {
//                        Server.logError(ex);
//                    }
//                }
//                String resultReturn;
//                if (isWhite()) {
//                    this.whiteKey(time);
//                    this.result = "WHITE";
//                    resultReturn = "WHITE";
//                } else if (isToPostmaster()) {
//                    resultReturn = null;
//                } else if (isToAbuse()) {
//                    resultReturn = null;
//                } else if (isBlockKey() || isSenderBlock() || isAnyLinkBLOCK() || Block.containsWHOIS(User.this, getSender())) {
//                    if (actionBLOCK == Action.FLAG) {
//                        this.result = "FLAG";
//                        resultReturn = "FLAG";
//                    } else if (actionBLOCK == Action.HOLD) {
//                        this.result = "HOLD";
//                        resultReturn = "HOLD";
//                    } else {
//                        blockKey(time);
//                        this.result = "BLOCK";
//                        resultReturn = "BLOCK";
//                    }
//                } else if (isInexistent(client)) {
//                    blockKey(time);
//                    this.result = "BLOCK";
//                    resultReturn = "BLOCK";
//                } else if (isToAdmin()) {
//                    resultReturn = null;
//                } else if (reject) {
//                    this.complain(time);
//                    this.result = "REJECT";
//                    resultReturn = "REJECT";
//                } else if (!hasMailFrom() && !hasHeaderFrom()) {
//                    this.complain(time);
//                    this.result = "REJECT";
//                    resultReturn = "REJECT";
//                } else if (!hasMessageID() || isInvalidDate(time) || hasMiscellaneousSymbols() || hasTokenRed() || isAnyLinkRED() || isBlock()) {
//                    if (actionRED == Action.FLAG) {
//                        this.result = "FLAG";
//                        resultReturn = "FLAG";
//                    } else if (actionRED == Action.HOLD) {
//                        this.result = "HOLD";
//                        resultReturn = "HOLD";
//                    } else {
//                        this.complain(time);
//                        this.result = "REJECT";
//                        resultReturn = "REJECT";
//                    }
//                } else {
//                    resultReturn = null;
//                }
//                return resultReturn;
//            } finally {
//                this.STORED = false;
//                this.CHANGED.release(true);
//                this.notifyHeader();
//            }
//        }
        
        public String setHeader(
                long time,
                Client client,
                String from,
                String replyto,
                String subject,
                String messageID,
                String date,
                String unsubscribe,
                Action actionBLOCK,
                Action actionRED
        ) {
            if (from == null || from.length() == 0) {
                from = null;
            } else if (!Domain.isMailFrom(from = from.toLowerCase())) {
                from = null;
            }
            if (replyto == null || replyto.length() == 0) {
                replyto = null;
            } else if (!Domain.isMailFrom(replyto = replyto.toLowerCase())) {
                replyto = null;
            }
            if (subject == null || subject.length() == 0) {
                subject = null;
            } else {
                try {
                    subject = MimeUtility.decodeText(subject);
                    subject = subject.trim();
                } catch (UnsupportedEncodingException ex) {
                }
                while (subject.contains("  ")) {
                    subject = subject.replace("  ", " ");
                }
                if (subject.length() == 0) {
                    subject = null;
                }
            }
            if (messageID == null || messageID.length() == 0) {
                messageID = null;
            } else {
                int index = messageID.indexOf('<');
                if (index >= 0) {
                    messageID = messageID.substring(index + 1);
                    index = messageID.indexOf('>');
                    if (index > 0) {
                        messageID = messageID.substring(0, index);
                    }
                }
            }
            boolean reject = false;
            Timestamp emailDate = null;
            if (date == null) {
                emailDate = new Timestamp(time);
            } else if (date.length() == 0) {
                emailDate = null;
            } else {
                try {
                    Date newDate = Core.parseEmailDateSafe(date);
                    emailDate = new Timestamp(newDate.getTime());
                    if (Math.abs(time - emailDate.getTime()) > 31104000000L) {
                        emailDate = null;
                        reject = true;
                    }
                } catch (ParseException ex) {
                    emailDate = null;
                    reject = true;
                }
            }
            URL unsubscribeURL = null;
            if (unsubscribe != null && unsubscribe.length() > 0) {
                try {
                    int index = unsubscribe.indexOf('<');
                    if (index >= 0) {
                        unsubscribe = unsubscribe.substring(index + 1);
                        index = unsubscribe.indexOf('>');
                        if (index > 0) {
                            unsubscribe = unsubscribe.substring(0, index);
                            unsubscribeURL = new URL(unsubscribe);
                            if (addLink(unsubscribeURL.getHost())) {
                                reject = true;
                            }
                        }
                    }
                } catch (MalformedURLException ex) {
                    Server.logTrace("malformed unsubscribe URL: " + unsubscribe);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            this.CHANGED.acquire();
            try {
                this.from = from;
                this.replyto = replyto;
                this.subject = subject;
                this.messageID = messageID;
                this.date = emailDate;
                this.unsubscribe = unsubscribeURL;
            } finally {
                User.this.usingHeader = true;
                User.CHANGED = true;
                this.STORED = false;
                this.CHANGED.release(true);
            }
            String resultReturn;
            if (isWhite()) {
                this.whiteKey(time);
                resultReturn = "WHITE";
            } else if (isToPostmaster()) {
                resultReturn = null;
            } else if (isToAbuse()) {
                resultReturn = null;
            } else if (isBlockKey() || isSenderBlock() || isAnyLinkBLOCK() || Block.containsWHOIS(User.this, getSender())) {
                if (actionBLOCK == Action.FLAG) {
                    resultReturn = "FLAG";
                } else if (actionBLOCK == Action.HOLD) {
                    resultReturn = "HOLD";
                } else {
                    blockKey(time);
                    resultReturn = "BLOCK";
                }
            } else if (isInexistent(client)) {
                blockKey(time);
                resultReturn = "BLOCK";
            } else if (isToAdmin()) {
                resultReturn = null;
            } else if (reject) {
                this.complain(time);
                resultReturn = "REJECT";
            } else if (!hasMailFrom() && !hasHeaderFrom()) {
                this.complain(time);
                resultReturn = "REJECT";
            } else if (!hasMessageID() || isInvalidDate(time) || hasMiscellaneousSymbols() || hasTokenRed() || isAnyLinkRED() || isBlock()) {
                if (actionRED == Action.FLAG) {
                    resultReturn = "FLAG";
                } else if (actionRED == Action.HOLD) {
                    resultReturn = "HOLD";
                } else {
                    this.complain(time);
                    resultReturn = "REJECT";
                }
            } else {
                resultReturn = null;
            }
            this.CHANGED.acquire();
            try {
                if (resultReturn == null) {
                    return null;
                } else {
                    return this.result = resultReturn;
                }
            } finally {
                this.CHANGED.release(true);
                this.notifyHeader();
            }
        }
        
        private synchronized void notifyHeader() {
            notify();
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
            if (isWhiteKey()) {
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
            if (isOriginBlock()) {
                return Situation.ORIGIN;
            } else if (isBlock()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public Situation getSenderBlockSituation() {
            String validator = getValidator(false);
            if (validator == null) {
                return Situation.ORIGIN;
            } else if (isSenderBlock(false)) {
                return Situation.DOMAIN;
            } else if (isSenderBlock(true)) {
                if (Subnet.isValidIP(validator)) {
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
            String senderLocal = getSender();
            String recipientLocal = getRecipient();
            if (recipientAdvised) {
                return false;
            } else if (senderLocal == null) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Domain.isValidEmail(senderLocal)) {
                return false;
            } else if (!Domain.isValidEmail(recipientLocal)) {
                return false;
            } else if (NoReply.contains(recipientLocal, true)) {
                return false;
            } else {
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
                        Locale locale = User.this.getLocale();
//                        String qualifierLocal = getQualifierName();
                        String messageidLocal = getMessageID();
                        InternetAddress[] recipients = InternetAddress.parse(recipientLocal);
                        MimeMessage message = Core.newMessage();
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
                            ServerHTTP.buildText(builder, "Uma mensagem enviada por " + senderLocal + " foi retida por suspeita de SPAM.");
                            if (!isSenderTrustable()) {
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
                            ServerHTTP.buildText(builder, "A message sent from " + senderLocal + " was retained under suspicion of SPAM.");
                            if (!isSenderTrustable()) {
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
                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.recipientAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (MailConnectException ex) {
                    return false;
                } catch (SendFailedException ex) {
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        if (ex.getCause().getMessage().contains(" 5.1.1 ")) {
                            Trap.addInexistentSafe(User.this, recipientLocal);
                        }
                    }
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        public synchronized boolean adviseRecipientSPAM(long time) {
            String senderLocal = getSender();
            String recipientLocal = getRecipient();
            String subjectLocal = getSubject();
            String messageidLocal = getMessageID();
            if (recipientAdvised) {
                return false;
            } else if (senderLocal == null) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (subjectLocal == null) {
                return false;
            } else if (messageidLocal == null) {
                return false;
            } else if (isToPostmaster()) {
                return false;
            } else if (isToAdmin()) {
                return false;
            } else if (isToAbuse()) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Domain.isValidEmail(recipientLocal)) {
                return false;
            } else if (NoReply.contains(recipientLocal, true)) {
                return false;
            } else {
                try {
                    String url = Core.getBlockURL(User.this, time);
                    if (url == null) {
                        return false;
                    } else {
                        Server.logDebug("sending suspect alert by e-mail.");
                        Locale locale = User.this.getLocale();
                        InternetAddress[] recipients = InternetAddress.parse(recipientLocal);
                        MimeMessage message = Core.newMessage();
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(User.this.getInternetAddresses());
                        message.setSubject(subjectLocal);
                        message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
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
                            ServerHTTP.buildText(builder, "Esta mensagem, cujo assunto foi preservado e havia sido enviada por " + senderLocal + ", foi entregue em sua caixa postal por haver nenhuma suspeita sobre ela.");
                            ServerHTTP.buildText(builder, "Informações mais recentes levantam forte suspeita de que esta mensagem seria SPAM.");
                            ServerHTTP.buildText(builder, "Se você concorda com esta nova interpretação, acesse esta URL para bloquear o remetente e para contribuir para o combate de SPAM na Internet:");
                        } else {
                            ServerHTTP.buildMessage(builder, "SPAM suspected alert");
                            ServerHTTP.buildText(builder, "This message, whose subject was preserved and sent by " + senderLocal + ", was delivered to your mailbox because there was no suspicion about it.");
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
                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.recipientAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (MailConnectException ex) {
                    return false;
                } catch (SendFailedException ex) {
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        if (ex.getCause().getMessage().contains(" 5.1.1 ")) {
                            Trap.addInexistentSafe(User.this, recipientLocal);
                        }
                    }
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        private synchronized boolean adviseSenderHOLD(long time) {
            String mailFrom = getMailFrom();
            String recipientLocal = getRecipient();
            if (senderAdvised) {
                return true;
            } else if (mailFrom == null) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Domain.isValidEmail(mailFrom)) {
                return false;
            } else if (NoReply.contains(mailFrom, true)) {
                return false;
            } else if (NoReply.contains(recipientLocal, true)) {
                return false;
            } else if (Generic.containsGeneric(mailFrom)) {
                return false;
            } else if (!isSenderTrustable()) {
                return false;
            } else if (isBlock()) {
                return false;
            } else {
                try {
                    String url = Core.getHoldingURL(User.this, time);
                    if (url == null) {
                        return false;
                    } else {
                        Server.logDebug("sending retention warning by e-mail.");
                        Locale locale = User.this.getLocale();
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                subjectLocal = "Aviso de retenção de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String messageidLocal = getMessageID();
                        InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                        MimeMessage message = Core.newMessage();
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
                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.senderAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (ServiceUnavailableException ex) {
                    blockKey(time);
                    return false;
                } catch (NameNotFoundException ex) {
                    blockKey(time);
                    return false;
                } catch (CommunicationException ex) {
                    return false;
                } catch (MailConnectException ex) {
                    blockKey(time);
                    return false;
                } catch (SendFailedException ex) {
                    blockKey(time);
                    return false;
                } catch (MessagingException ex) {
                    blockKey(time);
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
                return true;
            } else if (mailFrom == null) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!isPass()) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Domain.isValidEmail(mailFrom)) {
                return false;
            } else if (NoReply.contains(mailFrom, true)) {
                return false;
            } else if (NoReply.contains(recipientLocal, true)) {
                return false;
            } else if (Generic.containsGeneric(mailFrom)) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else {
                try {
                    String url = getUnblockURL();
                    if (url == null) {
                        return false;
                    } else {
                        Server.logDebug("sending blocked warning by e-mail.");
                        Locale locale = User.this.getLocale();
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String messageidLocal = getMessageID();
                        InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                        MimeMessage message = Core.newMessage();
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
                        builder.append(subjectLocal);
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
                            ServerHTTP.buildText(builder, "A mensagem, que foi enviada para " + recipientLocal + ", foi rejeitada por bloqueio manual.");
                            ServerHTTP.buildText(builder, "Se você considera isto um engano, acesse esta URL para solicitar o desbloqueio:");
                        } else {
                            ServerHTTP.buildMessage(builder, "Message block warning");
                            ServerHTTP.buildText(builder, "The message, which was sent to " + recipientLocal + ", was rejected by manual block.");
                            ServerHTTP.buildText(builder, "If you consider this a mistake, access this URL to request unblock:");
                        }
                        ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.senderAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            blockKey(time);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (ServiceUnavailableException ex) {
                    blockKey(time);
                    return false;
                } catch (NameNotFoundException ex) {
                    blockKey(time);
                    return false;
                } catch (CommunicationException ex) {
                    return false;
                } catch (MailConnectException ex) {
                    blockKey(time);
                    return false;
                } catch (SendFailedException ex) {
                    blockKey(time);
                    return false;
                } catch (MessagingException ex) {
                    blockKey(time);
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }

        private synchronized boolean adviseUserHOLD(long time) {
            String senderLocal = getSender();
            String userEmail = getEmail();
            if (adminAdvised) {
                return true;
            } else if (senderLocal == null) {
                return false;
            } else if (userEmail == null) {
                return false;
            } else if (!Domain.isValidEmail(senderLocal)) {
                return false;
            } else if (NoReply.contains(userEmail, true)) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else {
                try {
                    String unholdURL = Core.getUnholdURL(User.this, time);
                    String blockURL = Core.getBlockURL(User.this, time);
                    if (unholdURL == null) {
                        return false;
                    } else if (blockURL == null) {
                        return false;
                    } else {
                        Server.logDebug("sending retention warning by e-mail.");
                        Locale locale = User.this.getLocale();
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
//                        String qualifierLocal = getQualifierName();
                        String recipientLocal = getRecipient();
                        String messageidLocal = getMessageID();
                        String textBody = getTextPlainBody(256);
                        TreeSet<String> linkSet = getLinkSet();
                        InternetAddress[] recipients = User.this.getInternetAddresses();
                        MimeMessage message = Core.newMessage();
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(InternetAddress.parse(senderLocal));
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
                        builder.append(subjectLocal);
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
                            ServerHTTP.buildText(builder, "Uma mensagem enviada de " + senderLocal + " para "  + recipientLocal + " foi retida por suspeita de SPAM.");
                            if (recipientAdvised) {
                                ServerHTTP.buildText(builder, "O destinatário já foi avisado sobre a retenção, porém ele não liberou a mensagem ainda.");
                            } else if (senderAdvised) {
                                ServerHTTP.buildText(builder, "O remetente já foi avisado sobre a retenção, porém ele não solicitou a liberação da mensagem ainda.");
                            }
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Atenção! Este remetente não pôde ser autenticado. Isso significa que a mensagem pode ser uma fraude!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>Não é possível determinar com segurança qual servidor disparou esta mensagem.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "A mensagem foi disparada por um servidor no domínio " + hostDomain + ".");
                                }
                            }
                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
                                ServerHTTP.buildText(builder, "Os seguintes elementos foram encontrados no corpo da mensagem retida:");
                                builder.append("    <ul>\n");
                                if (textBody != null) {
                                    builder.append("    <li>");
                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
                                    builder.append("</li>\n");
                                }
                                if (linkSet != null) {
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
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Attention! This sender could not be authenticated. That means the message can be a fraud!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "<p>The message was fired by a server in domain " + hostDomain + ".");
                                }
                            }
                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
                                ServerHTTP.buildText(builder, "The following elements have been found in message body:");
                                builder.append("    <ul>\n");
                                if (textBody != null) {
                                    builder.append("    <li>");
                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
                                    builder.append("</li>\n");
                                }
                                if (linkSet != null) {
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
                                }
                                builder.append("    </ul>\n");
                            }
                            ServerHTTP.buildText(builder, "If you consider this message legitimate, access this URL to request its release:");
                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                            ServerHTTP.buildText(builder, "If you consider this SPAM message, access this URL to block the sender:");
                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                        }

                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.adminAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (MailConnectException ex) {
                    return false;
                } catch (MessagingException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
    private synchronized boolean adviseAdminHOLD(long time) {
            String senderLocal = getSender();
            String userEmail = Core.getAdminEmail();
            if (senderAdvised) {
                return true;
            } else if (senderLocal == null) {
                return false;
            } else if (userEmail == null) {
                return false;
            } else if (!Domain.isValidEmail(senderLocal)) {
                return false;
            } else if (NoReply.contains(userEmail, true)) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else {
                try {
                    String unholdURL = Core.getUnholdURL(User.this, time);
                    String blockURL = Core.getBlockURL(User.this, time);
                    if (unholdURL == null) {
                        return false;
                    } else if (blockURL == null) {
                        return false;
                    } else {
                        Server.logDebug("sending retention warning by e-mail.");
                        Locale locale = User.this.getLocale();
                        String subjectLocal = getSubject();
                        if (subjectLocal == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                subjectLocal = "Aviso de rejeição de mensagem";
                            } else {
                                subjectLocal = "Message retention warning";
                            }
                        }
                        String recipientMail = getRecipient();
                        String requestURL;
                        if (recipientMail == null) {
                            requestURL = null;
                        } else if (NoReply.contains(recipientMail, true)) {
                            requestURL = null;
                        } else {
                            requestURL = Core.getHoldingURL(User.this, time);
                        }
//                        String qualifierLocal = getQualifierName();
                        String recipientLocal = getRecipient();
                        String messageidLocal = getMessageID();
                        String textBody = getTextPlainBody(256);
                        TreeSet<String> linkSet = getLinkSet();
                        InternetAddress[] recipients = {Core.getAdminInternetAddress()};
                        MimeMessage message = Core.newMessage();
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(InternetAddress.parse(senderLocal));
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
                        builder.append(subjectLocal);
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
                            ServerHTTP.buildText(builder, "Uma mensagem enviada de " + senderLocal + " para "  + recipientLocal + " foi retida por suspeita de SPAM.");
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Atenção! Este remetente não pôde ser autenticado. Isso significa que a mensagem pode ser uma fraude!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>Não é possível determinar com segurança qual servidor disparou esta mensagem.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "A mensagem foi disparada por um servidor no domínio " + hostDomain + ".");
                                }
                            }
                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
                                ServerHTTP.buildText(builder, "Os seguintes elementos foram encontrados no corpo da mensagem retida:");
                                builder.append("    <ul>\n");
                                if (textBody != null) {
                                    builder.append("    <li>");
                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
                                    builder.append("</li>\n");
                                }
                                if (linkSet != null) {
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
                            }
                            ServerHTTP.buildText(builder, "Se você considera esta mensagem legítima, acesse esta URL para solicitar a sua liberação:");
                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                            ServerHTTP.buildText(builder, "Se você considera esta mensagem SPAM, acesse esta URL para bloquear o remetente:");
                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                            if (requestURL != null) {
                                ServerHTTP.buildText(builder, "Se você não tiver certeza do que essa mensagem seja, acesse esta URL para passar esta liberação ao destinatário:");
                                ServerHTTP.buildText(builder, "<a href=\"" + requestURL + "\">" + requestURL + "</a>");
                            }
                        } else {
                            ServerHTTP.buildMessage(builder, "Message retention warning");
                            ServerHTTP.buildText(builder, "A message sent from " + senderLocal + " to " + recipientLocal + " was retained under suspicion of SPAM.");
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Attention! This sender could not be authenticated. That means the message can be a fraud!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "<p>The message was fired by a server in domain " + hostDomain + ".");
                                }
                            }
                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
                                ServerHTTP.buildText(builder, "The following elements have been found in message body:");
                                builder.append("    <ul>\n");
                                if (textBody != null) {
                                    builder.append("    <li>");
                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
                                    builder.append("</li>\n");
                                }
                                if (linkSet != null) {
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
                                }
                                builder.append("    </ul>\n");
                            }
                            ServerHTTP.buildText(builder, "If you consider this message legitimate, access this URL to request its release:");
                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                            ServerHTTP.buildText(builder, "If you consider this SPAM message, access this URL to block the sender:");
                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                            if (requestURL != null) {
                                ServerHTTP.buildText(builder, "If you're not sure what this message is, visit this URL to pass this release to the recipient:");
                                ServerHTTP.buildText(builder, "<a href=\"" + requestURL + "\">" + requestURL + "</a>");
                            }
                        }
                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                        builder.append("    </div>\n");
                        builder.append("  </body>\n");
                        builder.append("</html>\n");
                        // Making HTML part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                        // Making logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        File logoFile = ServerHTTP.getWebFile("logo.png");
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        logoPart.setDisposition(MimeBodyPart.INLINE);
                        // Join both parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart content.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (Core.sendMessage(locale, message, 30000)) {
                            this.CHANGED.acquire();
                            this.senderAdvised = true;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (MailConnectException ex) {
                    return false;
                } catch (SendFailedException ex) {
                    return false;
                } catch (MessagingException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        @Override
        public String toString() {
            return email + ": " + (helo == null ? ip : helo + " [" + ip + "]")
                    + (getSender() == null ? "" : " " + getSender())
                    + " " + getQualifierName() + " > " + recipient + " = " + result;
        }
    }
}
