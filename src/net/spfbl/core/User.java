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
import com.sun.mail.smtp.SMTPSendFailedException;
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
import java.util.ConcurrentModificationException;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
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
import net.spfbl.data.Abuse;
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
    private TimeZone timezone;
    private boolean usingHeader = false;
    private boolean supressClearBLOCK = false;

    /**
     * Atributos para OTP.
     */
    private String otp_secret = null; // Chave oficial.
    private String otp_transition = null; // Chave de transição.
    private byte otp_fail = 0;
    private Integer otp_sucess = null;
    private long otp_last = 0;
    
    private User(User other) {
        this.email = other.email;
        this.name = other.name;
        this.locale = other.locale;
        this.timezone = other.timezone;
        this.usingHeader = other.usingHeader;
        this.supressClearBLOCK = other.supressClearBLOCK;
        this.otp_secret = other.otp_secret;
        this.otp_transition = other.otp_transition;
        this.otp_fail = other.otp_fail;
        this.otp_sucess = other.otp_sucess;
        this.otp_last = other.otp_last;
        this.queryMap = other.cloneQueryMap();
    }
    
    private User(String email, String name) throws ProcessException {
        if (Domain.isValidEmail(email) && simplify(name) != null) {
            this.email = email.toLowerCase();
            this.name = simplify(name);
            this.locale = Core.getDefaultLocale(email);
            this.timezone = TimeZone.getDefault();
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
    
    /**
     * Change locale of user.
     * @param token locale pattern.
     * @return true if value was changed.
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
    
    /**
     * Change timezone of user.
     * @param token timezone pattern.
     * @return true if value was changed.
     */
    public boolean setTimeZone(String token) {
        if (token == null) {
            return false;
        } else {
            TimeZone newTimeZone = TimeZone.getTimeZone(token);
            if (newTimeZone == null) {
                return false;
            } else if (newTimeZone.equals(this.timezone)) {
                return false;
            } else {
                this.timezone = newTimeZone;
                return CHANGED = true;
            }
        }
    }
    
    public boolean setSupressClearBLOCK(boolean supress) {
        if (this.supressClearBLOCK == supress) {
            return false;
        } else {
            this.supressClearBLOCK = supress;
            return CHANGED = true;
        }
    }
    
    public boolean canClearBLOCK() {
        return !supressClearBLOCK;
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
    
    public TimeZone getTimeZone() {
        return timezone;
    }
    
    private Date getDate(String text) {
        return getDate(text, null);
    }
    
    private Date getDate(String text, Date defaultDate) {
        if (text == null) {
            return defaultDate;
        } else if (text.length() == 0) {
            return defaultDate;
        } else {
            try {
                DateFormat dateFormat = DateFormat.getDateInstance(DateFormat.SHORT, locale);
                dateFormat.setTimeZone(timezone);
                return dateFormat.parse(text);
            } catch (ParseException ex) {
                return defaultDate;
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
        long threshold = System.currentTimeMillis() - 604800000L;
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
    
    private static final int QUERY_MAX = 512;
    
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
     * Set of know recipients. Active when not null.
     */
    private TreeSet<String> recipientSet = null;
    
    public synchronized Boolean containsRecipient(String recipient) {
        if (recipient == null) {
            return false;
        } else if (recipientSet == null) {
            return null;
        } else {
            return recipientSet.contains(recipient);
        }
    }
    
    protected synchronized boolean clearRecipient() {
        if (recipientSet == null) {
            return false;
        } else {
            recipientSet.clear();
            recipientSet = null;
            return true;
        }
    }

    protected boolean addRecipient(String client, String address) {
        if (address == null) {
            return false;
        } else if (Domain.isValidEmail(address = address.toLowerCase())) {
            Trap.dropSafe(client, address);
            if (addRecipient(address)) {
                return CHANGED = true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    
    private synchronized boolean addRecipient(String address) {
        if (recipientSet == null) {
            recipientSet = new TreeSet<>();
        }
        return recipientSet.add(address);
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
    
    public synchronized static TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
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
    
    public synchronized static User clone(String email) {
        if (email == null) {
            return null;
        } else {
            User user = MAP.get(email);
            return new User(user);
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
    
    public static HashMap<String,User> cloneMap() {
        HashMap<String,User> map = new HashMap<>();
        for (String key : keySet()) {
            User user = clone(key);
            map.put(key, user);
        }
        return map;
    }
    
    protected static void autoInductionWhiteKey() {
        try {
            Server.logTrace("starting auto whiteKey.");
            Connection connection = Core.newConnectionMySQL();
            if (connection != null) {
                try {
                    for (User user : User.getSet()) {
                        long begin = System.currentTimeMillis();
                        String command = "SELECT whiteKey\n"
                                + "FROM user_query\n"
                                + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 3456000) * 1000)\n"
                                + "AND user = '" + user.getEmail() + "'\n"
                                + "GROUP BY whiteKey\n"
                                + "HAVING MAX(result * 1) = 2\n"
                                + "AND COUNT(*) > 32\n"
                                + "AND STD(time) / 86400000 > 7";
                        try {
                            Statement statement = connection.createStatement();
                            statement.setQueryTimeout(600);
                            ResultSet rs = statement.executeQuery(command);
                            while (rs.next()) {
                                String whiteKey = rs.getString(1);
                                if (White.addExact(user, whiteKey)) {
                                    Server.logDebug("new WHITE '" + user.getEmail() + ":" + whiteKey + "' added by 'RECURRENCE'.");
                                }
                            }
                        } catch (MySQLTimeoutException ex) {
                            Server.logMySQL(begin, command, ex);
                        }
                    }
                } finally {
                    connection.close();
                    Server.logMySQL("connection closed.");
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logTrace("finished auto whiteKey.");
        }
    }
    
    protected static void autoInductionBlockKey() {
        try {
            Server.logTrace("starting auto blockKey.");
            Connection connection = Core.newConnectionMySQL();
            if (connection != null) {
                try {
                    for (User user : User.getSet()) {
                        long begin = System.currentTimeMillis();
                        String command = "SELECT whiteKey, blockKey\n"
                                + "FROM user_query\n"
                                + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 3456000) * 1000)\n"
                                + "AND user = '" + user.getEmail() + "'\n"
                                + "GROUP BY whiteKey, blockKey\n"
                                + "HAVING MIN(result * 1) BETWEEN 3 AND 12\n"
                                + "AND MAX(result * 1) > 6\n"
                                + "AND COUNT(*) > 32\n"
                                + "AND STD(time) / 86400000 > 7";
                        try {
                            Statement statement = connection.createStatement();
                            statement.setQueryTimeout(600);
                            ResultSet rs = statement.executeQuery(command);
                            while (rs.next()) {
                                String whiteKey = rs.getString(1);
                                String blockKey = rs.getString(2);
                                boolean white = White.containsExtact(user, whiteKey);
                                if (!white && Block.addExact(user, blockKey)) {
                                    Server.logDebug("new BLOCK '" + user.getEmail() + ":" + blockKey + "' added by 'RECURRENCE'.");
                                }
                            }
                        } catch (MySQLTimeoutException ex) {
                            Server.logMySQL(begin, command, ex);
                        }
                    }
                } finally {
                    connection.close();
                    Server.logMySQL("connection closed.");
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logTrace("finished auto blockKey.");
        }
    }
    
    public static void autoInductionBlockSMTP() {
        try {
            Server.logTrace("starting auto block SMTP.");
            Connection connection = Core.newConnectionMySQL();
            if (connection != null) {
                try {
                    for (User user : User.getSet()) {
                        if (user.isUsingHeader()) {
                            TreeMap<String,BinomialDistribution> binomialMap = new TreeMap<>();
                            TreeMap<String,Long> beginMap = new TreeMap<>();
                            TreeMap<String,Long> endMap = new TreeMap<>();
                            String userEmail = user.getEmail();
                            long time = System.currentTimeMillis();
                            String command = "SELECT ip, sender, "
                                    + "IF(hostname = '', null, hostname) AS hostname, "
                                    + "qualifier, recipient,\n"
                                    + "SUM((result * 1) < 3) AS ham,\n"
                                    + "SUM((result * 1) > 6) AS spam,\n"
                                    + "MIN(time) AS begin,\n"
                                    + "MAX(time) AS end\n"
                                    + "FROM user_query\n"
                                    + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 7776000) * 1000)\n"
                                    + "AND user = '" + userEmail + "'\n"
                                    + "GROUP BY ip, sender, hostname, qualifier, recipient";
                            try {
                                Statement statement = connection.createStatement();
                                statement.setQueryTimeout(600);
                                ResultSet rs = statement.executeQuery(command);
                                while (rs.next()) {
                                    String ip = rs.getString("ip");
                                    String sender = rs.getString("sender");
                                    String hostname = rs.getString("hostname");
                                    String qualifier = rs.getString("qualifier");
                                    String recipient = rs.getString("recipient");
                                    int ham = rs.getInt("ham");
                                    int spam = rs.getInt("spam");
                                    long begin = rs.getLong("begin");
                                    long end = rs.getLong("end");
                                    String blockKey = Block.keySMTP(
                                            userEmail, ip, sender,
                                            hostname, qualifier, recipient
                                    );
                                    BinomialDistribution distribution = binomialMap.get(blockKey);
                                    if (distribution == null) {
                                        distribution = new BinomialDistribution();
                                        binomialMap.put(blockKey, distribution);
                                    }
                                    distribution.addFailure(ham);
                                    distribution.addSucess(spam);
                                    Long beginMin = beginMap.get(blockKey);
                                    if (beginMin == null || begin < beginMin) {
                                        beginMap.put(blockKey, begin);
                                    }
                                    Long endMax = endMap.get(blockKey);
                                    if (endMax == null || end > endMax) {
                                        endMap.put(blockKey, end);
                                    }
                                }
                                for (String blockKey : binomialMap.keySet()) {
                                    BinomialDistribution distribution = binomialMap.get(blockKey);
                                    if (distribution.getFailure() == 0) {
                                        if (distribution.getSucess() > 32) {
                                            long beginMin = beginMap.get(blockKey);
                                            long endMax = endMap.get(blockKey);
                                            long diff = endMax - beginMin;
                                            long diffMin = Server.WEEK_TIME * 3;
                                            if (diff > diffMin && Block.addExact(blockKey)) {
                                                Server.logDebug("new BLOCK '" + blockKey + "' added by 'RECURRENCE'.");
                                            }
                                        }
                                    }
                                }
                            } catch (MySQLTimeoutException ex) {
                                Server.logMySQL(time, command, ex);
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        }
                    }
                } finally {
                    connection.close();
                    Server.logMySQL("connection closed.");
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logTrace("finished auto block SMTP.");
        }
    }
    
    private static ArrayList<String[]> getHREFInductionList(User user) {
        if (user == null) {
            return null;
        } else if (user.isUsingHeader()) {
            try {
                Connection connection = Core.newConnectionMySQL();
                if (connection == null) {
                    return null;
                } else {
                    long begin = System.currentTimeMillis();
                    String command = "SELECT whiteKey, blockKey, linkMap FROM user_query\n"
                            + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 3456000) * 1000)\n"
                            + "AND user = '" + user.getEmail() + "'\n"
                            + "AND linkMap IS NOT NULL\n"
                            + "ORDER BY time DESC\n"
                            + "LIMIT 100000";
                    try {
                        ArrayList<String[]> rowList = new ArrayList<>();
                        try (Statement statement = connection.createStatement()) {
                            statement.setQueryTimeout(600);
                            ResultSet rs = statement.executeQuery(command);
                            while (rs.next()) {
                                String[] queryRow = new String[3];
                                queryRow[0] = rs.getString(1);
                                queryRow[1] = rs.getString(2);
                                queryRow[2] = rs.getString(3);
                                rowList.add(queryRow);
                            }
                            return rowList;
                        } catch (SQLException ex) {
                            Server.logMySQL(begin, command, ex);
                            return null;
                        } catch (Exception ex) {
                            Server.logError(ex);
                            return null;
                        }
                    } finally {
                        connection.close();
                        Server.logMySQL("connection closed.");
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        } else {
            return null;
        }
    }
    
    protected static void autoInductionHREF() {
        Server.logTrace("starting auto block HREF.");
        TreeSet<String> adminTokenSet = new TreeSet<>();
        TreeSet<String> userTokenSet = new TreeSet<>();
        TreeMap<String,TreeSet<String>> ipMap = new TreeMap<>();
        TreeMap<String,BinomialDistribution> binomialMap = new TreeMap<>();
        for (User user : User.getSet()) {
            ArrayList<String[]> queryList = getHREFInductionList(user);
            if (queryList != null) {
                for (String[] queryRow : queryList) {
                    String whiteKey = queryRow[0];
                    String blockKey = queryRow[1];
                    String linkMap = queryRow[2];
                    boolean white = White.containsExtact(user, whiteKey);
                    boolean block = !white && Block.containsExact(user, blockKey);
                    if (white || block) {
                        TreeMap<String,Boolean> map = Core.getTreeMapBoolean(linkMap, ";");
                        TreeSet<String> expandedSet = new TreeSet<>();
                        for (String link : map.keySet()) {
                            if (Core.isSignatureURL(link)) {
                                link = Core.getSignatureHostnameURL(link);
                            }
                            if (!Ignore.contains(link)) {
                                String ownerID = null;
                                String generic = null;
                                if (Subnet.isValidIP(link)) {
                                    expandedSet.add("HREF=" + link);
                                } else if (link.contains("@")) {
                                    expandedSet.add("HREF=" + link);
                                    String host = Domain.extractHost(link, true);
                                    if (!Provider.containsMX(host)) {
                                        expandedSet.add("HREF=" + host);
                                        expandedSet.add("HREF=" + Domain.extractDomainSafeNotNull(link, true));
                                        expandedSet.add("HREF=" + Domain.extractTLDSafeNotNull(link, true));
                                        ownerID = Domain.getOwnerID(link);
                                    }
                                } else if ((generic = Generic.findGenericSoft(link)) != null) {
                                    while (generic.contains("#") || generic.contains(".H.")) {
                                        int index = generic.indexOf('.', 1);
                                        if (index == -1) {
                                            generic = null;
                                            break;
                                        } else {
                                            generic = generic.substring(index);
                                        }
                                    }
                                    if (generic != null) {
                                        expandedSet.add("HREF=" + generic);
                                    }
                                } else if (ipMap.containsKey(link)) {
                                    expandedSet.add("HREF=." + link);
                                    expandedSet.add("HREF=" + Domain.extractDomainSafeNotNull(link, true));
                                    expandedSet.add("HREF=" + Domain.extractTLDSafeNotNull(link, true));
                                    for (String ip : ipMap.get(link)) {
                                         expandedSet.add("HREF=" + ip);
                                    }
                                    ownerID = Domain.getOwnerID(link);
                                } else {
                                    expandedSet.add("HREF=." + link);
                                    expandedSet.add("HREF=" + Domain.extractDomainSafeNotNull(link, true));
                                    expandedSet.add("HREF=" + Domain.extractTLDSafeNotNull(link, true));
                                    ipMap.put(link, Reverse.getAddressSetSafe(link));
                                    for (String ip : ipMap.get(link)) {
                                         expandedSet.add("HREF=" + ip);
                                    }
                                    ownerID = Domain.getOwnerID(link);
                                }
                                if (ownerID != null) {
                                    expandedSet.add("HREF=" + ownerID);
                                }
                            }
                        }
                        for (String token : expandedSet) {
                            for (int i = 0; i < 2; i++) {
                                BinomialDistribution distribution = binomialMap.get(token);
                                if (distribution == null) {
                                    distribution = new BinomialDistribution();
                                    binomialMap.put(token, distribution);
                                }
                                if (white) {
                                    distribution.addFailure();
                                } else if (block) {
                                    distribution.addSucess();
                                }
                                if (i == 0) {
                                    adminTokenSet.add(token);
                                    token = user.getEmail() + ":" + token;
                                    userTokenSet.add(token);
                                }
                            }
                        }
                    }
                }
            }
        }
        TreeSet<String> blockSet = new TreeSet<>();
        for (String token : adminTokenSet) {
            if (!Domain.isOfficialTLD(token.startsWith("HREF=") ? token.substring(5) : token)) {
                BinomialDistribution distribution = binomialMap.get(token);
                if (distribution.getFailure() == 0) {
                    if (distribution.getSucess() > 32) {
                        blockSet.add(token);
                    }
                }
            }
        }
        for (String token : userTokenSet) {
            BinomialDistribution distribution = binomialMap.get(token);
            if (distribution.getFailure() == 0) {
                if (distribution.getSucess() > 2) {
                    int index = token.indexOf(':');
                    String href = token.substring(index + 1);
                    distribution = binomialMap.get(href);
                    if (distribution.getFailure() < 3) {
                        if (distribution.getSucess() > 32) {
                            blockSet.add(token);
                        }
                    }
                }
            }
        }
        for (String token : blockSet) {
            try {
                if (Block.addExact(token)) {
                    Server.logDebug("new BLOCK '" + token + "' added by 'RECURRENCE'.");
                }
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        Server.logTrace("finished auto block HREF.");
    }
    
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,User> map = getMap();
                File fileTemp = new File("./data/.user.map");
                int attempts = 3;
                while (attempts-- > 0) {
                    try (FileOutputStream outputStream = new FileOutputStream(fileTemp)) {
                        SerializationUtils.serialize(map, outputStream);
                        // Atualiza flag de atualização.
                        CHANGED = false;
                        break;
                    } catch (ConcurrentModificationException ex) {
                        if (attempts == 0) {
                            throw ex;
                        } else {
                            Thread.sleep(3000);
                        }
                    }
                }
                File file = new File("./data/user.map");
                if (!file.exists() || file.delete()) {
                    fileTemp.renameTo(file);
                    Server.logStore(time, file);
                } else {
                    Server.logError("cannot store at " + file + " because this file is used by other process.");
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static void load() {
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
                        if (user.timezone == null) {
                            user.timezone = Core.getDefaultTimeZone(user.email);
                        }
                        for (long time2 : user.getTimeSet()) {
                            Query query = user.getQuery(time2);
                            if (query.date != null && Math.abs(time2 - query.date.getTime()) > 31104000000L) {
                                query.date = null;
                            }
                            if (query.CHANGED == null) {
                                query.CHANGED = new BinarySemaphore(!query.STORED);
                            } else if (!query.STORED) {
                                query.CHANGED.release(true);
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
        if (locale == null || timezone == null) {
            return name + " <" + email + ">";
        } else {
            return name + " <" + email + "> " + locale + " " + timezone.getID();
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
    
    public TreeMap<Long,Query> getQueryMap(
            Long begin, String filter
    ) {
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        if (begin == null) {
            TreeMap<Long,Query> queryLocalMap;
            if (isAdmin()) {
                queryLocalMap = getAllQueryHeadMap(begin);
            } else {
                queryLocalMap = getQueryHeadMap(begin);
            }
            long timeRED;
            if (Core.hasMySQL()) {
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                timeRED = System.currentTimeMillis() - deferTimeRED;
            } else {
                timeRED = 0;
            }
            Entry<Long,Query> entry;
            while ((entry = queryLocalMap.pollLastEntry()) != null) {
                long time = entry.getKey();
                if (time > timeRED) {
                    Query query = entry.getValue();
                    if (filter == null) {
                        resultMap.put(time, query);
                    } else if (filter.length() == 0) {
                        resultMap.put(time, query);
                    } else if (query.matchAll(time, filter)) {
                        resultMap.put(time, query);
                    }
                } else {
                    break;
                }
            }
        }
        boolean finished = false;
        if (resultMap.isEmpty() && Core.hasMySQL()) {
            finished = true;
            Date date = null;
            String ipParam = null;
            String emailParam = null;
            String domainParam = null;
            boolean rejectedParam = false;
            boolean unsuspectedParam = false;
            boolean whitelistedParam = false;
            if (filter != null) {
                filter = filter.toLowerCase();
                StringTokenizer tokenizer = new StringTokenizer(filter, ",");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    token = token.trim();
                    date = getDate(token, date);
                    ipParam = Subnet.isValidIP(token) ? Subnet.normalizeIP(token) : ipParam;
                    if (Domain.isValidEmail(token)) {
                        emailParam = token.toLowerCase();
                    } else if (Domain.hasTLD(token)) {
                        domainParam = Domain.normalizeHostname(token, true);
                    }
                    switch (token) {
                        case "rejeitada": case "rejeitado": case "rejected":
                        case "rejeitadas": case "rejeitados": case "rejecteds":
                            rejectedParam = true;
                            break;
                        case "retida": case "retido": case "hold": case "holding":
                        case "retidas": case "retidos": case "holds": case "detained":
                            return new TreeMap<>();
                        case "atrasada": case "atrasado": case "delayed":
                        case "atrasadas": case "atrasados":
                            return new TreeMap<>();
                        case "insuspeita": case "insuspeito": case "unsuspected":
                        case "insuspeitas": case "insuspeitos":
                            unsuspectedParam = true;
                            break;
                        case "confiavel": case "confiaveis": case "whitelisted":
                        case "confiável": case "confiáveis":
                            whitelistedParam = true;
                    }
                }
            }
            long end;
            if (date == null) {
                if (begin == null) {
                    finished = false;
                    end = System.currentTimeMillis() - 1814400000L;
                } else if (emailParam == null) {
                    end = begin - 1814400000L;
                } else {
                    end = begin - 1814400000L;
                }
            } else if (begin == null) {
                end = date.getTime();
                begin = end + 86400000L;
            } else {
                end = date.getTime();
            }
            String command = "SELECT * FROM user_query\n"
                    + (begin == null ? "WHERE time > " + end + "\n"
                    : "WHERE time BETWEEN " + end + " AND " + begin + "\n")
                    + (isAdmin() ? "" : "AND user = '" + getEmail() + "'\n")
                    + (rejectedParam ? "AND result IN('BLOCK','REJECT')\n" : "")
                    + (unsuspectedParam ? "AND result = 'ACCEPT'\n" : "")
                    + (whitelistedParam ? "AND result = 'WHITE'\n" : "")
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
                    + "LIMIT " + (domainParam == null ? 64 : 32);
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
                                    Query query = getQuery(time);
                                    if (query == null) {
                                        query = new Query(rs);
                                    }
                                    putQuery(time, query);
                                    resultMap.put(time, query);
                                    finished = false;
                                } catch (Exception ex) {
                                    Server.logError(ex);
                                }
                            }
                        } catch (MySQLTimeoutException ex) {
                            Server.logMySQL(beginTime, command, ex);
                            return null;
                        } catch (SQLException ex) {
                            Server.logError(ex);
                        }
                    } finally {
                        connection.close();
                        Server.logMySQL("connection closed.");
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (!finished) {
            if (resultMap.isEmpty()) {
                resultMap.put(System.currentTimeMillis(), null);
            } else {
                long firstKey = resultMap.firstKey();
                resultMap.put(firstKey - 1, null);
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
    
    public static Query getUserQuery(ResultSet rs) throws SQLException {
        User user = User.get(rs.getString("user"));
        if (user == null) {
            return null;
        } else {
            return user.getQuery(rs);
        }
    }
    
    private Query getQuery(ResultSet rs) throws SQLException {
        return new Query(rs);
    }
    
    public static Query getAnyQuery(long time) {
        for (User user : User.getSet()) {
            Query query = user.getQuery(time);
            if (query != null) {
                return query;
            }
        }
        if (Core.hasMySQL()) {
            long time2 = System.currentTimeMillis();
            String command = "SELECT * FROM user_query\n"
                    + "WHERE time = " + time;
            Connection connection = Core.aquireConnectionMySQL();
            if (connection != null) {
                try {
                    try (Statement statement = connection.createStatement()) {
                        statement.setQueryTimeout(3);
                        ResultSet rs = statement.executeQuery(command);
                        if (rs.next()) {
                            String email = rs.getString("user");
                            User user = User.get(email);
                            if (user == null) {
                                Server.logMySQL(time2, command, "NOT FOUND");
                            } else {
                                Query query = user.getQuery(rs);
                                Server.logMySQL(time2, command, "FOUND");
                                return query;
                            }
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
        return null;
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
                            putQuery(time, query);
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
    
    public synchronized Query cloneQuery(long time) {
        if (queryMap == null) {
            return null;
        } else {
            Query query = queryMap.get(time);
            return new Query(query);
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
    
    public TreeSet<Long> getAllTimeSet(long begin, long end) {
        TreeSet<Long> timeSet = new TreeSet<>();
        for (User user : User.getSet()) {
            timeSet.addAll(user.getTimeSet(begin, end));
        }
        return timeSet;
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
    
    private TreeMap<Long,Query> cloneQueryMap() {
        TreeMap<Long,Query> queryMap = new TreeMap<>();
        for (long time : getTimeSet()) {
            Query query = cloneQuery(time);
            queryMap.put(time, query);
        }
        return queryMap;
    }
    
    public String blockByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            long timeFound = 0;
            Query queryFound = null;
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuerySafe(time);
                if (query != null && query.isMessage(messageID)) {
                    timeFound = time;
                    queryFound = query;
                    break;
                }
            }
            if (queryFound == null && Core.hasMySQL()) {
                long time2 = System.currentTimeMillis();
                String command = "SELECT * FROM user_query\n"
                        + "WHERE time > ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP) - 604800) * 1000)\n"
                        + "AND messageID = '" + messageID + "'\n"
                        + "AND user = '" + getEmail() + "'\n"
                        + "ORDER BY time DESC\n"
                        + "LIMIT 1";
                Connection connection = Core.aquireConnectionMySQL();
                if (connection != null) {
                    try {
                        try (Statement statement = connection.createStatement()) {
                            statement.setQueryTimeout(3);
                            ResultSet rs = statement.executeQuery(command);
                            if (rs.next()) {
                                timeFound = rs.getLong("time");
                                queryFound = new Query(rs);
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
            if (queryFound == null) {
                return "MESSAGE NOT FOUND";
            } else if (queryFound.isWhiteKey() && queryFound.isGreen()) {
                if (queryFound.complain(timeFound)) {
                    return "COMPLAINED " + queryFound.getTokenSet();
                } else {
                    return "ALREADY COMPLAINED";
                }
            } else if (queryFound.hasTokenRed()) {
                if (queryFound.blockKey(timeFound)) {
                    return "BLOCKED " + queryFound.getBlockKey();
                } else if (queryFound.complain(timeFound)) {
                    return "COMPLAINED " + queryFound.getTokenSet();
                } else {
                    return "ALREADY COMPLAINED";
                }
            } else if (queryFound.blockForRecipient(timeFound)) {
                queryFound.complain(timeFound);
                return "BLOCKED " + queryFound.getBlockKey() + ">" + queryFound.getRecipient();
            } else if (queryFound.complain(timeFound)) {
                return "COMPLAINED " + queryFound.getTokenSet();
            } else {
                return "ALREADY COMPLAINED";
            }
        }
    }
    
    public String blockBySubject(String subject) {
        if (subject == null) {
            return "INVALID MESSAGE";
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
                return "INVALID MESSAGE";
            } else {
                TreeSet<String> blockKeySet = new TreeSet<>();
                TreeMap<Long,Query> queryMap = new TreeMap<>();
                for (long time : getTimeSet().descendingSet()) {
                    Query query = getQuerySafe(time);
                    if (query != null && query.isSubject(subject)) {
                        queryMap.put(time, query);
                        blockKeySet.add(query.getBlockKey());
                    }
                }
                if (blockKeySet.size() == 1) {
                    long time = queryMap.firstKey();
                    Query query = queryMap.get(time);
                    if (query.isWhiteKey() && query.isGreen()) {
                        if (query.complain(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.hasTokenRed()) {
                        if (query.blockKey(time)) {
                            return "BLOCKED " + query.getBlockKey();
                        } else if (query.complain(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.blockForRecipient(time)) {
                        query.complain(time);
                        return "BLOCKED " + query.getBlockKey() + ">" + query.getRecipient();
                    } else if (query.complain(time)) {
                        return "COMPLAINED " + query.getTokenSet();
                    } else {
                        return "ALREADY COMPLAINED";
                    }
                } else {
                    return "MESSAGE NOT FOUND";
                }
            }
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
            token = SubnetIPv6.tryTransformToIPv4(token);
            if (Subnet.isReservedIP(token)) {
                return null;
            } else {
                return Subnet.normalizeIP(token);
            }
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
    
    private static String normalizeSigner(String signer) {
        if (signer == null) {
            return null;
        } else if (Domain.isHostname(signer)) {
            return Domain.normalizeHostname(signer, false);
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
    
    private static final Semaphore warningSemaphore = new Semaphore(1);
    
//    public static void sendHoldingWarning() {
//        if (warningSemaphore.tryAcquire()) {
//            try {
//                for (User user : getSet()) {
//                    if (!Core.isRunning()) {
//                        break;
//                    } else if (user.isUsingHeader()) {
//                        TreeSet<String> whiteKeySet = new TreeSet<>();
//                        long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
//                        long deferTimeRED = Core.getDeferTimeRED() * 60000L;
//                        long deferTimeHOLD = Core.getDeferTimeHOLD() * 60000L;
//                        long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
//                        long timeAdmin = System.currentTimeMillis() - 3 * deferTimeYELLOW;
//                        long timeUser = System.currentTimeMillis() - deferTimeRED;
//                        long timeBegin = System.currentTimeMillis() - deferTimeHOLD;
//                        for (long time : user.getTimeSet(timeBegin, timeEnd)) {
//                            Query query = user.getQuery(time);
//                            if (!Core.isRunning()) {
//                                break;
//                            } else if (query != null) {
//                                if (query.isNotAdvisedUser() && query.isHoldingFull()) {
//                                    if (time < timeUser) {
//                                        String whiteKey = query.getWhiteKey();
//                                        if (!whiteKeySet.contains(whiteKey)) {
//                                            if (query.adviseUserHOLD(time)) {
//                                                whiteKeySet.add(whiteKey);
//                                            } else if (query.adviseAdminHOLD(time)) {
//                                                whiteKeySet.add(whiteKey);
//                                            }
//                                        }
//                                    } else if (!query.adviseSenderHOLD(time)) {
//                                        if (time < timeAdmin) {
//                                            query.adviseAdminHOLD(time);
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            } finally {
//                warningSemaphore.release();
//            }
//        }
//    }
    
    public static void sendHoldingWarning() {
        if (warningSemaphore.tryAcquire()) {
            try {
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long deferTimeHOLD = Core.getDeferTimeHOLD() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeUser = System.currentTimeMillis() - deferTimeRED;
                long timeBegin = System.currentTimeMillis() - deferTimeHOLD;
                TreeMap<String,TreeMap<Long,Query>> keyMap = new TreeMap<>();
                for (User user : getSet()) {
                    if (!Core.isRunning()) {
                        break;
                    } else if (user.isUsingHeader()) {
                        for (long time : user.getTimeSet(timeBegin, timeEnd)) {
                            Query query = user.getQuery(time);
                            if (!Core.isRunning()) {
                                break;
                            } else if (query != null && query.isHoldingFull()) {
                                if (query.isNotAdvisedUser()) {
                                    if (time < timeUser) {
                                        query.adviseUserHOLD(time);
                                    } else {
                                        query.adviseSenderHOLD(time);
                                    }
                                }
                                if (query.isNotAdvisedAdmin()) {
                                    String key = query.getWhiteKey() + " " + query.getBlockKey();
                                    TreeMap<Long,Query> queryMap = keyMap.get(key);
                                    if (queryMap == null) {
                                        queryMap = new TreeMap<>();
                                        keyMap.put(key, queryMap);
                                    }
                                    queryMap.put(time, query);
                                }
                            }
                        }
                    }
                }
//                int maxSize = 0;
//                long timeKey = Long.MAX_VALUE;
//                for (String key : keyMap.keySet()) {
//                    TreeMap<Long,Query> queryMap = keyMap.get(key);
//                    int size = queryMap.size();
//                    long firstTime = queryMap.firstKey();
//                    if (maxSize < size) {
//                        maxSize = size;
//                        timeKey = firstTime;
//                    } else if (maxSize == size && timeKey > firstTime) {
//                        timeKey = firstTime;
//                    }
//                }
//                for (String key : keyMap.keySet()) {
//                    TreeMap<Long,Query> queryMap = keyMap.get(key);
//                    long firstTime = queryMap.firstKey();
//                    if (!Core.isRunning()) {
//                        break;
//                    } else if (timeKey == firstTime) {
//                        User.adviseAdminHOLD(queryMap);
//                        break;
//                    }
//                }
                
                int maxSize = 0;
                long timeKey = Long.MAX_VALUE;
                TreeMap<Long,Query> resultMap = null;
                for (String key : keyMap.keySet()) {
                    TreeMap<Long,Query> queryMap = keyMap.get(key);
                    long lastTime = queryMap.lastKey();
                    if (lastTime < timeUser) {
                        int size = queryMap.size();
                        long firstTime = queryMap.firstKey();
                        if (maxSize < size) {
                            maxSize = size;
                            timeKey = firstTime;
                            resultMap = queryMap;
                        } else if (maxSize == size && timeKey > firstTime) {
                            timeKey = firstTime;
                            resultMap = queryMap;
                        }
                    }
                }
                if (resultMap != null && maxSize > 2 && Core.isRunning()) {
                    User.adviseAdminHOLD(resultMap);
                }
            } finally {
                warningSemaphore.release();
            }
        }
    }
    
    public static void sendWarningMessages() {
        for (User user : getSet()) {
            if (!Core.isRunning()) {
                break;
            } else {
                long deferTimeYELLOW = Core.getDeferTimeYELLOW() * 60000L;
                long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                long timeEnd = System.currentTimeMillis() - deferTimeYELLOW;
                long timeBegin = System.currentTimeMillis() - deferTimeRED;
                for (long time : user.getTimeSet(timeBegin, timeEnd)) {
                    Query query = user.getQuery(time);
                    if (!Core.isRunning()) {
                        break;
                    } else if (query != null) {
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
    //                            if (query.isSuspectFull()) {
    //                                query.adviseRecipientSPAM(time);
    //                            }
                            }
                        } else if (query.isResult("BLOCK")) {
                            query.adviseSenderBLOCK(time);
                            query.reportAbuse(time);
                        }
    //                    if (drop) {
    //                        // Drop from memory because 
    //                        // it was stored in MySQL.
    //                        user.dropQuery(time);
    //                    }
                    }
                }
            }
        }
    }
    
    public static void storeAndDropFinished() {
        if (Core.hasMySQL()) {
            for (User user : getSet()) {
                if (!Core.isRunning()) {
                    break;
                } else {
                    long deferTimeRED = Core.getDeferTimeRED() * 60000L;
                    long timeBegin = System.currentTimeMillis() - deferTimeRED;
                    for (long time : user.getTimeHead(timeBegin)) {
                        Query query = user.getQuery(time);
                        if (!Core.isRunning()) {
                            break;
                        } else if (query != null) {
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
    }
    
    public boolean sendTOTP() {
        return ServerHTTP.enviarOTP(locale, this);
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
    
    private static final String MYSQL_STORE_COMMAND_2_9_0 =
            "INSERT INTO user_query "
            + "(time, user, client, ip, helo, hostname, "
            + "sender, qualifier, recipient, tokenSet, "
            + "signerSet, whiteKey, blockKey, "
            + "result, mailFrom, replyto, subject, "
            + "messageID, date, unsubscribe, linkMap, "
            + "executableSet, malware, "
            + "adminAdvised, senderAdvised, recipientAdvised, "
            + "userAdvised, abuseAdvised)\n"
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE "
            + "signerSet = ?, whiteKey = ?, blockKey = ?, "
            + "result = ?, mailFrom = ?, "
            + "replyto = ?, subject = ?, messageID = ?, "
            + "date = ?, unsubscribe = ?, "
            + "linkMap = ?, executableSet = ?, malware = ?, "
            + "adminAdvised = ?, senderAdvised = ?, recipientAdvised = ?, "
            + "userAdvised = ?, abuseAdvised = ?";
    
    public static boolean storeDB() {
        try {
            long time2 = System.currentTimeMillis();
            Connection connection = Core.aquireConnectionMySQL();
            if (connection != null) {
                try {
                    try {
                        PreparedStatement statement
                                = connection.prepareStatement(
                                        MYSQL_STORE_COMMAND_2_9_0
                                );
                        try {
                            statement.setQueryTimeout(60);
                            for (User user : getSet()) {
                                for (long time : user.getTimeSet()) {
                                    Query query = user.getQuery(time);
                                    if (query != null) {
                                        if (query.storeDB_2_9_0(statement, time)) {
                                            connection.commit();
                                        } else {
                                            return false;
                                        }
                                    }
                                }
                            }
                            Server.logMySQL(time2, "user_query stored");
                        } finally {
                            statement.close();
                        }
                    } catch (SQLException ex1) {
                        try {
                            PreparedStatement statement
                                    = connection.prepareStatement(
                                            MYSQL_STORE_COMMAND_2_8_0
                                    );
                            try {
                                statement.setQueryTimeout(60);
                                for (User user : getSet()) {
                                    for (long time : user.getTimeSet()) {
                                        Query query = user.getQuery(time);
                                        if (query != null) {
                                            if (query.storeDB_2_8_0(statement, time)) {
                                                connection.commit();
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                }
                                Server.logMySQL(time2, "user_query stored");
                            } finally {
                                statement.close();
                            }
                        } catch (SQLException ex2) {
                            PreparedStatement statement
                                    = connection.prepareStatement(
                                            MYSQL_STORE_COMMAND_2_7_6
                                    );
                            try {
                                for (User user : getSet()) {
                                    for (long time : user.getTimeSet()) {
                                        Query query = user.getQuery(time);
                                        if (query != null) {
                                            if (query.storeDB_2_7_6(statement, time)) {
                                                connection.commit();
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                }
                                Server.logMySQL(time2, "user_query stored");
                            } finally {
                                statement.close();
                            }
                        }
                    }
                } finally {
                    Core.releaseConnectionMySQL();
                }
            }
            return true;
        } catch (SQLException ex) {
            Server.logError(ex);
            return false;
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
        if (!query.STORED) {
            StoreThread storeThread = getStoreThread();
            if (storeThread != null) {
                storeThread.put(time, query);
            }
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
            } else if (query.STORED) {
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
                        while (continueRun() && (entry = pollFirstEntry()) != null) {
//                            Server.logTrace("pollFirstEntry()");
                            Query query = entry.getValue();
                            long time = entry.getKey();
//                            Server.logTrace(time + " waitHeader()");
                            query.waitHeader();
//                            Server.logTrace(time + " aquireConnectionMySQL()");
                            Connection connection = Core.aquireConnectionMySQL();
                            if (connection == null) {
//                                Server.logTrace(time + " retryMap.put(time, query)");
                                put(time, query);
                            } else {
                                try {
                                    try {
                                        try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_9_0)) {
                                            statement.setQueryTimeout(60);
    //                                        Server.logTrace(time + " storeDB_2_9_0(statement, time)");
                                            if (query.storeDB_2_9_0(statement, time)) {
                                                connection.commit();
                                            }
                                        }
                                    } catch (SQLException ex1) {
                                        Server.logError(ex1);
                                        try {
                                            try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_8_0)) {
                                                statement.setQueryTimeout(60);
    //                                            Server.logTrace(time + " storeDB_2_8_0(statement, time)");
                                                if (query.storeDB_2_8_0(statement, time)) {
                                                    connection.commit();
                                                }
                                            }
                                        } catch (SQLException ex2) {
                                            Server.logError(ex2);
                                            try {
                                                try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_7_6)) {
    //                                                Server.logTrace(time + " storeDB_2_7_6(statement, time)");
                                                    if (query.storeDB_2_7_6(statement, time)) {
                                                        connection.commit();
                                                    }
                                                }
                                            } catch (SQLException ex3) {
                                                Server.logError(ex3);
                                            }
                                        }
                                    }
                                } finally {
//                                    Server.logTrace(time + " releaseConnectionMySQL()");
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
        private TreeSet<String> signerSet = null;
        private String result;
        private String from = null;
        private String replyto = null;
        private String subject = null;
        private String messageID = null;
        private Timestamp date = null;
        private URL unsubscribe = null;
        private TreeMap<String,Boolean> linkMap = null;
        private TreeSet<String> executableSet = null;
        private String malware = null;
        private byte[] body = null;
        
        private boolean adminAdvised = false;
        private boolean senderAdvised = false;
        private boolean recipientAdvised = false;
        private boolean userAdvised = false;
        private boolean abuseAdvised = false;
        
        private boolean STORED = false; // Obsoleto.
        private BinarySemaphore CHANGED; // Mudar para final depois da transição.
        
        private Query(Query other) {
            this.client = other.client;
            this.ip = other.ip;
            this.helo = other.helo;
            this.hostname = other.hostname;
            this.sender = other.sender;
            this.qualifier = other.qualifier;
            this.recipient = other.recipient;
            this.loadTokenSet(Core.getSequence(other.tokenSet, ";"));
            this.loadSignerSet(Core.getSequence(other.signerSet, ";"));
            this.result = other.result;
            this.from = other.from;
            this.replyto = other.replyto;
            this.subject = other.subject;
            this.messageID = other.messageID;
            this.date = other.date;
            this.unsubscribe = other.unsubscribe;
            this.loadLinkMap(Core.getSequence(other.linkMap, ";", 65535));
            this.loadExecutableSet(Core.getSequence(other.executableSet, ";"));
            this.malware = other.malware;
            this.body = other.body;
            this.adminAdvised = other.adminAdvised;
            this.senderAdvised = other.senderAdvised;
            this.recipientAdvised = other.recipientAdvised;
            this.userAdvised = other.userAdvised;
            this.abuseAdvised = other.abuseAdvised;
            this.STORED = other.STORED;
            this.CHANGED = other.CHANGED.duplicate();
        }
        
        private Query(ResultSet rs) throws SQLException {
            this.client = rs.getString("client");
            this.ip = rs.getString("ip");
            this.helo = rs.getString("helo");
            this.hostname = rs.getString("hostname");
            this.sender = rs.getString("sender");
            this.qualifier = SPF.Qualifier.get(rs.getString("qualifier"));
            this.recipient = rs.getString("recipient");
            this.loadTokenSet(rs.getString("tokenSet"));
            this.loadSignerSet(rs.getString("signerSet"));
            this.result = rs.getString("result");
            this.from = rs.getString("mailFrom");
            this.replyto = rs.getString("replyto");
            this.subject = rs.getString("subject");
            this.messageID = rs.getString("messageID");
            this.date = rs.getTimestamp("date");
            this.unsubscribe = Core.getURL(rs.getString("unsubscribe"));
            this.loadLinkMap(rs.getString("linkMap"));
            this.loadExecutableSet(rs.getString("executableSet"));
            this.malware = rs.getString("malware");
//            this.body = rs.getBytes("body");
            this.adminAdvised = rs.getBoolean("adminAdvised");
            this.senderAdvised = rs.getBoolean("senderAdvised");
            this.recipientAdvised = rs.getBoolean("recipientAdvised");
            this.userAdvised = rs.getBoolean("userAdvised");
            this.abuseAdvised = rs.getBoolean("abuseAdvised");
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
        
        private boolean loadSignerSet(String text) {
            TreeSet<String> set = Core.getTreeSet(text, ";");
            if (set == null) {
                return false;
            } else if (signerSet == null) {
                signerSet = set;
                return true;
            } else {
                signerSet.addAll(set);
                return true;
            }
        }
        
        private boolean loadExecutableSet(String text) {
            TreeSet<String> set = Core.getTreeSet(text, ";");
            if (set == null) {
                return false;
            } else if (executableSet == null) {
                executableSet = set;
                return true;
            } else {
                executableSet.addAll(set);
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
        
//        public String createComplainTicket(long time) throws ProcessException {
//            String ticket = "complain " + getUserEmail();
//            byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
//            byteArray[0] = (byte) (time & 0xFF);
//            byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
//            byteArray[7] = (byte) ((time >>> 8) & 0xFF);
//            return Server.encryptURLSafe(byteArray);
//        }
        
        private boolean storeDB(long time) {
            try {
                Connection connection = Core.aquireConnectionMySQL();
                if (connection == null) {
                    return false;
                } else {
                    try {
                        try {
                            try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_9_0)) {
                                statement.setQueryTimeout(60);
                                if (storeDB_2_9_0(statement, time)) {
                                    connection.commit();
                                    return true;
                                } else {
                                    return false;
                                }
                            }
                        } catch (SQLException ex1) {
                            try {
                                try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_8_0)) {
                                    statement.setQueryTimeout(60);
                                    if (storeDB_2_8_0(statement, time)) {
                                        connection.commit();
                                        return true;
                                    } else {
                                        return false;
                                    }
                                }
                            } catch (SQLException ex2) {
                                try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_7_6)) {
                                    if (storeDB_2_7_6(statement, time)) {
                                        connection.commit();
                                        return true;
                                    } else {
                                        return false;
                                    }
                                }
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
//                Server.logTrace(time + " storing.");
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
//                    Server.logTrace(time + " executing.");
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
//                Server.logTrace(time + " not stored.");
                return true;
            }
        }
        
        private boolean storeDB_2_8_0(PreparedStatement statement, long time) {
            if (this.CHANGED.acquireIf(true)) {
//                Server.logTrace(time + " storing.");
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
//                    Server.logTrace(time + " executing.");
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
//                Server.logTrace(time + " not stored.");
                return true;
            }
        }
        
        private boolean storeDB_2_9_0(PreparedStatement statement, long time) {
            if (this.CHANGED.acquireIf(true)) {
//                Server.logTrace(time + " storing.");
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
                    statement.setString(11, Core.getSequence(signerSet, ";"));
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
                    statement.setString(22, Core.getSequence(executableSet, ";"));
                    statement.setString(23, malware);
                    statement.setBoolean(24, adminAdvised);
                    statement.setBoolean(25, senderAdvised);
                    statement.setBoolean(26, recipientAdvised);
                    statement.setBoolean(27, userAdvised);
                    statement.setBoolean(28, abuseAdvised);
                    statement.setString(29, Core.getSequence(signerSet, ";"));
                    statement.setString(30, whiteKey);
                    statement.setString(31, blockKey);
                    statement.setString(32, result);
                    statement.setString(33, from);
                    statement.setString(34, replyto);
                    statement.setString(35, subject);
                    statement.setString(36, messageID);
                    statement.setTimestamp(37, date);
                    statement.setString(38, getUnsubscribeString());
                    statement.setString(39, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(40, Core.getSequence(executableSet, ";"));
                    statement.setString(41, malware);
                    statement.setBoolean(42, adminAdvised);
                    statement.setBoolean(43, senderAdvised);
                    statement.setBoolean(44, recipientAdvised);
                    statement.setBoolean(45, userAdvised);
                    statement.setBoolean(46, abuseAdvised);
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
//                Server.logTrace(time + " not stored.");
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
        
        public boolean hasDynamicIP() {
            return Generic.isDynamicIP(ip);
        }
        
        public boolean hasQualifiedIP() {
            return Generic.isQualifiedIP(ip);
        }
        
        public String getCIDR() {
            if (ip.contains(":")) {
                return SubnetIPv6.normalizeCIDRv6(ip + "/64");
            } else {
                return ip + "/32";
            }
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
            String fromLocal = getHeaderFrom();
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
        
        public String getRecipientDomain(boolean pontuacao) {
            String recipientLocal = getRecipient();
            if (recipientLocal == null) {
                return null;
            } else if (pontuacao) {
                int index = recipientLocal.indexOf('@');
                return recipientLocal.substring(index);
            } else {
                int index = recipientLocal.indexOf('@');
                return recipientLocal.substring(index + 1);
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
        
        private boolean containsSigner(String domain) {
            if (domain == null) {
                return false;
            } else if (signerSet == null) {
                return false;
            } else {
                return signerSet.contains(domain);
            }
        }
        
        private boolean isSigned(String address) {
            if (address == null) {
                return false;
            } else {
                int index = address.indexOf('@');
                String domain = address.substring(index + 1);
                if (containsSigner(domain)) {
                    return true;
                } else if (isPass() && getMailFrom().endsWith('@' + domain)) {
                    return true;
                } else if ((domain = Domain.extractDomainSafe(domain, false)) == null) {
                    return false;
                } else {
                    return containsSigner(domain);
                }
            }
        }
        
        public String getReplyToValid() {
            if (isSigned(replyto) && Domain.isValidEmail(replyto) && !NoReply.contains(replyto, true)) {
                return replyto;
            } else if (isSigned(from) && Domain.isValidEmail(from) && !NoReply.contains(from, true)) {
                return from;
            } else if (isPass() && Domain.isValidEmail(sender) && !NoReply.contains(sender, true)) {
                return sender;
            } else if (isSigned(sender) && Domain.isValidEmail(sender) && !NoReply.contains(sender, true)) {
                return sender;
            } else {
                return null;
            }
        }
        
        public String getSender() {
            if (isSigned(from) && Domain.isValidEmail(from)) {
                return from;
            } else if (isSigned(replyto) && Domain.isValidEmail(replyto)) {
                return replyto;
            } else if (sender == null) {
                return from == null ? replyto : from;
            } else if (Provider.containsMX(sender) && Domain.isValidEmail(sender)) {
                return sender;
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
            String trueSender = getSender();
            if (trueSender == null) {
                return "NONE";
            } else if (isSigned(trueSender)) {
                return "PASS";
            } else if (qualifier == null) {
                return "NONE";
            } else if (trueSender.equals(sender)) {
                return qualifier.name();
            } else {
                return "NONE";
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
            String senderLocal = getSender();
            if (senderLocal == null) {
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
        
        public boolean isHeaderFrom(String from) {
            if (from == null) {
                return this.from == null;
            } else {
                return from.equals(this.from);
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
        
        public boolean isSubject(String subject) {
            if (subject == null || subject.length() == 0) {
                return false;
            } else if (subject.equals(this.subject)) {
                return true;
            } else if (subject.startsWith("Fw: ")) {
                return subject.substring(4).equals(this.subject);
            } else if (subject.startsWith("Fwd: ")) {
                return subject.substring(5).equals(this.subject);
            } else {
                return false;
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
        
        public boolean isBlockSMTP() {
            String blockKey = Block.keySMTP(
                    User.this.getEmail(), getIP(), getMailFrom(),
                    getValidHostname(), getQualifierName(), getRecipient()
            );
            if (Block.containsExact(blockKey)) {
                return true;
            } else {
                blockKey = Block.keySMTP(
                        User.this.getEmail(), getIP(),
                        getValidHostname(), getRecipientDomain(true)
                );
                return Block.containsExact(blockKey);
            }
        }
        
        public boolean isBlockKey() {
            String blockKey = getBlockKey();
            return Block.containsExact(User.this, blockKey);
        }
        
        public boolean isBlockKeyByAdmin() {
            String email = Core.getAdminEmail();
            if (email == null) {
                return false;
            } else {
                String blockKey = getBlockKey();
                return Block.containsExact(email, blockKey);
            }
        }
        
        public TreeSet<String> getAllBlockKeys() {
            TreeSet<String> keySet = new TreeSet<>();
            keySet.add(getBlockKey());
            for (String link : getLinkKeySet()) {
                if (link.equals(getUserEmail())) {
                    // Do nothing.
                } else if (link.equals(getRecipient())) {
                    // Do nothing.
                } else if (Ignore.contains(link)) {
                    // Do nothing.
                } else if (Provider.contains(link)) {
                    // Do nothing.
                } else if (Core.isSignatureURL(link)) {
                    keySet.add(link);
                } else if (Domain.isHostname(link)) {
                    keySet.add("HREF=." + link);
                } else {
                    keySet.add("HREF=" + link);
                }
            }
            keySet.addAll(getExecutableSet());
            return keySet;
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
        
        public boolean isWhiteKeyByAdmin() {
            String email = Core.getAdminEmail();
            if (email == null) {
                return false;
            } else {
                String whiteKey = getWhiteKey();
                return White.containsExtact(email, whiteKey);
            }
        }
        
        public String getWhiteKey() {
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
            if (!isToAbuse()) {
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
                if (sender == null) {
                    try {
                        White.clear(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                } else {
                    try {
                        White.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(sender)) {
                    try {
                        White.clear(null, User.this, ip, sender, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (from != null) {
                    try {
                        White.clear(null, User.this, ip, from, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(from)) {
                    try {
                        White.clear(null, User.this, ip, from, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (replyto != null) {
                    try {
                        White.clear(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(replyto)) {
                    try {
                        White.clear(null, User.this, ip, replyto, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                try {
                    White.clear(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
                } catch (ProcessException ex) {
                    Server.logError(ex);
                }
            }
        }
        
        public void clearBlock() {
            if (canClearBLOCK() && !isFromReserved() && !isToReserved() && !NoReply.contains(getSender(), true)) {
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
                if (sender == null) {
                    try {
                        Block.clear(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                } else {
                    try {
                        Block.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(sender)) {
                    try {
                        Block.clear(null, User.this, ip, sender, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (from != null) {
                    try {
                        Block.clear(null, User.this, ip, from, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(from)) {
                    try {
                        Block.clear(null, User.this, ip, from, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (replyto != null) {
                    try {
                        Block.clear(null, User.this, ip, replyto, getValidHostname(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(replyto)) {
                    try {
                        Block.clear(null, User.this, ip, replyto, getValidHostname(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (linkMap != null) {
                    for (String link : linkMap.keySet()) {
                        if (Core.isSignatureURL(link)) {
                            Block.dropExact(link);
                            link = Core.getSignatureHostURL(link);
                        }
                        Block.clearHREF(User.this, link, email);
                    }
                }
            }
        }
        
        public String getBlockSender() {
            Situation situation;
            String senderLocal = getSender();
            if (senderLocal == null) {
                return null;
            } else if (isSigned(senderLocal)) {
                situation = Situation.AUTHENTIC;
            } else if (senderLocal.equals(sender)) {
                situation = getSituation(true);
            } else {
                situation = Situation.NONE;
            }
            switch (situation) {
                case AUTHENTIC:
                    return getSenderSimplified(true, true);
                case NONE:
                    String domain1 = getOriginDomain(false);
                    if (domain1 == null) {
                        return getSenderSimplified(true, true) + ";NONE";
                    } else {
                        return getSenderSimplified(true, true) + ";" + domain1;
                    }
                case ZONE:
                    String domain2 = getOriginDomain(false);
                    if (domain2 == null) {
                        return getSenderDomain(true) + ";NOTPASS";
                    } else {
                        return getSenderDomain(true) + ";" + domain2;
                    }
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
                    String domain3 = getOriginDomain(false);
                    if (domain3 == null) {
                        return "mailer-daemon@;" + getIP();
                    } else {
                        return "mailer-daemon@" + domain3;
                    }
                default:
                    return null;
            }
        }
        
        public void blockExecutables() {
            try {
                if (executableSet != null) {
                    for (String signature : executableSet) {
                        if (!Ignore.containsExact(getEmail() + ":" + signature)) {
                            if (Block.addExact(signature)) {
                                Server.logDebug("new BLOCK '" + signature + "' added by 'EXECUTABLE'.");
                                Peer.sendBlockToAll(signature);
                            }
                        }
                    }
                }
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        
        public void blockShortnersAndIPs() {
            try {
                if (linkMap != null) {
                    for (String link : linkMap.keySet()) {
                        if (Subnet.isValidIP(link)) {
                            if (Block.addExact("HREF=" + link)) {
                                Server.logDebug("new BLOCK 'HREF=" + link + "' added by 'SUSPECT'.");
                            }
                        } else {
                            String url = Core.getSignatureRootURL(link);
                            if (Core.isShortenerURL(url)) {
                                if (Block.addExact(link)) {
                                    Server.logDebug("new BLOCK '" + link + "' added by 'SUSPECT'.");
                                    Peer.sendBlockToAll(link);
                                }
                            }
                        }
                    }
                }
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        
        public boolean blockKey(long time) {
            try {
                clearWhite();
                complain(time);
                blockExecutables();
                blockShortnersAndIPs();
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
        
        public boolean isBlockedForRecipient() {
            if (recipient == null) {
                return false;
            } else {
                return Block.containsExact(
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
                        return Block.add(User.this, getSenderSimplified(true, true));
                    case NONE:
                        String domain1 = this.getOriginDomain(false);
                        if (domain1 == null) {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";NONE");
                        } else {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";" + domain1);
                        }
                    case ZONE:
                        String domain2 = this.getOriginDomain(false);
                        if (domain2 == null) {
                            return Block.add(User.this, getSenderDomain(true) + ";NOTPASS");
                        } else {
                            return Block.add(User.this, getSenderDomain(true) + ";" + domain2);
                        }
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
                        String domain3 = this.getOriginDomain(false);
                        if (domain3 == null) {
                            return Block.addExact(getUserEmail() + ":mailer-daemon@;" + getIP());
                        } else {
                            return Block.addExact(getUserEmail() + ":mailer-daemon@" + domain3);
                        }
                    case RECIPIENT:
                        String recipientAddr = getRecipient();
                        if (recipientAddr == null) {
                            return false;
                        } else {
                            boolean removed = removeRecipient();
                            boolean added = Trap.addInexistent(User.this, recipientAddr);
                            return removed || added;
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
            } else if (isSigned(senderLocal)) {
                situation = Situation.AUTHENTIC;
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
                                boolean added = addRecipient();
                                boolean removed = Trap.clear(getClientEmailSet(), User.this, recipientAddr);
                                return added || removed;
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
        
        public boolean hasMalwareNotIgnored() {
            if (malware == null) {
                return false;
            } else if (Ignore.containsExact(getEmail() + ":MALWARE=" + malware)) {
                return false;
            } else {
                return true;
            }
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
            } else if (isAnyLinkBLOCK(true)) {
                return false;
            } else if (isUsingHeader()) {
                return hasSubject();
            } else {
                return true;
            }
        }
        
        public boolean isSuspectFull() {
            if (!isResult("ACCEPT")) {
                return false;
            } else if (!hasSubject()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (hasTokenRed()) {
                return true;
            } else if (isAnyLinkSuspect()) {
                return true;
            } else if (isSubjectSuspect()) {
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
        
        public boolean isUserAdvised() {
            return userAdvised;
        }
        
        public boolean isAbuseAdvised() {
            return abuseAdvised;
        }
        
        public boolean isNotAdvised() {
            return !senderAdvised && !recipientAdvised && !adminAdvised && !userAdvised;
        }
        
        public boolean isNotAdvisedLocal() {
            return !recipientAdvised && !adminAdvised && !userAdvised;
        }
        
        public boolean isNotAdvisedAdmin() {
            return !adminAdvised;
        }
        
        public boolean isNotAdvisedUser() {
            return !userAdvised;
        }
        
        public boolean isNotAdvisedAbuse() {
            return !abuseAdvised;
        }
        
        public boolean isWhite() {
            return getWhite() != null;
        }
        
        public String getWhite() {
            String white;
            if (isWhiteKey()) {
                return getWhiteKey();
            } else if (sender != null && (white = White.find(null, User.this, ip, sender, getValidHostname(), (isSigned(sender) ? "PASS" : qualifier == null ? "NONE" : qualifier.name()), recipient)) != null) {
                return white;
            } else if (from != null && (white = White.find(null, User.this, ip, from, getValidHostname(), (isSigned(from) ? "PASS" : "NONE"), recipient)) != null) {
                return white;
            } else if (replyto != null && (white = White.find(null, User.this, ip, replyto, getValidHostname(), (isSigned(replyto) ? "PASS" : "NONE"), recipient)) != null) {
                return white;
            } else if (sender == null) {
                return White.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient);
            } else {
                return null;
            }
        }
        
        public boolean isBlock() {
            return getBlock() != null;
        }
        
        public String getBlock() {
            String block;
            if (isBlockKey()) {
                return getBlockKey();
            } else if (sender != null && (block = Block.find(null, User.this, ip, sender, getValidHostname(), (isSigned(sender) ? "PASS" : qualifier == null ? "NONE" : qualifier.name()), recipient, false, true, true, true)) != null) {
                return block;
            } else if (from != null && (block = Block.find(null, User.this, ip, from, getValidHostname(), (isSigned(from) ? "PASS" : "NONE"), recipient, false, true, true, true)) != null) {
                return block;
            } else if (replyto != null && (block = Block.find(null, User.this, ip, replyto, getValidHostname(), (isSigned(replyto) ? "PASS" : "NONE"), recipient, false, true, true, true)) != null) {
                return block;
            } else if (sender == null && (block = Block.find(null, User.this, ip, null, getValidHostname(), "NONE", recipient, false, true, true, true)) != null) {
                return block;
            } else if (Ignore.containsHost(getValidHostname())) {
                return null;
            } else if (Provider.containsDomain(getValidHostname())) {
                return null;
            } else {
                return Block.findDNSBL(ip);
            }
        }
        
        public boolean isAnyLinkBLOCK(boolean findIP) {
            for (String token : getLinkKeySet()) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        return true;
                    } else {
                        token = Core.getSignatureHostURL(token);
                    }
                }
                if (Block.findHREF(User.this, token, findIP) != null) {
                    setLinkBlocked(token);
                    return true;
                }
            }
            return false;
        }
        
        public String getBlockHREF(boolean findIP) {
            String block = null;
            for (String token : getLinkKeySet()) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        return token;
                    } else {
                        token = Core.getSignatureHostURL(token);
                    }
                }
                if ((block = Block.findHREF(User.this, token, findIP)) != null) {
                    setLinkBlocked(token);
                    break;
                }
            }
            return block;
        }
        
        public boolean isSubjectSuspect() {
            if (subject == null) {
                return false;
            } else {
                return Block.containsSubject(User.this, subject);
            }
        }
        
        public boolean isAnyLinkSuspect() {
            for (String token : getLinkKeySet()) {
                if (Core.isSignatureURL(token)) {
                    token = Core.getSignatureHostURL(token);
                }
                if (SPF.isRed(token)) {
                    Server.logTrace("isAnyLinkSuspect isRed");
                    return true;
//                } else if (Subnet.isValidIP(token)) {
//                    Server.logTrace("isAnyLinkSuspect isValidIP");
//                    return true;
//                } else if (Generic.containsGenericSoft(token)) {
//                    Server.logTrace("isAnyLinkSuspect containsGenericSoft");
//                    return true;
//                } else if (Block.find(User.this, token, false, false, false) != null) {
//                    Server.logTrace("isAnyLinkSuspect BLOCK");
//                    return true;
                } else if (Domain.isHostname(token)) {
//                    if (token.contains(".xn--")) {
//                       // IDNA encoding.
//                       Server.logTrace("isAnyLinkSuspect IDNA encoding");
//                       return true;
//                    } else {
                        String listed = Reverse.getListedHost(token, "multi.uribl.com", "127.0.0.2", "127.0.0.4", "127.0.0.8");
                        if (listed != null) {
                            Server.logTrace("isAnyLinkSuspect multi.uribl.com");
                            Server.logDebug("host " + token + " is listed in 'multi.uribl.com;" + listed + "'.");
                            return true;
                        }
//                    }
                }
            }
            return false;
        }
        
        private synchronized Boolean containsRecipient() {
            if (recipient == null) {
                return false;
            } else if (recipientSet == null) {
                return null;
            } else {
                return recipientSet.contains(recipient);
            }
        }
        
        private synchronized boolean addRecipient() {
            if (recipient == null) {
                return false;
            } else if (recipientSet == null) {
                return false;
            } else if (recipientSet.add(recipient)) {
                return User.CHANGED = true;
            } else {
                return false;
            }
        }
        
        private synchronized boolean removeRecipient() {
            if (recipient == null) {
                return false;
            } else if (recipientSet == null) {
                return false;
            } else {
                boolean removed = recipientSet.remove(recipient);
                if (recipientSet.isEmpty()) {
                    recipientSet = null;
                    User.CHANGED = true;
                }
                if (removed) {
                    return User.CHANGED = true;
                } else {
                    return false;
                }
            }
        }
        
        public synchronized boolean isInexistent(Client client) {
            if (recipient == null) {
                return false;
            } else if (Trap.containsAnything(client, User.this, recipient)) {
                return true;
            } else if (recipientSet == null) {
                return false;
            } else if (recipientSet.contains(recipient)) {
                return false;
            } else {
                Trap.addInexistentSafe(client, recipient);
                return true;
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
        
        public boolean isToReserved() {
            if (recipient == null) {
                return false;
            } else if (recipient.startsWith("postmaster@")) {
                return true;
            } else if (recipient.startsWith("abuse@")) {
                return true;
            } else if (recipient.startsWith("mailer-daemon@")) {
                return true;
            } else if (isToAdmin()) {
                return true;
            } else if (isToAbuse()) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean isFromReserved() {
            if (sender == null) {
                return true;
            } else if (from == null) {
                return true;
            } else if (sender.startsWith("postmaster@")) {
                return true;
            } else if (sender.startsWith("abuse@")) {
                return true;
            } else if (sender.startsWith("mailer-daemon@")) {
                return true;
            } else if (from.startsWith("postmaster@")) {
                return true;
            } else if (from.startsWith("abuse@")) {
                return true;
            } else if (from.startsWith("mailer-daemon@")) {
                return true;
            } else {
                return false;
            }
        }
        
        public Long getTrapTime() {
            if (recipient == null) {
                return null;
            } else {
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
                if (timeUser != null) {
                    removeRecipient();
                } else if (Boolean.FALSE.equals(containsRecipient())) {
                    timeUser = Long.MAX_VALUE;
                }
                return timeUser;
            }
        }
        
        public boolean isOriginWhite() {
            String domain = getOriginDomain(false);
            if (domain == null) {
                return White.containsExtact(User.this, "mailer-daemon@;" + getIP());
            } else {
                return White.containsExtact(User.this, "mailer-daemon@" + domain + ";" + domain);
            }
        }
        
        public boolean isBlockCIDR() {
            return Block.containsExact(User.this, "CIDR=" + getCIDR());
        }
        
        public boolean isSenderBlock() {
            if (isSenderBlock(false)) {
                return true;
            } else {
                Situation situation;
                String senderLocal = getSender();
                if (senderLocal == null) {
                    return false;
                } else if (isSigned(senderLocal)) {
                    situation = Situation.AUTHENTIC;
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
            String senderLocal = getSender();
            if (isSigned(senderLocal)) {
                return true;
            } else if (isPass() && isMailFrom(senderLocal)) {
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
        
        public boolean isUniqueSender() {
            if (sender == null) {
                return from != null;
            } else if (from == null) {
                return true;
            } else {
                return sender.equals(from);
            }
        }
        
        public boolean hasTokenRed() {
//            return SPF.hasRed(tokenSet);
            boolean unique = isUniqueSender();
            for (String token : tokenSet) {
                if (unique) {
                    if (SPF.isRed(token)) {
                        return true;
                    }
                } else if (Subnet.isValidIP(token)) {
                    if (SPF.isRed(token)) {
                        return true;
                    }
                } else if (!Provider.containsDomain(token)) {
                    if (SPF.isRed(token)) {
                        return true;
                    }
                }
            }
            return false;
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
            } else if (filter.equals("retidas") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("retido") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("retidos") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("hold") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("holding") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("detained") && isResult("HOLD")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitadas") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitado") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitados") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejected") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejecteds") && isResult("BLOCK")) {
                return true;
            } else if (filter.equals("rejeitada") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejeitadas") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejeitado") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejeitados") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejected") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("rejecteds") && isResult("REJECT")) {
                return true;
            } else if (filter.equals("atrasada") && isResult("GREYLIST")) {
                return true;
            } else if (filter.equals("atrasado") && isResult("GREYLIST")) {
                return true;
            } else if (filter.equals("delayed") && isResult("GREYLIST")) {
                return true;
            } else if (filter.equals("atrasadas") && isResult("GREYLIST")) {
                return true;
            } else if (filter.equals("atrasados") && isResult("GREYLIST")) {
                return true;
            } else if (filter.equals("atrasada") && isResult("LISTED")) {
                return true;
            } else if (filter.equals("atrasado") && isResult("LISTED")) {
                return true;
            } else if (filter.equals("delayed") && isResult("LISTED")) {
                return true;
            } else if (filter.equals("atrasadas") && isResult("LISTED")) {
                return true;
            } else if (filter.equals("atrasados") && isResult("LISTED")) {
                return true;
            } else if (filter.equals("insuspeita") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("insuspeito") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("unsuspected") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("insuspeitas") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("insuspeitos") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("confiavel") && isResult("WHITE")) {
                return true;
            } else if (filter.equals("confiaveis") && isResult("WHITE")) {
                return true;
            } else if (filter.equals("whitelisted") && isResult("WHITE")) {
                return true;
            } else if (filter.equals("confiável") && isResult("WHITE")) {
                return true;
            } else if (filter.equals("confiáveis") && isResult("WHITE")) {
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
                } else if (filter.equals(getHeaderFrom())) {
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
        
        public String getHeaderFrom() {
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
            } else if (link.equals(getUserEmail())) {
                return false;
            } else if (link.equals(getRecipient())) {
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
        
        public boolean hasSuspectReplyTo() {
            String replyTo = getReplyTo();
            if (replyTo == null) {
                return false;
            } else if (replyTo.endsWith("@yahoo.com")) {
                return !isSigned(replyTo) && sizeLinkKeySetExcept(replyTo) == 0;
            } else if (replyTo.endsWith("@gmail.com")) {
                return !isSigned(replyTo) && sizeLinkKeySetExcept(replyTo) == 0;
            } else {
                return false;
            }
        }
        
        public boolean hasExecutableNotIgnored() {
            if (executableSet == null) {
                return false;
            } else if (executableSet.isEmpty()) {
                return false;
            } else {
                int count = executableSet.size();
                for (String signature : executableSet) {
                    if (Ignore.containsExact(getEmail() + ":" + signature)) {
                        count--;
                    }
                }
                return count > 0;
            }
        }
        
        public boolean hasExecutableBlocked() {
            if (executableSet == null) {
                return false;
            } else if (executableSet.isEmpty()) {
                return false;
            } else {
                for (String signature : executableSet) {
                    if (!Ignore.containsExact(getEmail() + ":" + signature)) {
                        if (Block.containsExact(signature)) {
                            return true;
                        }
                    }
                }
                return false;
            }
        }
        
        public boolean hasMiscellaneousSymbols() {
            return Core.hasMiscellaneousSymbols(subject);
        }
        
        public boolean isInvalidDate(long time) {
            if (date == null) {
                return false;
            } else {
//                return Math.abs(time - date.getTime()) > (3 * Server.DAY_TIME);
                return Math.abs(time - date.getTime()) > (21 * Server.DAY_TIME);
            }
        }
        
        private int sizeLinkKeySetExcept(String key) {
            if (linkMap == null) {
                return 0;
            } else if (linkMap.containsKey(key)) {
                return linkMap.size() - 1;
            } else {
                return linkMap.size();
            }
        }
        
        private boolean containsLinkKeySet(String key) {
            if (linkMap == null) {
                return false;
            } else {
                return linkMap.containsKey(key);
            }
        }
        
        private TreeSet<String> getLinkKeySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (linkMap != null) {
                keySet.addAll(linkMap.keySet());
            }
            return keySet;
        }
        
        private TreeSet<String> getExecutableSet() {
            TreeSet<String> resultSet = new TreeSet<>();
            if (executableSet != null) {
                resultSet.addAll(executableSet);
            }
            return resultSet;
        }
        
        public boolean addLink(String link) {
            if ((link = normalizeLink(link)) == null) {
                return false;
            } else if (link.equals(getUserEmail())) {
                return false;
            } else if (link.equals(getRecipient())) {
                return false;
            } else {
                boolean blocked;
                if (isToPostmaster()) {
                    blocked = false;
                } else if (isToAdmin()) {
                    blocked = false;
                } else if (isToAbuse()) {
                    blocked = false;
                } else if (Block.findHREF(User.this, link, false) == null) {
                    blocked = false;
                } else {
                    blocked = true;
                }
                this.CHANGED.acquire();
                try {
                    if (this.linkMap == null) {
                        this.linkMap = new TreeMap<>();
                    }
                    this.linkMap.put(link, blocked);
                    this.STORED = false;
                    User.CHANGED = true;
                    return blocked;
                } finally {
                    this.CHANGED.release(true);
                }
            }
        }
        
        public String setLinkSet(TreeSet<String> linkSet) {
            if (linkSet == null) {
                return null;
            } else {
                TreeMap<String,Boolean> resultMap = new TreeMap<>();
                String result = null;
                String block;
                for (String link : linkSet) {
                    if (link.equals(getUserEmail())) {
                        // Do nothing.
                    } else if (link.equals(getRecipient())) {
                        // Do nothing.
                    } else if (link.startsWith("MALWARE=")) {
                        int beginIndex = link.indexOf('=') + 1;
                        String malware = link.substring(beginIndex);
                        setMalware(malware);
                    } else if (Core.isExecutableSignature(link)) {
                        addExecutable(link);
                    } else if (Core.isSignatureURL(link)) {
                        if ((block = Block.getSignatureBlockURL(link)) == null) {
                            resultMap.put(link, false);
                        } else {
                            resultMap.put(link, true);
                            result = block;
                        }
                    } else if ((link = normalizeLink(link)) != null) {
                        if (isToPostmaster()) {
                            resultMap.put(link, false);
                        } else if (isToAdmin()) {
                            resultMap.put(link, false);
                        } else if (isToAbuse()) {
                            resultMap.put(link, false);
                        } else if ((block = Block.findHREF(User.this, link, false)) == null) {
                            resultMap.put(link, false);
                        } else {
                            resultMap.put(link, true);
                            result = block;
                        }
                    }
                }
                this.CHANGED.acquire();
                try {
                    if (this.linkMap == null) {
                        this.linkMap = resultMap;
                    } else {
                        this.linkMap.putAll(resultMap);
                    }
                    this.STORED = false;
                    User.CHANGED = true;
                    return result;
                } finally {
                    this.CHANGED.release(true);
                }
            }
        }
        
        public boolean setSignerSet(TreeSet<String> signerSet) {
            if (signerSet == null) {
                return false;
            } else if (signerSet.isEmpty()) {
                return false;
            } else {
                TreeSet<String> resultSet = new TreeSet<>();
                for (String signer : signerSet) {
                    if ((signer = normalizeSigner(signer)) != null) {
                        resultSet.add(signer);
                    }
                }
                if (resultSet.isEmpty()) {
                    return false;
                } else {
                    this.CHANGED.acquire();
                    try {
                        boolean changed = false;
                        for (String signer : resultSet) {
                            if (this.signerSet == null) {
                                this.signerSet = new TreeSet<>();
                            }
                            if (this.signerSet.add(signer)) {
                                changed = true;
                            }
                        }
                        if (changed) {
                            this.STORED = false;
                            User.CHANGED = true;
                            return true;
                        } else {
                            return false;
                        }
                    } finally {
                        this.CHANGED.release(true);
                    }
                }
            }
        }
        
        public boolean addExecutable(String signature) {
            if (Core.isExecutableSignature(signature)) {
                this.CHANGED.acquire();
                if (executableSet == null) {
                    executableSet = new TreeSet<>();
                }
                executableSet.add(signature);
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return true;
            } else {
                return false;
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
                if (this.malware == null) {
                    this.malware = malware;
                    this.STORED = false;
                    User.CHANGED = true;
                }
                this.CHANGED.release(true);
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
                    text = text.replace('\t', ' ');
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
                this.STORED = false;
                User.CHANGED = true;
                return true;
            }
        }
        
        public boolean needHeader() {
            if (isFail()) {
                return false;
            } else if (Boolean.FALSE.equals(containsRecipient())) {
                return false;
            } else if (isUsingHeader()) {
                String hostnameLocal = getValidHostname();
                String senderLocal = getMailFrom();
                if (hostnameLocal == null) {
                    return false;
                } else if (senderLocal == null) {
                    return false;
                } else if (Provider.containsDomain(hostnameLocal)) {
                    return true;
                } else if (Generic.containsGenericSoft(hostnameLocal)) {
                    return false;
                } else if (Generic.containsGenericSoft(senderLocal)) {
                    return false;
                } else if (isSenderRed()) {
                    return false;
                } else if (isBlockKey()) {
                    return false;
                } else if (isBlockSMTP()) {
                    return false;
                } else if (isBlockedForRecipient()) {
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
                waitHeader(10000);
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
        
        public String setHeader(
                long time,
                Client client,
                String from,
                String replyto,
                String subject,
                String messageID,
                String date,
                String unsubscribe,
                Action actionGRACE,
                Action actionBLOCK,
                Action actionRED
        ) {
//            try {
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
                Timestamp emailDate;
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
                    this.STORED = false;
                } finally {
                    this.CHANGED.release(true);
                    User.this.usingHeader = true;
                    this.STORED = false;
                    User.CHANGED = true;
                }
                String resultReturn;
                if (isWhiteKey()) {
                    if (hasMalwareNotIgnored()) {
                        resultReturn = "REJECT";
                    } else {
                        resultReturn = "WHITE";
                    }
                } else if (isWhite()) {
                    if (hasMalwareNotIgnored()) {
                        resultReturn = "REJECT";
                    } else {
                        whiteKey(time);
                        resultReturn = "WHITE";
                    }
                } else if (isToAbuse()) {
                    resultReturn = null;
                } else if (hasMalwareNotIgnored()) {
                    blockKey(time);
                    resultReturn = "BLOCK";
                } else if (isToPostmaster()) {
                    resultReturn = null;
                } else if (isInexistent(client)) {
                    blockKey(time);
                    resultReturn = "BLOCK";
                } else if (isBlockKey()) {
                    if (actionBLOCK == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionBLOCK == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        resultReturn = "BLOCK";
                    }
                } else if (isWhiteKeyByAdmin()) {
                    if (hasMalwareNotIgnored()) {
                        resultReturn = "REJECT";
                    } else {
                        whiteKey(time);
                        resultReturn = "WHITE";
                    }
                } else if (hasDynamicIP()) {
                    Analise.processToday(getIP());
                    blockKey(time);
                    resultReturn = "BLOCK";
                 } else if (isBlockKeyByAdmin() || isSenderBlock() || isBlockCIDR() || hasExecutableBlocked() || isAnyLinkBLOCK(false) || Block.containsWHOIS(User.this, getSender())) {
                    if (actionBLOCK == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionBLOCK == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        blockKey(time);
                        resultReturn = "BLOCK";
                    }
                } else if (isToAdmin()) {
                    resultReturn = null;
                } else if ((resultReturn = getBlock()) != null) {
                    Server.logTrace("HEADER isBlock " + resultReturn);
                    if (actionBLOCK == Action.REJECT && !hasQualifiedIP()) {
                        Analise.processToday(getIP());
                        blockKey(time);
                        resultReturn = "BLOCK";
                    } else if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (reject) {
                    this.complain(time);
                    resultReturn = "REJECT";
                } else if (!hasMailFrom() && !hasHeaderFrom()) {
                    this.complain(time);
                    resultReturn = "REJECT";
                } else if (hasSuspectReplyTo()) {
                    Server.logTrace("HEADER hasSuspectReplyTo");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (hasExecutableNotIgnored()) {
                    Server.logTrace("HEADER hasExecutableNotIgnored");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (hasTokenRed()) {
                    Server.logTrace("HEADER hasTokenRed");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (isAnyLinkSuspect()) {
                    Server.logTrace("HEADER isAnyLinkSuspect");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (isInvalidDate(time)) {
                    Server.logTrace("HEADER isInvalidDate");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (hasMiscellaneousSymbols()) {
                    Server.logTrace("HEADER hasMiscellaneousSymbols");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (isSubjectSuspect()) {
                    Server.logTrace("HEADER isSubjectSuspect");
                    if (actionRED == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionRED == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else if (Domain.isGraceTime(getMailFrom()) || Domain.isGraceTime(getHeaderFrom()) || Domain.isGraceTime(getValidHostname())) {
                    Server.logTrace("HEADER isGraceTime");
                    if (actionGRACE == Action.FLAG) {
                        resultReturn = "FLAG";
                    } else if (actionGRACE == Action.HOLD) {
                        resultReturn = "HOLD";
                    } else {
                        this.complain(time);
                        resultReturn = "REJECT";
                    }
                } else {
                    resultReturn = null;
                }
                Analise.processToday(getSender());
                setResult(resultReturn);
                return resultReturn;
                
//                this.CHANGED.acquire();
//                try {
//                    if (resultReturn != null) {
//                        this.result = resultReturn;
//                    }
//                    User.CHANGED = true;
//                    this.STORED = false;
//                    return resultReturn;
//                } finally {
//                    this.CHANGED.release(true);
//                }
//            } finally {
//                this.notifyHeader();
//            }
        }
        
        public synchronized void notifyHeader() {
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
                return true;
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
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isWhiteKeyByAdmin()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
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
                            if (hasExecutableNotIgnored()) {
                                ServerHTTP.buildText(builder, "<b>Atenção! Esta mensagem contém arquivos executáveis com potencial de danificar o computador!</b>");
                            }
                            ServerHTTP.buildText(builder, "Se você considera esta mensagem legítima, acesse esta URL para efetivar a sua liberação:");
                        } else {
                            ServerHTTP.buildMessage(builder, "Message retention warning");
                            ServerHTTP.buildText(builder, "A message sent from " + senderLocal + " was retained under suspicion of SPAM.");
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Warning! This sender could not be authenticated. This means that there is no guarantee that this message will be genuine!");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "The message was fired by a server in domain " + hostDomain + ".");
                                }
                            }
                            if (hasExecutableNotIgnored()) {
                                ServerHTTP.buildText(builder, "<b>Warning! This message contains executable files that could potentially damage the computer!</b>");
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
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (NameNotFoundException ex) {
                    return false;
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
        
//        public synchronized boolean adviseRecipientSPAM(long time) {
//            String senderLocal = getSender();
//            String recipientLocal = getRecipient();
//            String subjectLocal = getSubject();
//            String messageidLocal = getMessageID();
//            if (recipientAdvised) {
//                return true;
//            } else if (senderLocal == null) {
//                return false;
//            } else if (recipientLocal == null) {
//                return false;
//            } else if (subjectLocal == null) {
//                return false;
//            } else if (messageidLocal == null) {
//                return false;
//            } else if (isToPostmaster()) {
//                return false;
//            } else if (isToAdmin()) {
//                return false;
//            } else if (isToAbuse()) {
//                return false;
//            } else if (!Core.hasOutputSMTP()) {
//                return false;
//            } else if (!Domain.isValidEmail(recipientLocal)) {
//                return false;
//            } else if (NoReply.contains(recipientLocal, true)) {
//                return false;
//            } else if (isWhiteKey()) {
//                return false;
//            } else if (isBlockKey()) {
//                return false;
//            } else if (isAnyLinkBLOCK(true)) {
//                return false;
//            } else {
//                try {
//                    String url = Core.getBlockURL(User.this, time);
//                    if (url == null) {
//                        return false;
//                    } else {
//                        Server.logDebug("sending suspect alert by e-mail.");
//                        Locale locale = User.this.getLocale();
//                        InternetAddress[] recipients = InternetAddress.parse(recipientLocal);
//                        MimeMessage message = Core.newMessage();
//                        message.addRecipients(Message.RecipientType.TO, recipients);
//                        message.setReplyTo(User.this.getInternetAddresses());
//                        message.setSubject(subjectLocal);
//                        message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
//                        // Corpo da mensagem.
//                        StringBuilder builder = new StringBuilder();
//                        builder.append("<!DOCTYPE html>\n");
//                        builder.append("<html lang=\"");
//                        builder.append(locale.getLanguage());
//                        builder.append("\">\n");
//                        builder.append("  <head>\n");
//                        builder.append("    <meta charset=\"UTF-8\">\n");
//                        builder.append("    <title>");
//                        builder.append(subject);
//                        builder.append("</title>\n");
//                        ServerHTTP.loadStyleCSS(builder);
//                        builder.append("  </head>\n");
//                        builder.append("  <body>\n");
//                        builder.append("  <body>\n");
//                        builder.append("    <div id=\"container\">\n");
//                        builder.append("      <div id=\"divlogo\">\n");
//                        builder.append("        <img src=\"cid:logo\">\n");
//                        builder.append("      </div>\n");
//                        if (locale.getLanguage().toLowerCase().equals("pt")) {
//                            ServerHTTP.buildMessage(builder, "Alerta de suspeita de SPAM");
//                            ServerHTTP.buildText(builder, "Esta mensagem, cujo assunto foi preservado e havia sido enviada por " + senderLocal + ", foi entregue em sua caixa postal por haver nenhuma suspeita sobre ela.");
//                            ServerHTTP.buildText(builder, "Informações mais recentes levantam forte suspeita de que esta mensagem seria SPAM.");
//                            ServerHTTP.buildText(builder, "Se você concorda com esta nova interpretação, acesse esta URL para bloquear o remetente e para contribuir para o combate de SPAM na Internet:");
//                        } else {
//                            ServerHTTP.buildMessage(builder, "SPAM suspected alert");
//                            ServerHTTP.buildText(builder, "This message, whose subject was preserved and sent by " + senderLocal + ", was delivered to your mailbox because there was no suspicion about it.");
//                            ServerHTTP.buildText(builder, "More recent information raises strong suspicion that this message would be SPAM.");
//                            ServerHTTP.buildText(builder, "If you agree with this new interpretation, access this URL to block the sender and contribute to the fight against spam on the Internet:");
//                        }
//                        ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
//                        if (!User.this.isEmail(recipientLocal)) {
//                            String abuseEmail = Core.getAbuseEmail();
//                            if (abuseEmail != null) {
//                                if (locale.getLanguage().toLowerCase().equals("pt")) {
//                                    ServerHTTP.buildText(builder, "Se você receber qualquer mensagem de SPAM, poderá encaminhar a mensagem de SPAM para " + abuseEmail + ".");
//                                    ServerHTTP.buildText(builder, "Este remetente poderá ser bloqueado automaticamente no caso de recebermos muitas denuncias contra ele.");
//                                } else {
//                                    ServerHTTP.buildText(builder, "If you receive any SPAM message, you can forward the SPAM message to " + abuseEmail + ".");
//                                    ServerHTTP.buildText(builder, "This sender may be automatically blocked if we receive too many complaints against him.");
//                                }
//                            }
//                            if (locale.getLanguage().toLowerCase().equals("pt")) {
//                                ServerHTTP.buildText(builder, "Para maiores informações, entre em contato com o seu setor de TI.");
//                            } else {
//                                ServerHTTP.buildText(builder, "For more information, contact your post administrator.");
//                            }
//                        }
//                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
//                        builder.append("    </div>\n");
//                        builder.append("  </body>\n");
//                        builder.append("</html>\n");
//                        // Making HTML part.
//                        MimeBodyPart htmlPart = new MimeBodyPart();
//                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
//                        // Making logo part.
//                        MimeBodyPart logoPart = new MimeBodyPart();
//                        File logoFile = ServerHTTP.getWebFile("logo.png");
//                        logoPart.attachFile(logoFile);
//                        logoPart.setContentID("<logo>");
//                        logoPart.addHeader("Content-Type", "image/png");
//                        logoPart.setDisposition(MimeBodyPart.INLINE);
//                        // Join both parts.
//                        MimeMultipart content = new MimeMultipart("related");
//                        content.addBodyPart(htmlPart);
//                        content.addBodyPart(logoPart);
//                        // Set multiplart content.
//                        message.setContent(content);
//                        message.saveChanges();
//                        // Enviar mensagem.
//                        if (Core.sendMessage(locale, message, 30000)) {
//                            Server.logDebug("suspect warning sent by e-mail.");
//                            this.CHANGED.acquire();
//                            this.recipientAdvised = true;
//                            this.STORED = false;
//                            User.CHANGED = true;
//                            this.CHANGED.release(true);
//                            User.storeDB(time, this);
//                            return true;
//                        } else {
//                            return false;
//                        }
//                    }
//                } catch (NameNotFoundException ex) {
//                    return false;
//                } catch (MailConnectException ex) {
//                    return false;
//                } catch (SendFailedException ex) {
//                    if (ex.getCause() instanceof SMTPAddressFailedException) {
//                        if (ex.getCause().getMessage().contains(" 5.1.1 ")) {
//                            Trap.addInexistentSafe(User.this, recipientLocal);
//                        }
//                    }
//                    return false;
//                } catch (Exception ex) {
//                    Server.logError(ex);
//                    return false;
//                }
//            }
//        }
        
        private synchronized boolean adviseSenderHOLD(long time) {
            String mailFrom;
            String recipientLocal;
            if (senderAdvised) {
                return true;
            } else if ((mailFrom = getReplyToValid()) == null) {
                return false;
            } else if ((recipientLocal = getRecipient()) == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (NoReply.contains(mailFrom, true)) {
                return false;
            } else if (NoReply.contains(recipientLocal, true)) {
                return false;
            } else if (!Domain.isValidEmail(recipientLocal)) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlock()) {
                if (hasTokenRed()) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by '" + mailFrom + ";RED'.");
                    }
                } else if (!Reverse.hasMX(mailFrom)) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by '" + mailFrom + ";NXDOMAIN'.");
                    }
                }
                return false;
            } else if (isAnyLinkBLOCK(true)) {
                if (blockKey(time)) {
                    Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by '" + mailFrom + ";HREF'.");
                }
                return false;
            } else if (hasDynamicIP()) {
                if (blockKey(time)) {
                    Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by '" + mailFrom + ";DYNAMIC'.");
                }
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
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (ServiceUnavailableException ex) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'ServiceUnavailableException'.");
                    }
                    return false;
                } catch (NameNotFoundException ex) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'NameNotFoundException'.");
                    }
                    return false;
                } catch (CommunicationException ex) {
                    return false;
                } catch (MailConnectException ex) {
                    return false;
                } catch (SendFailedException ex) {
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        if (blockKey(time)) {
                            Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'SendFailedException'.");
                        }
                    }
                    return false;
                } catch (MessagingException ex) {
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        private synchronized boolean adviseSenderBLOCK(long time) {
            String mailFrom;
            String recipientLocal;
            if (senderAdvised) {
                return true;
            } else if ((mailFrom = getReplyToValid()) == null) {
                return false;
            } else if ((recipientLocal = getRecipient()) == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (Trap.containsAnything(null, User.this, recipientLocal)) {
                return false;
            } else if (NoReply.contains(recipientLocal, false)) {
                return false;
            } else if (!Domain.isValidEmail(recipientLocal)) {
                return false;
            } else if (isBlockedForRecipient()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isWhiteKeyByAdmin()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
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
                                subjectLocal = "Message rejection warning";
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
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            this.blockForRecipient(time);
                            User.storeDB(time, this);
                            Server.logDebug("reject warning sent by e-mail.");
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (ServiceUnavailableException ex) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'ServiceUnavailableException'.");
                    }
                    return false;
                } catch (NameNotFoundException ex) {
                    if (blockKey(time)) {
                        Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'NameNotFoundException'.");
                    }
                    return false;
                } catch (CommunicationException ex) {
                    blockForRecipient(time);
                    return false;
                } catch (MailConnectException ex) {
                    blockForRecipient(time);
                    return false;
                } catch (SendFailedException ex) {
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        if (blockKey(time)) {
                            Server.logDebug("new BLOCK '" + getUserEmail() + ":" + getBlockKey() + "' added by 'SendFailedException'.");
                        }
                    }
                    return false;
                } catch (MessagingException ex) {
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
            if (userAdvised) {
                return true;
            } else if (senderLocal == null) {
                return false;
            } else if (userEmail == null) {
                return false;
            } else if (NoReply.contains(userEmail, true)) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isWhiteKeyByAdmin()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
                return false;
            } else if (isAnyLinkBLOCK(true)) {
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
                        if (Domain.isValidEmail(senderLocal)) {
                            message.setReplyTo(InternetAddress.parse(senderLocal));
                        }
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
                            if (hasExecutableNotIgnored()) {
                                ServerHTTP.buildText(builder, "<b>Atenção! Esta mensagem contém arquivos executáveis com potencial de danificar o computador!</b>");
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
                                            builder.append(Core.tryGetSignatureRootURL(link));
                                            builder.append("</font></b>");
                                        } else {
                                            builder.append(Core.tryGetSignatureRootURL(link));
                                        }
                                        builder.append("</li>\n");
                                    }
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
                            if (!isSenderTrustable()) {
                                ServerHTTP.buildText(builder, "<b>Warning! This sender could not be authenticated. That means the message can be a fraud!</b>");
                                String hostDomain = getValidHostDomain();
                                if (hostDomain == null) {
                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
                                } else {
                                    ServerHTTP.buildText(builder, "<p>The message was fired by a server in domain " + hostDomain + ".");
                                }
                            }
                            if (hasExecutableNotIgnored()) {
                                ServerHTTP.buildText(builder, "<b>Warning! This message contains executable files that could potentially damage the computer!</b>");
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
                            this.userAdvised = true;
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (NameNotFoundException ex) {
                    return false;
                } catch (CommunicationException ex) {
                    return false;
                } catch (ServiceUnavailableException ex) {
                    return false;
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
        
//        private synchronized boolean adviseAdminHOLD(long time) {
//            String adminEmail = Core.getAdminEmail();
//            if (adminAdvised) {
//                return true;
//            } else if (adminEmail == null) {
//                return false;
//            } else if (NoReply.contains(adminEmail, true)) {
//                return false;
//            } else if (!Core.hasOutputSMTP()) {
//                return false;
//            } else if (isWhiteKey()) {
//                return false;
//            } else if (isBlockKey()) {
//                return false;
//            } else if (isWhiteKeyByAdmin()) {
//                return false;
//            } else if (isBlockKeyByAdmin()) {
//                return false;
//            } else if (isAnyLinkBLOCK(true)) {
//                return false;
//            } else {
//                try {
//                    String unholdURL = Core.getUnholdURL(User.this, time);
//                    String blockURL = Core.getBlockURL(User.this, time);
//                    if (unholdURL == null) {
//                        return false;
//                    } else if (blockURL == null) {
//                        return false;
//                    } else {
//                        Server.logDebug("sending retention warning by e-mail.");
//                        Locale locale = User.this.getLocale();
//                        String subjectLocal = getSubject();
//                        if (subjectLocal == null) {
//                            if (locale.getLanguage().toLowerCase().equals("pt")) {
//                                subjectLocal = "Aviso de retenção de mensagem";
//                            } else {
//                                subjectLocal = "Message retention warning";
//                            }
//                        }
//                        subjectLocal += " [" + Long.toHexString(time) + "]";
//                        String recipientMail = getRecipient();
//                        String requestURL;
//                        if (recipientMail == null) {
//                            requestURL = null;
//                        } else if (NoReply.contains(recipientMail, true)) {
//                            requestURL = null;
//                        } else {
//                            requestURL = Core.getHoldingURL(User.this, time);
//                        }
////                        String qualifierLocal = getQualifierName();
//                        String recipientLocal = getRecipient();
//                        String messageidLocal = getMessageID();
//                        String textBody = getTextPlainBody(256);
//                        TreeSet<String> linkSet = getLinkSet();
//                        InternetAddress[] recipients = {Core.getAdminInternetAddress()};
//                        MimeMessage message = Core.newMessage();
//                        message.addRecipients(Message.RecipientType.TO, recipients);
//                        String senderLocal = getSender();
//                        String hostDomain = getValidHostDomain();
//                        if (senderLocal == null) {
//                            if (hostDomain == null) {
//                                senderLocal = "mailer-daemon";
//                            } else {
//                                senderLocal = "mailer-daemon@" + hostDomain;
//                            }
//                        } else if (Domain.isValidEmail(senderLocal)) {
//                            message.setReplyTo(InternetAddress.parse(senderLocal));
//                        }
//                        message.setSubject(subjectLocal);
//                        if (messageidLocal != null) {
//                            message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
//                        }
//                        // Corpo da mensagem.
//                        StringBuilder builder = new StringBuilder();
//                        builder.append("<!DOCTYPE html>\n");
//                        builder.append("<html lang=\"");
//                        builder.append(locale.getLanguage());
//                        builder.append("\">\n");
//                        builder.append("  <head>\n");
//                        builder.append("    <meta charset=\"UTF-8\">\n");
//                        builder.append("    <title>");
//                        builder.append(subjectLocal);
//                        builder.append("</title>\n");
//                        ServerHTTP.loadStyleCSS(builder);
//                        builder.append("  </head>\n");
//                        builder.append("  <body>\n");
//                        builder.append("    <div id=\"container\">\n");
//                        builder.append("      <div id=\"divlogo\">\n");
//                        builder.append("        <img src=\"cid:logo\">\n");
//                        builder.append("      </div>\n");
//                        if (locale.getLanguage().toLowerCase().equals("pt")) {
//                            ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagem");
//                            ServerHTTP.buildText(builder, "Uma mensagem enviada de " + senderLocal + " para "  + recipientLocal + " foi retida por suspeita de SPAM.");
//                            if (!isSenderTrustable()) {
//                                ServerHTTP.buildText(builder, "<b>Atenção! Este remetente não pôde ser autenticado. Isso significa que a mensagem pode ser uma fraude!</b>");
//                                if (hostDomain == null) {
//                                    ServerHTTP.buildText(builder, "<b>Não é possível determinar com segurança qual servidor disparou esta mensagem.</b>");
//                                } else {
//                                    ServerHTTP.buildText(builder, "A mensagem foi disparada por um servidor no domínio " + hostDomain + ".");
//                                }
//                            }
//                            if (hasExecutableNotIgnored()) {
//                                ServerHTTP.buildText(builder, "<b>Atenção! Esta mensagem contém arquivos executáveis com potencial de danificar o computador!</b>");
//                            }
//                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
//                                ServerHTTP.buildText(builder, "Os seguintes elementos foram encontrados no corpo da mensagem retida:");
//                                builder.append("    <ul>\n");
//                                if (textBody != null) {
//                                    builder.append("    <li>");
//                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
//                                    builder.append("</li>\n");
//                                }
//                                if (linkSet != null) {
//                                    for (String link : linkSet) {
//                                        builder.append("    <li>");
//                                        if (isLinkBlocked(link)) {
//                                            builder.append("<b><font color=\"DarkRed\">");
//                                            builder.append(Core.tryGetSignatureRootURL(link));
//                                            builder.append("</font></b>");
//                                        } else {
//                                            builder.append(Core.tryGetSignatureRootURL(link));
//                                        }
//                                        builder.append("</li>\n");
//                                    }
//                                }
//                                builder.append("    </ul>\n");
//                            }
//                            ServerHTTP.buildText(builder, "Se você considera esta mensagem legítima, acesse esta URL para solicitar a sua liberação:");
//                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
//                            ServerHTTP.buildText(builder, "Se você considera esta mensagem SPAM, acesse esta URL para bloquear o remetente:");
//                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
//                            if (requestURL != null) {
//                                ServerHTTP.buildText(builder, "Se você não tiver certeza do que essa mensagem seja, acesse esta URL para passar esta liberação ao destinatário:");
//                                ServerHTTP.buildText(builder, "<a href=\"" + requestURL + "\">" + requestURL + "</a>");
//                            }
//                        } else {
//                            ServerHTTP.buildMessage(builder, "Message retention warning");
//                            ServerHTTP.buildText(builder, "A message sent from " + senderLocal + " to " + recipientLocal + " was retained under suspicion of SPAM.");
//                            if (!isSenderTrustable()) {
//                                ServerHTTP.buildText(builder, "<b>Warning! This sender could not be authenticated. That means the message can be a fraud!</b>");
//                                if (hostDomain == null) {
//                                    ServerHTTP.buildText(builder, "<b>It is not possible to determine with certainty which server fired this message.</b>");
//                                } else {
//                                    ServerHTTP.buildText(builder, "<p>The message was fired by a server in domain " + hostDomain + ".");
//                                }
//                            }
//                            if (hasExecutableNotIgnored()) {
//                                ServerHTTP.buildText(builder, "<b>Warning! This message contains executable files that could potentially damage the computer!</b>");
//                            }
//                            if (textBody != null || (linkSet != null && !linkSet.isEmpty())) {
//                                ServerHTTP.buildText(builder, "The following elements have been found in message body:");
//                                builder.append("    <ul>\n");
//                                if (textBody != null) {
//                                    builder.append("    <li>");
//                                    builder.append(StringEscapeUtils.escapeHtml4(textBody));
//                                    builder.append("</li>\n");
//                                }
//                                if (linkSet != null) {
//                                    for (String link : linkSet) {
//                                        builder.append("    <li>");
//                                        if (isLinkBlocked(link)) {
//                                            builder.append("<b><font color=\"DarkRed\">");
//                                            builder.append(link);
//                                            builder.append("</font></b>");
//                                        } else {
//                                            builder.append(link);
//                                        }
//                                        builder.append("</li>\n");
//                                    }
//                                }
//                                builder.append("    </ul>\n");
//                            }
//                            ServerHTTP.buildText(builder, "If you consider this message legitimate, access this URL to request its release:");
//                            ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
//                            ServerHTTP.buildText(builder, "If you consider this SPAM message, access this URL to block the sender:");
//                            ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
//                            if (requestURL != null) {
//                                ServerHTTP.buildText(builder, "If you're not sure what this message is, visit this URL to pass this release to the recipient:");
//                                ServerHTTP.buildText(builder, "<a href=\"" + requestURL + "\">" + requestURL + "</a>");
//                            }
//                        }
//                        ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
//                        builder.append("    </div>\n");
//                        builder.append("  </body>\n");
//                        builder.append("</html>\n");
//                        // Making HTML part.
//                        MimeBodyPart htmlPart = new MimeBodyPart();
//                        htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
//                        // Making logo part.
//                        MimeBodyPart logoPart = new MimeBodyPart();
//                        File logoFile = ServerHTTP.getWebFile("logo.png");
//                        logoPart.attachFile(logoFile);
//                        logoPart.setContentID("<logo>");
//                        logoPart.addHeader("Content-Type", "image/png");
//                        logoPart.setDisposition(MimeBodyPart.INLINE);
//                        // Join both parts.
//                        MimeMultipart content = new MimeMultipart("related");
//                        content.addBodyPart(htmlPart);
//                        content.addBodyPart(logoPart);
//                        // Set multiplart content.
//                        message.setContent(content);
//                        message.saveChanges();
//                        // Enviar mensagem.
//                        if (Core.sendMessage(locale, message, 30000)) {
//                            this.CHANGED.acquire();
//                            this.adminAdvised = true;
//                            this.STORED = false;
//                            User.CHANGED = true;
//                            this.CHANGED.release(true);
//                            User.storeDB(time, this);
//                            return true;
//                        } else {
//                            return false;
//                        }
//                    }
//                } catch (Exception ex) {
//                    Server.logError(ex);
//                    return false;
//                }
//            }
//        }
    
        public synchronized boolean reportAbuse(long time) {
            String abuseEmail;
            if (abuseAdvised) {
                return true;
            } else if (!Core.hasAdminEmail()) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if ((abuseEmail = Abuse.getEmail(getIP(), true)) == null) {
                return false;
            } else if (NoReply.contains(abuseEmail, true)) {
                Abuse.dropEmail(getIP(), abuseEmail);
                return false;
            } else if (!isBlock()) {
                return false;
            } else {
                try {
                    Server.logDebug("sending abuse report by e-mail.");
                    String messageidLocal = getMessageID();
                    String subjectLocal = getSubject();
                    String arrivalDate = Core.getEmailDate(new Date(time));
                    InternetAddress[] recipients = InternetAddress.parse(abuseEmail);
//                    InternetAddress[] bcc = {Core.getAdminInternetAddress()};
                    boolean removalRequest = isBlockKey() || isBlockedForRecipient();
                    String unblockURL = isBlockedForRecipient() ? null : getUnblockURL();
                    MimeMessage message = Abuse.newAbuseReportMessage(
                            User.this,
                            getMalware(),
                            getMailFrom(),
                            getRecipient(),
                            arrivalDate,
                            getIP(),
                            getLinkKeySet(),
                            removalRequest,
                            unblockURL
                    );
                    message.addRecipients(Message.RecipientType.TO, recipients);
//                    message.addRecipients(Message.RecipientType.BCC, bcc);
                    message.setReplyTo(User.this.getInternetAddresses());
                    if (subjectLocal == null) {
                        message.setSubject("Abuse report");
                    } else {
                        message.setSubject("[ABUSE] " + subjectLocal);
                    }
                    if (messageidLocal != null) {
                        message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                    }
                    message.saveChanges();
                    // Enviar mensagem.
                    if (Core.sendMessage(Locale.US, message, 30000)) {
                        this.CHANGED.acquire();
                        this.abuseAdvised = true;
                        this.STORED = false;
                        User.CHANGED = true;
                        this.CHANGED.release(true);
                        User.storeDB(time, this);
                        Server.logDebug("abuse report sent by e-mail.");
                        return true;
                    } else {
                        return false;
                    }
                } catch (CommunicationException ex) {
                    return false;
                } catch (NameNotFoundException | ServiceUnavailableException ex) {
                    Abuse.dropEmail(getIP(), abuseEmail);
                    return false;
                } catch (SMTPSendFailedException ex) {
                    Abuse.dropEmail(getIP(), abuseEmail);
                    return false;
                } catch (SendFailedException ex) {
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        Abuse.dropEmail(getIP(), abuseEmail);
                    } else {
                        Server.logError(ex);
                    }
                    return false;
                } catch (MessagingException ex) {
                    Abuse.dropEmail(getIP(), abuseEmail);
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
    
    private static boolean adviseAdminHOLD(
            TreeMap<Long,Query> queryMap
    ) {
        String adminEmail = Core.getAdminEmail();
        if (adminEmail == null) {
            return false;
        } else if (queryMap == null) {
            return false;
        } else if (queryMap.isEmpty()) {
            return false;
        } else if (NoReply.contains(adminEmail, true)) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
//        } else if (queryMap.size() == 1) {
//            long time = queryMap.firstKey();
//            Query query = queryMap.get(time);
//            return query.adviseAdminHOLD(time);
        } else {
            try {
                long timeKey = queryMap.lastKey();
                String unholdURL = Core.getUnholdURL(timeKey, adminEmail);
                String blockURL = Core.getBlockURL(timeKey, adminEmail);
                if (unholdURL == null) {
                    return false;
                } else if (blockURL == null) {
                    return false;
                } else {
                    Server.logDebug("sending retention warning by e-mail.");
                    User user = User.get(adminEmail);
                    Locale locale = user == null ? Core.getDefaultLocale(adminEmail) : user.getLocale();
                    Query lastQuery = queryMap.get(timeKey);
                    String key = lastQuery.getWhiteKey() + " " + lastQuery.getBlockKey();
                    String subject;
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        subject = queryMap.size() + " retenções agrupadas por '" + key + "'";
                    } else {
                        subject = queryMap.size() + " retentions grouped for '" + key + "'";
                    }
                    TreeSet<String> subjectSet = new TreeSet<>();
                    TreeSet<String> senderSet = new TreeSet<>();
                    TreeSet<String> recipientSet = new TreeSet<>();
                    TreeSet<String> bodySet = new TreeSet<>();
                    TreeSet<String> linkSet = new TreeSet<>();
                    TreeSet<String> executableSet = new TreeSet<>();
                    for (long time : queryMap.keySet()) {
                        Query query = queryMap.get(time);
                        subjectSet.add(query.getSubject());
                        senderSet.add(query.getSender());
                        recipientSet.add(query.getRecipient());
                        String textBody = query.getTextPlainBody(256);
                        if (textBody != null) {
                            bodySet.add(textBody);
                        }
                        linkSet.addAll(query.getLinkKeySet());
                        executableSet.addAll(query.getExecutableSet());
                    }

                    InternetAddress[] recipients = {Core.getAdminInternetAddress()};
                    MimeMessage message = Core.newMessage();
                    message.addRecipients(Message.RecipientType.TO, recipients);
                    message.setSubject(subject);
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
    //                if (locale.getLanguage().toLowerCase().equals("pt"))
                    {
                        ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagens");
                        ServerHTTP.buildText(builder, "Algumas mensagens foram retidas com os assuntos:");
                        builder.append("    <ul>\n");
                        for (String subjectItem : subjectSet) {
                            builder.append("    <li>");
                            builder.append(subjectItem);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                        ServerHTTP.buildText(builder, "As mensagens foram enviadas pelos seguintes remetentes:");
                        builder.append("    <ul>\n");
                        for (String sender : senderSet) {
                            builder.append("    <li>");
                            builder.append(sender);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                        ServerHTTP.buildText(builder, "Os destinatários destas mensagens são:");
                        builder.append("    <ul>\n");
                        for (String recipient : recipientSet) {
                            builder.append("    <li>");
                            builder.append(recipient);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                        if (!executableSet.isEmpty()) {
                            ServerHTTP.buildText(builder, "<b>Atenção! As seguintes assinaturas de executáveis foram encontradas no corpo das mensagens:</b>");
                            builder.append("    <ul>\n");
                            for (String signature : executableSet) {
                                builder.append("    <li>");
                                builder.append(signature);
                                builder.append("</li>\n");
                            }
                            builder.append("    </ul>\n");
                        }
                        if (!bodySet.isEmpty()) {
                            ServerHTTP.buildText(builder, "Os seguintes textos foram encontrados nos corpos das mensagens:");
                            builder.append("    <ul>\n");
                            for (String text : bodySet) {
                                builder.append("    <li>");
                                builder.append(StringEscapeUtils.escapeHtml4(text));
                                builder.append("</li>\n");
                            }
                            builder.append("    </ul>\n");
                        }
                        if (!linkSet.isEmpty()) {
                            ServerHTTP.buildText(builder, "Os seguintes links foram encontrados no corpo das mensagens:");
                            builder.append("    <ul>\n");
                            for (String link : linkSet) {
                                builder.append("    <li>");
                                builder.append(Core.tryGetSignatureRootURL(link));
                                builder.append("</li>\n");
                            }
                            builder.append("    </ul>\n");
                        }
                        ServerHTTP.buildText(builder, "Se você considera estas mensagens legítimas, acesse esta URL para solicitar a liberação:");
                        ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                        ServerHTTP.buildText(builder, "Se você considera estas mensagens SPAM, acesse esta URL para bloquear o remetente:");
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
                        for (long time : queryMap.keySet()) {
                            Query query = queryMap.get(time);
                            query.CHANGED.acquire();
                            query.adminAdvised = true;
                            query.STORED = false;
                            User.CHANGED = true;
                            query.CHANGED.release(true);
                            User.storeDB(time, query);
                        }
                    } else {
                        return false;
                    }
                    return true;
                }
            } catch (NameNotFoundException ex) {
                return false;
            } catch (CommunicationException ex) {
                return false;
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
}
