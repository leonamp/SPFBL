/*
 * This dataFile is part of SPFBL.
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
import com.mysql.jdbc.exceptions.MySQLTimeoutException;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.smtp.SMTPSendFailedException;
import com.sun.mail.util.MailConnectException;
import com.sun.mail.util.SocketConnectException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.ConcurrentModificationException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeUtility;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import static net.spfbl.core.Core.encrypt32;
import net.spfbl.core.Filterable.Filter;
import static net.spfbl.core.Filterable.Filter.ABUSE_SUBMISSION;
import static net.spfbl.core.Filterable.Filter.USER_PHISHING;
import static net.spfbl.core.Filterable.Filter.USER_SPAM;
import net.spfbl.core.Filterable.Situation;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidRecipient;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import static net.spfbl.core.Server.MINUTE_TIME;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.CIDR;
import net.spfbl.data.DKIM;
import net.spfbl.data.Dictionary;
import net.spfbl.data.FQDN;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Recipient;
import static net.spfbl.data.Recipient.Type.INEXISTENT;
import net.spfbl.data.Reputation;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.DESIRABLE;
import net.spfbl.data.Trap;
import net.spfbl.data.URI;
import net.spfbl.data.White;
import net.spfbl.service.ServerHTTP;
import net.spfbl.service.ServerSMTP;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Qualifier;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.LocaleUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

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
     * Authentication attributes.
     */
    private String otp_secret = null; // Chave oficial.
    private String otp_transition = null; // Chave de transição.
    private byte otp_fail = 0;
    private Integer otp_sucess = null;
    private long otp_last = 0;
    private String password_md5 = null;
    private byte password_fail = 0;
    private long password_last = 0;
    
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
        this.password_md5 = other.password_md5;
        this.password_fail = other.password_fail;
        this.password_last = other.password_last;
        this.queryMap = other.cloneQueryMap(User.this);
        this.identificationMap = other.cloneIdentificationMap();
        this.DEFERED_MAP = other.getDeferedMap();
        this.transportMap = other.getTransportMap();
    }
    
    private User(String email, String name) throws ProcessException {
        if (isValidEmail(email) && simplify(name) != null) {
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
    
    public boolean usingHeader() {
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
    
    public boolean isSameRootDomain(String address) {
        if (address == null) {
            return false;
        } else {
            int index1 = email.indexOf('@') + 1;
            int index2 = address.indexOf('@') + 1;
            String domain1 = Domain.extractDomainSafeNotNull(email.substring(index1), false);
            String domain2 = Domain.extractDomainSafeNotNull(address.substring(index2), false);
            return domain1.equals(domain2);
        }
    }
    
    public boolean isEmail(String email) {
        return this.email.equals(email);
    }
    
    private static final Regex PASSWORD_PATTERN = new Regex("^"
            + "[0-9a-zA-Z@#$%!&?;<>{}]{8,32}"
            + "$"
    );
    
    public boolean setPassword(String password) {
        if (password == null) {
            return false;
        } else {
            String md5 = null;
            if (PASSWORD_PATTERN.matches(password)) {
                md5 = Core.md5Hex(password);
            }
            if (md5 == null) {
                return false;
            } else {
                password_md5 = md5;
                password_fail = 0;
                password_last = 0;
                otp_transition = null;
                otp_fail = 0;
                return CHANGED = true;
            }
        }
    }
    
    public void clearPassword() {
        if (password_md5 != null) {
            password_md5 = null;
            password_fail = 0;
            password_last = 0;
            otp_transition = null;
            CHANGED = true;
        }
    }
    
    public boolean isValidPassword(String password) {
        String md5 = Core.md5Hex(password);
        if (md5 == null) {
            return false;
        } else if (md5.equals(password_md5)) {
            password_fail = 0;
            password_last = System.currentTimeMillis();
            otp_transition = null;
            return true;
        } else {
            password_fail++;
            password_last = System.currentTimeMillis();
            CHANGED = true;
            return false;
        }
    }
    
    public long getFailTimePassword() {
        long thresholdTime = (long) Math.pow(2, password_fail);
        long idleTime = System.currentTimeMillis() - password_last;
        if (idleTime < 1000) {
            return 1000;
        } else {
            return thresholdTime - idleTime;
        }
        
    }
    
    public boolean tooManyFailsPassword() {
        long thresholdTime = (long) Math.pow(2, password_fail);
        long idleTime = System.currentTimeMillis() - password_last;
        if (idleTime < 1000) {
            return false;
        } else {
            return thresholdTime > idleTime;
        }
    }
    
    public boolean hasPassword() {
        return password_md5 != null;
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
    
    public void clearTransitionOTP() {
        CHANGED = true;
        otp_transition = null;
    }
    
    public long getFailTimeOTP() {
        long thresholdTime = (long) Math.pow(2, otp_fail);
        long idleTime = System.currentTimeMillis() - otp_last;
        if (idleTime < 1000) {
            return 1000;
        } else {
            return thresholdTime - idleTime;
        }
        
    }
    
    public boolean tooManyFailsOTP() {
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
        } else if (Core.isTestingVersion() && Core.isMyHostname("localhost")) {
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
    
    private TreeMap<Integer,Properties> transportMap = null;
    
    public synchronized boolean hasTransport() {
        if (transportMap == null) {
            return false;
        } else {
            return !transportMap.isEmpty();
        }
    }
    
    private synchronized Object getTransport() {
        if (transportMap == null) {
            return null;
        } else if (transportMap.isEmpty()) {
            return null;
        } else if (transportMap.size() == 1) {
            int key = transportMap.firstKey();
            return transportMap.get(key);
        } else {
            TreeMap<Integer,Properties> resultMap = new TreeMap<>();
            resultMap.putAll(transportMap);
            return resultMap;
        }
    }
    
    public synchronized TreeMap<Integer,Properties> getTransportMap() {
        if (transportMap == null) {
            return null;
        } else if (transportMap.isEmpty()) {
            return null;
        } else {
            TreeMap<Integer,Properties> resultMap = new TreeMap<>();
            resultMap.putAll(transportMap);
            return resultMap;
        }
    }
    
    public synchronized Properties putTransport(int index, Properties props) {
        if (props == null) {
            return null;
        } else if (transportMap == null) {
            transportMap = new TreeMap<>();
            return transportMap.put(index, props);
        } else {
            return transportMap.put(index, props);
        }
    }
    
    public synchronized Properties removeTransport(int index) {
        if (transportMap == null) {
            return null;
        } else {
            Properties props = transportMap.remove(index);
            if (transportMap.isEmpty()) {
                transportMap = null;
            }
            return props;
        }
    }
    
    public synchronized String setTransport(int index, String name, String value) {
        if (name == null) {
            return null;
        } else if (transportMap == null) {
            return null;
        } else {
            Properties props = transportMap.get(index);
            if (props == null) {
                return null;
            } else if (value == null) {
                return (String) props.remove(name);
            } else if (props.containsKey(name)) {
                return (String) props.put(name, value);
            } else {
                return null;
            }
        }
    }
    
    public synchronized boolean putTransport(int index, String name, String value) {
        if (name == null) {
            return false;
        } else if (value == null) {
            return false;
        } else if (transportMap == null) {
            return false;
        } else {
            Properties props = transportMap.get(index);
            if (props == null) {
                return false;
            } else if (props.containsKey(name)) {
                return false;
            } else {
                props.put(name, value);
                return true;
            }
        }
    }
    
    public static Properties[] getSessionProperties(InternetAddress address) {
        User user = User.getUserFor(address);
        if (user == null) {
            return null;
        } else {
            return user.getSessionProperties();
        }
    }
    
    public Properties[] getSessionProperties() {
        Object result = getTransport();
        if (result instanceof Properties) {
            Properties[] propsArray = new Properties[1];
            propsArray[0] = (Properties) result;
            return propsArray;
        } else if (result instanceof TreeMap) {
            TreeMap<Integer,Properties> resultMap = (TreeMap) result;
            int size = resultMap.size();
            int index = 0;
            Properties[] propsArray = new Properties[size];
            for (Integer key : resultMap.keySet()) {
                propsArray[index++] = resultMap.get(key);
            }
            return propsArray;
        } else {
            return null;
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
    
    private SecretKey secretKey = null;
    private byte[] ivBytes = null;
    
    private synchronized SecretKey getSecretKey() {
        if (secretKey == null) {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                keyGen.init(new SecureRandom());
                secretKey = keyGen.generateKey();
                CHANGED = true;
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        return secretKey;
    }
    
    private transient IvParameterSpec ivParams = null;
    
    private synchronized IvParameterSpec getIV() {
        if (ivBytes == null) {
            SecureRandom randomSecureRandom = new SecureRandom();
            randomSecureRandom.nextBytes(ivBytes = new byte[8]);
            CHANGED = true;
        }
        if (ivParams == null) {
            ivParams = new IvParameterSpec(ivBytes);
        }
        return ivParams;
    }
    
    public static InternetAddress[] getInvitationArray(User user, InternetAddress address) {
        InternetAddress invitation = getInvitation(user, address);
        if (invitation == null) {
            return null;
        } else {
            InternetAddress[] invitationArray = {invitation};
            return invitationArray;
        }
    }
    
    public static InternetAddress getInvitation(User user, InternetAddress address) {
        if (user == null) {
            return null;
        } else if (address == null) {
            return null;
        } else {
            return user.getInvitation(address);
        }
    }
    
    public InternetAddress getInvitation(InternetAddress address) {
        if (address == null) {
            return null;
        } else {
            try {
                String invitation = getInvitation(address.getAddress());
                if (invitation == null) {
                    return null;
                } else {
                    String personal = address.getPersonal();
                    return new InternetAddress(invitation, personal);
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public String getInvitation(String recipient) {
        if (recipient == null) {
            return null;
        } else if (recipient.contains("+")) {
            return null;
        } else {
            try {
                recipient = recipient.toLowerCase();
                long timeMillis = System.currentTimeMillis();
                int timeLong = (int) (timeMillis >>> 32);
                int timeShort = (int) (timeMillis & 0xFFFFFFFF);
                int hashCode = recipient.hashCode() + timeLong;
                // Encrypt.
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.putInt(hashCode);
                buffer.putInt(timeShort);
                byte[] signature = buffer.array();
                Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), getIV());
                byte[] code = cipher.doFinal(signature);
                // Encode.
                String encoded = Core.BASE32STANDARD.encodeToString(code);
                encoded = encoded.substring(0, 13);
                encoded = encoded.toLowerCase();
                // Concatenate.
                int index = recipient.lastIndexOf('@');
                String part = recipient.substring(0, index);
                String domain = recipient.substring(index);
                return part + "+" + encoded + domain;
            } catch (Exception ex) {
                Server.logError(ex);
                return recipient;
            }
        }
    }
    
    public boolean isInvitation(String recipient, String subaddress) {
        if (recipient == null) {
            return false;
        } else if (subaddress == null) {
            return false;
        } else if (subaddress.length() != 13) {
            return false;
        } else if (recipient.contains("+")) {
            return false;
        } else {
            try {
                // Decode.
                subaddress = subaddress.toUpperCase();
                byte[] code = Core.BASE32STANDARD.decode(subaddress);
                if (code.length == 8) {
                    // Decrypt.
                    Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), getIV());
                    code = cipher.doFinal(code);
                    ByteBuffer buffer = ByteBuffer.wrap(code);
                    long timeMillis = System.currentTimeMillis();
                    int timeLong = (int) (timeMillis >>> 32);
                    int hashCode = buffer.getInt() - timeLong;
                    int timeShort = buffer.getInt();
                    long creation = 0;
                    recipient = recipient.toLowerCase();
                    // Compare.
                    if (hashCode == recipient.hashCode()) {
                        creation = timeLong & 0x00000000FFFFFFFFL;
                        creation <<= 32;
                        creation |= timeShort & 0x00000000FFFFFFFFL;
                    } else if (hashCode + 1 == recipient.hashCode()) {
                        creation = timeLong & 0x00000000FFFFFFFFL;
                        creation--;
                        creation <<= 32;
                        creation |= timeShort & 0x00000000FFFFFFFFL;
                    }
                    return System.currentTimeMillis() - creation < Server.DAY_TIME;
                } else {
                    return false;
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
        
    public boolean isInvitation(String recipient) {
        if (recipient == null) {
            return false;
        } else {
            int index1 = recipient.indexOf('+');
            int index2 = recipient.lastIndexOf('@');
            if (index1 > 0 && index2 > 0) {
                // Subaddress Extension.
                // https://tools.ietf.org/html/rfc5233.html
                String subaddress = recipient.substring(index1 + 1, index2);
                // Concatenate.
                String part = recipient.substring(0, index1);
                String domain = recipient.substring(index2);
                recipient = part + domain;
                recipient = recipient.toLowerCase();
                return isInvitation(recipient, subaddress);
            } else {
                return false;
            }
        }
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
                if (query.isResult("HOLD")) {
                    processExpired(time, query);
                } else if (query.setResult("GREYLIST", "REJECT")) {
                    query.addUnacceptable();
                } else if (query.setResult("LISTED", "REJECT")) {
                    query.addUnacceptable();
                }
                storeDB(time, query);
            }
            if (dropQuery(time)) {
                CHANGED = true;
            }
        }
    }
    
    private static boolean processExpired(long timeKey, Query query) {
        if (query == null) {
            return false;
        } else {
            SimpleImmutableEntry<Filter,String> filterEntry = query.processFilterExpired();
            Filter filter = filterEntry.getKey();
            String reason = filterEntry.getValue();
            String filterResult = filter.name() + (reason == null ? "" : ';' + reason);
            switch (filter) {
                case HOLD_WHITE_KEY_USER: // 50,00%
                    query.setResult("WHITE");
                    query.addBeneficial(timeKey);
                    break;
                case HOLD_BLOCK_KEY_USER: // 50,00%
                    query.setResult("BLOCK");
                    query.addUndesirable(timeKey);
                    break;
                case HOLD_WHITE_KEY_ADMIN: // 97,64%
                case HOLD_WHITELISTED: // 97,14%
                    query.whiteKey(timeKey);
                    query.setResultFilter("WHITE", filterResult);
                    query.addDesirable(timeKey);
                    break;
                case HOLD_SPF_FAIL: // 50,00%
                    query.blockKey(timeKey, "SPF_FAIL");
                case HOLD_BANNED: // 50,00%
                    query.setResultFilter("BLOCK", filterResult);
                    query.addHarmful(timeKey);
                    break;
                case HOLD_BLOCK_KEY_ADMIN: // 99,93%
                case HOLD_BLOCKED: // 98,60%
                case HOLD_SENDER_RED: // 96,97%
                case HOLD_UNDESIRABLE: // 93,81%
                case HOLD_RECIPIENT_RESTRICT: // 92,86%
                case HOLD_ENVELOPE_BLOCKED: // 89,07%
                case HOLD_HREF_SUSPECT: // 86,84%
                case HOLD_ENVELOPE_UNDESIRABLE: // 50,00%
                    query.blockKey(timeKey, filter.name());
                    query.setResultFilter("BLOCK", filterResult);
                    query.addUndesirable(timeKey);
                    break;
                case HOLD_DOMAIN_EMERGED: // 89,15%
                case HOLD_RECIPIENT_UNDESIRABLE: // 50,00%
                    query.setResultFilter("ACCEPT", filterResult);
                    query.addAcceptable();
                    break;
                case HOLD_EXPIRED: // 79,64%
                case HOLD_SPF_SOFTFAIL: // 76,00%
                case HOLD_FQDN_RED: // 66,67%
                    query.setResultFilter("REJECT", filterResult);
                    query.addUnacceptable();
                    break;
                default:
                    Server.logError("undefined filter: " + filter.name());
                    query.setResultFilter("ACCEPT", filterResult);
                    query.addAcceptable();
            }
            query.adviseMailerDaemonHOLDING(timeKey);
            return true;
        }
    }
    
    private static final int QUERY_MAX = 256;
    
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
        if (Core.isRunning()) {
            for (User user : getUserList()) {
                user.dropExpiredQuery();
                user.hairCutQuery();
                user.dropExpiredIdentification();
            }
        }
    }
    
    public static void dropAllExpiredDefered() {
        if (Core.isRunning()) {
            for (User user : getUserList()) {
                user.dropExpiredDeferedMap();
            }
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
        } else if (isValidEmail(address = address.toLowerCase())) {
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
    private static final HashMap<String,Object> MAP = new HashMap<>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public synchronized static User create(
            String email, String name
    ) throws ProcessException {
        if (email == null) {
            return null;
        } else {
            Object value;
            while ((value = MAP.get(email.toLowerCase())) instanceof String) {
                email = (String) value;
            }
            if (value instanceof User) {
                return (User) value;
            } else {
                User user = new User(email, name);
                MAP.put(email, user);
                CHANGED = true;
                return user;
            }
        }
    }
    
    public synchronized static TreeSet<String> getKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    public synchronized static TreeMap<String,Object> getMap() {
        TreeMap<String,Object> resultMap = new TreeMap<>();
        resultMap.putAll(MAP);
        return resultMap;
    }
    
    public static ArrayList<User> getUserList() {
        TreeSet<String> keySet = getKeySet();
        int n = keySet.size();
        ArrayList<User> userList = new ArrayList<>(n);
        for (String key : keySet) {
            Object value = MAP.get(key);
            if (value instanceof User) {
                userList.add((User) value);
            }
        }
        return userList;
    }
    
    public synchronized static Object drop(String email) {
        Object value = MAP.remove(email);
        if (value != null) {
            CHANGED = true;
        }
        return value;
    }
    
    private synchronized static boolean putAlias(String key, String value) {
        Object oldValue = MAP.put(key, value);
        if (oldValue instanceof User) {
            MAP.put(key, oldValue);
            return false;
        } else {
            return !value.equals(oldValue);
        }
    }
    
    public static boolean alias(String key, String value) {
        if ((key = Domain.normalizeEmail(key)) == null) {
            return false;
        } else if ((value = Domain.normalizeEmail(value)) == null) {
            return false;
        } else {
            key = key.toLowerCase();
            value = value.toLowerCase();
            if (key.equals(value)) {
                return false;
            } else {
                return putAlias(key, value);
            }
        }
    }
    
    public static TreeSet<Object> dropAll() {
        TreeSet<Object> dropSet = new TreeSet<>();
        for (String key : getKeySet()) {
            Object value = MAP.get(key);
            if (value instanceof User) {
                User user = (User) value;
                String email = user.getEmail();
                if (drop(email) != null) {
                    dropSet.add(user);
                }
            } else if (value instanceof String) {
                String alias = (String) value;
                if (drop(alias) != null) {
                    dropSet.add(alias);
                }
            }
        }
        return dropSet;
    }
    
    public static boolean isAlias(String email) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return false;
        } else {
            Object value = MAP.get(email);
            if (value instanceof User) {
                return false;
            } else {
                return true;
            }
        }
    }
    
    public static User getExact(String email) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return null;
        } else {
            Object value = MAP.get(email);
            if (value instanceof User) {
                return (User) value;
            } else {
                return null;
            }
        }
    }
    
    public static User get(String email) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return null;
        } else {
            Object value;
            while ((value = MAP.get(email)) instanceof String) {
                email = (String) value;
            }
            if (value instanceof User) {
                return (User) value;
            } else {
                return null;
            }
        }
    }
    
    public static User get(String email, String password) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return null;
        } else if (password == null) {
            return null;
        } else {
            Object value;
            while ((value = MAP.get(email)) instanceof String) {
                email = (String) value;
            }
            if (value instanceof User) {
                User user = (User) value;
                if (user.isValidPassword(password)) {
                    return user;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }
    }
    
    private static Object clone(String email) {
        if (email == null) {
            return null;
        } else {
            Object value = MAP.get(email);
            if (value instanceof User) {
                return new User((User) value);
            } else {
                return value;
            }
        }
    }
    
    public static boolean exists(String... emailSet) {
        if (emailSet == null) {
            return false;
        } else {
            for (String email : emailSet) {
                if (MAP.containsKey(email)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    private static HashMap<String,Object> getHashMap() {
        if (Core.isRunning()) {
            HashMap<String,Object> map = new HashMap<>();
            for (String key : getKeySet()) {
                Object value = clone(key);
                if (value != null) {
                    map.put(key, value);
                }
            }
            return map;
        } else {
            return MAP;
        }
    }
    
    public static void store() {
        closeExpiredHistory();
        removeExpiredHistory();
        dropAllExpiredQuery();
        dropAllExpiredDefered();
        storeMap();
    }
    
    public static void storeMap() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,Object> map = getHashMap();
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
                    key = Domain.normalizeEmail(key);
                    if (value instanceof User) {
                        User user = (User) value;
                        if (user.locale == null) {
                            user.locale = Core.getDefaultLocale(user.email);
                        }
                        if (user.timezone == null) {
                            user.timezone = Core.getDefaultTimeZone(user.email);
                        }
                        if (user.password_md5 != null) {
                            user.otp_transition = null;
                        }
                        for (long time2 : user.getTimeKeySet()) {
                            Query query = user.getQuery(time2);
                            if (query.unsubscribe != null && !query.unsubscribe.getProtocol().matches("^https?$")) {
                                query.unsubscribe = null;
                            }
                            if (query.date != null && Math.abs(time2 - query.date.getTime()) > 31104000000L) {
                                query.date = null;
                            }
                            if (query.sender != null && !query.sender.contains("@")) {
                                query.sender = null;
                            }
                            if (query.from != null && !query.from.contains("@")) {
                                query.from = null;
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
                    } else if (value instanceof String) {
                        String alias = (String) value;
                        alias = Domain.normalizeEmail(alias);
                        MAP.put(key, alias);
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
    
    private HashMap<String,Long> identificationMap = null;
    
    public static User getUserByIdentification(
            String messageID, String queueID, String fqdn
    ) {
        if (messageID == null) {
            return null;
        } else if (queueID == null) {
            return null;
        } else if (fqdn == null) {
            return null;
        } else {
            for (User user : getUserList()) {
                Long timeKey = user.getTimeByIdentification(messageID);
                Query query = user.getQuery(timeKey);
                if (query == null) {
                    timeKey = user.getTimeByIdentification(queueID, fqdn);
                    query = user.getQuery(timeKey);
                }
                if (query != null) {
                    if (query.isMessageID(messageID)) {
                        return user;
                    } else if (query.isQueueID(fqdn, queueID)) {
                        return user;
                    }
                }
            }
            return null;
        }
    }
    
    public synchronized Long getTimeByIdentification(String messageID) {
        if (messageID == null) {
            return null;
        } else if (identificationMap == null) {
            return null;
        } else {
            return identificationMap.get(messageID);
        }
    }
    
    public synchronized Long getTimeByIdentification(String queueID, String fqdn) {
        if (queueID == null) {
            return null;
        } else if (fqdn == null) {
            return null;
        } else if (identificationMap == null) {
            return null;
        } else {
            return identificationMap.get(queueID + '@' + fqdn);
        }
    }
    
    public synchronized boolean putIdentification(String messageID, Long timeKey) {
        if (messageID == null) {
            return false;
        } else if (timeKey == null) {
            return false;
        } else {
            if (identificationMap == null) {
                identificationMap = new HashMap<>();
            }
            Long oldValue = identificationMap.put(messageID, timeKey);
            if (oldValue == null) {
                return CHANGED = true;
            } else if (oldValue.equals(timeKey)) {
                return false;
            } else {
                return CHANGED = true;
            }
        }
    }
    
    public synchronized boolean putIdentification(String queueID, String fqdn, long timeKey) {
        if (queueID == null) {
            return false;
        } else if (fqdn == null) {
            return false;
        } else {
            if (identificationMap == null) {
                identificationMap = new HashMap<>();
            }
            Long oldValue = identificationMap.put(queueID + '@' + fqdn, timeKey);
            if (oldValue == null) {
                return CHANGED = true;
            } else if (oldValue.equals(timeKey)) {
                return false;
            } else {
                return CHANGED = true;
            }
        }
    }
    
    private synchronized boolean dropIdentification(String messageID) {
        if (messageID == null) {
            return false;
        } else if (identificationMap == null) {
            return false;
        } else {
            Long oldValue = identificationMap.remove(messageID);
            if (oldValue == null) {
                return false;
            } else if (identificationMap.isEmpty()) {
                identificationMap = null;
                return CHANGED = true;
            } else {
                return CHANGED = true;
            }
        }
    }
    
    private void dropExpiredIdentification() {
        HashMap<String,Long> idMap = cloneIdentificationMap();
        if (idMap != null) {
            for (String messageID : idMap.keySet()) {
                long timeKey = idMap.get(messageID);
                if (System.currentTimeMillis() - timeKey > Server.WEEK_TIME) {
                    dropIdentification(messageID);
                }
            }
        }
    }
    
    private synchronized HashMap<String,Long> cloneIdentificationMap() {
        if (identificationMap == null) {
            return null;
        } else {
            HashMap<String,Long> resultMap = new HashMap<>();
            resultMap.putAll(identificationMap);
            return resultMap;
        }
    }
    
    /**
     * Registro de consultas.
     */
    private TreeMap<Long,Query> queryMap = null;
    
    public User.Query addQuery(
            long time,
            InetAddress clientIP,
            Client client,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
    ) {
        SPF.Qualifier qualifierEnum;
        try {
            qualifierEnum = SPF.Qualifier.valueOf(qualifier);
        } catch (Exception ex) {
            qualifierEnum = null;
        }
        String fqdn;
        if (client != null) {
            return addQuery(
                    time, clientIP, client, ip, helo, hostname, sender,
                    qualifierEnum, recipient, subaddress, tokenSet,
                    result, filter
            );
        } else if ((fqdn = FQDN.getFQDN(clientIP, false)) != null) {
            return addQuery(
                    time, fqdn, ip, helo, hostname, sender,
                    qualifierEnum, recipient, subaddress, tokenSet,
                    result, filter
            );
        } else {
            return addQuery(
                    time, this.getDomain(), ip, helo, hostname, sender,
                    qualifierEnum, recipient, subaddress, tokenSet,
                    result, filter
            );
        }
    }
    
    public User.Query addQuery(
            long time,
            InetAddress clientIP,
            Client client,
            String ip,
            String helo,
            String hostname,
            String sender,
            SPF.Qualifier qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
    ) {
        try {
            String clientFQDN = FQDN.getFQDN(clientIP, false);
            Query query = new Query(
                    clientFQDN,
                    client,
                    ip,
                    helo,
                    hostname,
                    sender,
                    qualifier,
                    recipient,
                    subaddress,
                    tokenSet,
                    result,
                    filter
            );
            putQuery(time, query);
            storeDB(time, query);
            return query;
        } catch (ProcessException ex) {
            Server.logError(ex);
            return null;
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
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
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
                    subaddress,
                    tokenSet,
                    result,
                    filter
            );
            putQuery(time, query);
            storeDB(time, query);
            return query;
        } catch (ProcessException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public User.Query newQuery(
            String client,
            String ip,
            String helo,
            String fqdn,
            String sender,
            SPF.Qualifier qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String from,
            String replyTo,
            Date date,
            URL unsubscribe,
            TreeSet<String> signerSet,
            String subject,
            String messageID,
            String queueID,
            Date arrival
    ) {
        return new Query(
                client, ip, helo, fqdn, sender, qualifier, recipient, subaddress,
                tokenSet, result, from, replyTo, date, unsubscribe,
                signerSet, subject, messageID, queueID, arrival
        );
    }
    
    public static TreeMap<Long,Query> getQueries(
            String email, long timeKey, String blockKey
    ) throws Exception {
        if (blockKey == null) {
            return null;
        } else {
            TreeMap<Long,Query> resultMap = new TreeMap<>();
            for (User user : getUserList()) {
                if (user.isEmail(email)) {
                    Query query = user.getQuerySafe(timeKey);
                    if (query != null) {
                        resultMap.put(timeKey, query);
                    }
                }
                for (long timeKey2 : user.getTimeKeySet()) {
                    Query query = user.getQuery(timeKey2);
                    if (query != null) {
                        if (timeKey == timeKey2) {
                            resultMap.put(timeKey2, query);
                        } else if (query.isHolding() && blockKey.equals(query.getBlockKey())) {
                            resultMap.put(timeKey2, query);
                        }
                    }
                }
            }
            return resultMap;
        }
    }
    
    public TreeMap<Long,Query> getQueryMap(
            Long begin, String filter
    ) {
        long timeLast = begin == null ? System.currentTimeMillis() : begin;
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        TreeMap<Long,Query> queryLocalMap;
        if (isAdmin()) {
            queryLocalMap = getAllQueryHeadMap(begin, 1024);
        } else {
            queryLocalMap = getQueryHeadMap(begin, 1024);
        }
        long timeRED;
        if (Core.hasMySQL() || hasHistory()) {
            long deferTimeRED = Core.getDeferTimeRED() * 60000L;
            timeRED = System.currentTimeMillis() - deferTimeRED;
        } else {
            timeRED = 0;
        }
        Entry<Long,Query> entry;
        while ((entry = queryLocalMap.pollLastEntry()) != null) {
            long timeKey = entry.getKey();
            if (timeKey > timeRED) {
                Query query = entry.getValue();
                if (filter == null) {
                    resultMap.put(timeKey, query);
                } else if (filter.length() == 0) {
                    resultMap.put(timeKey, query);
                } else if (query.matchAll(timeKey, filter)) {
                    resultMap.put(timeKey, query);
                }
            } else {
                break;
            }
        }
        boolean finished = false;
        if (resultMap.isEmpty() && hasHistory()) {
            long start = System.currentTimeMillis();
            long end;
            long dayKey = (begin == null ? start : begin) / Server.DAY_TIME;
            long dayMin = (start / Server.DAY_TIME) - HISTORY_EXPIRES;
            try {
                do {
                    timeLast = dayKey * Server.DAY_TIME;
                    History history = getHistoryByDay(dayKey);
                    if (history == null) {
                        break;
                    } else {
                        for (long timeKey : history.getTimeKeySet(User.this)) {
                            if (begin == null || timeKey < begin) {
                                Query query = history.load(this, timeKey);
                                if (query != null) {
                                    if (filter == null) {
                                        resultMap.put(timeKey, query);
                                    } else if (filter.length() == 0) {
                                        resultMap.put(timeKey, query);
                                    } else if (query.matchAll(timeKey, filter)) {
                                        resultMap.put(timeKey, query);
                                    }
                                }
                            }
                        }
                    }
                    dayKey--;
                    end = System.currentTimeMillis();
                } while (dayKey >= dayMin && resultMap.size() < 32 && end - start < 5000);
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                finished = dayKey < dayMin;
            }
        }
        if (resultMap.isEmpty() && Core.hasMySQL()) {
            finished = true;
            Date date = null;
            String ipParam = null;
            String emailParam = null;
            String domainParam = null;
            boolean rejectedParam = false;
            boolean unsuspectedParam = false;
            boolean suspectedParam = false;
            boolean whitelistedParam = false;
            boolean malwareParam = false;
            boolean trapParam = false;
            if (filter != null) {
                filter = filter.toLowerCase();
                StringTokenizer tokenizer = new StringTokenizer(filter, ",");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    token = token.trim();
                    date = getDate(token, date);
                    ipParam = isValidIP(token) ? Subnet.normalizeIP(token) : ipParam;
                    if (isValidEmail(token)) {
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
                        case "greylisting": case "greylist":
                            return new TreeMap<>();
                        case "insuspeita": case "insuspeito": case "unsuspected":
                        case "insuspeitas": case "insuspeitos":
                        case "aceita": case "aceitas":
                        case "aceito": case "aceitos":
                            unsuspectedParam = true;
                            break;
                        case "suspeito": case "suspeita":
                        case "suspeitos": case "suspeitas":
                        case "flagged": case "junk":
                        case "suspect": case "suspects": case "suspected":
                            suspectedParam = true;
                            break;
                        case "confiavel": case "confiaveis": case "whitelisted":
                        case "confiável": case "confiáveis":
                            whitelistedParam = true;
                        case "malware": case "virus": case "vírus":
                            malwareParam = true;
                        case "trap": case "spamtrap":
                            trapParam = true;
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
                    + (suspectedParam ? "AND result = 'FLAG'\n" : "")
                    + (whitelistedParam ? "AND result = 'WHITE'\n" : "")
                    + (trapParam ? "AND result = 'TRAP'\n" : "")
                    + (malwareParam ? "AND malware IS NOT NULL\n" : "")
                    + (ipParam == null ? "" : "AND ip = '" + ipParam + "'\n")
                    + (emailParam == null ? "" : ""
                    + "AND (sender = '" + emailParam + "' "
                    + "OR mailFrom = '" + emailParam + "' "
                    + "OR replyto = '" + emailParam + "' "
                    + "OR recipient = '" + emailParam + "')\n")
                    + (domainParam == null ? "" : ""
                    + "AND (client = '" + domainParam + "' "
                    + "OR helo = '" + domainParam.substring(1) + "' "
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
                resultMap.put(timeLast - 1, null);
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
        byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
        if (byteArray == null) {
            return null;
        } else if (byteArray.length > 8) {
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
                        if (isValidEmail(token)) {
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
    }
    
    public static Entry<Long,Query> getQueryEntrySafe(String ticket) {
        byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
        if (byteArray == null) {
            return null;
        } else if (byteArray.length > 8) {
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
            ticket = Core.decodeHuffman(byteArray, 8);
            StringTokenizer tokenizer = new StringTokenizer(ticket, " ");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                if (token.endsWith(":")) {
                    int endIndex = token.length() - 1;
                    token = token.substring(0, endIndex);
                    if (isValidEmail(token)) {
                        User user = User.get(token);
                        if (user == null) {
                            return null;
                        } else {
                            Query query = user.getQuerySafe(date);
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
        } else {
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
    
    public Query getQuery(byte version, DataInput dis) throws Exception {
        return new Query(version, dis);
    }
    
    public static User getUserFor(InternetAddress address) {
        if (address == null) {
            return null;
        } else {
            return getUserFor(address.getAddress());
        }
    }
    
    public static User getUserFor(String email) {
        if (email == null) {
            return null;
        } else {
            email = email.toLowerCase();
            User user = User.get(email);
            if (user == null) {
                int index = email.indexOf('@');
                String domain = email.substring(index);
                user = User.get("postmaster" + domain);
            }
            return user;
        }
    }
    
    public static Query getQuery(User user, Long time) {
        if (user == null) {
            return null;
        } else if (time == null) {
            return null;
        } else {
            return user.getQuerySafe(time);
        }
    }
    
    public static Query getQuery(String email, long time) {
        if (email == null) {
            return null;
        } else {
            email = email.toLowerCase();
            User user = User.get(email);
            if (user == null) {
                int index = email.indexOf('@');
                String domain = email.substring(index);
                user = User.get("postmaster" + domain);
            }
            if (user == null) {
                return null;
            } else {
                return user.getQuerySafe(time);
            }
        }
    }
    
    public static Query getAnyQuery(long time) {
        ArrayList<User> userSet = User.getUserList();
        for (User user : userSet) {
            Query query = user.getQuery(time);
            if (query != null) {
                return query;
            }
        }
        for (User user : userSet) {
            Query query = user.loadHistory(time);
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
                        statement.setQueryTimeout(5);
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
    
    public Query getQuerySafe(Long time) {
        if (time == null) {
            return null;
        } else {
            Query query = getQuery(time);
            if (query == null) {
                query = loadHistory(time);
            }
            if (query == null && Core.hasMySQL()) {
                long time2 = System.currentTimeMillis();
                String command = "SELECT * FROM user_query\n"
                        + "WHERE time = " + time
                        + (isAdmin() ? "" : "\nAND user = '" + getEmail() + "'");
                Connection connection = Core.aquireConnectionMySQL();
                if (connection != null) {
                    try {
                        try (Statement statement = connection.createStatement()) {
                            statement.setQueryTimeout(5);
                            ResultSet rs = statement.executeQuery(command);
                            if (rs.next()) {
                                query = User.getUserQuery(rs);
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
    }
    
    private HashMap<String,Long> DEFERED_MAP = null;
    
    private synchronized HashMap<String,Long> getDeferedMap() {
        if (DEFERED_MAP == null) {
            return null;
        } else {
            HashMap<String,Long> resultMap = new HashMap<>();
            resultMap.putAll(DEFERED_MAP);
            return resultMap;
        }
    }
    
    private synchronized TreeSet<String> getDeferedKeySet() {
        TreeSet<String> resultSet = new TreeSet<>();
        if (DEFERED_MAP != null) {
            resultSet.addAll(DEFERED_MAP.keySet());
        }
        return resultSet;
    }
    
    private synchronized Long removeDeferedTimeKey(String flowKey) {
        if (flowKey == null) {
            return null;
        } else if (DEFERED_MAP == null) {
            return null;
        } else {
            Long timeKey = DEFERED_MAP.remove(flowKey);
            if (DEFERED_MAP.isEmpty()) {
                DEFERED_MAP = null;
            }
            return timeKey;
        }
    }
    
    private synchronized Long getDeferedTimeKey(String flowKey) {
        if (flowKey == null) {
            return null;
        } else if (DEFERED_MAP == null) {
            return null;
        } else {
            return DEFERED_MAP.get(flowKey);
        }
    }
    
    private synchronized boolean putDeferedTimeKey(String flowKey, Long timeKey) {
        if (flowKey == null) {
            return true;
        } else if (timeKey == null) {
            return false;
        } else {
            if (DEFERED_MAP == null) {
                DEFERED_MAP = new HashMap<>();
            }
            return !Objects.equals(
                    DEFERED_MAP.put(flowKey, timeKey),
                    timeKey
            );
        }
    }
    
    public void dropExpiredDeferedMap() {
        for (String flowKey : getDeferedKeySet()) {
            Long timeKey = getDeferedTimeKey(flowKey);
            if (timeKey != null && System.currentTimeMillis() - timeKey > Server.WEEK_TIME) {
                removeDeferedTimeKey(flowKey);
            }
        }
    }
    
    private static String getDeferedFlowKey(
            String ip,
            String hostname,
            String sender,
            String recipient
    ) {
        if ((ip = Subnet.normalizeIP(ip)) == null) {
            return null;
        } else {
            hostname = Domain.normalizeHostname(hostname, false);
            String flowKey = (sender == null ? "MAILER-DAEMON" : sender);
            flowKey += ">" + (hostname == null ? ip : hostname);
            flowKey += ">" + (recipient == null ? "@" : recipient);
            return flowKey;
        }
    }

    public boolean setDeferedQuery(
            long timeKey,
            String ip,
            String hostname,
            String sender,
            String recipient,
            String result
    ) {
        if (result == null) {
            return false;
        } else if (result.equals("GREYLIST") || result.equals("LISTED")) {
            String flowKey = getDeferedFlowKey(ip, hostname, sender, recipient);
            return putDeferedTimeKey(flowKey, timeKey);
        } else {
            return false;
        }
    }
    
    public Object[] getDeferedQuery(
            String ip,
            String hostname,
            String sender,
            String recipient,
            String newResult
    ) {
        String flowKey = getDeferedFlowKey(ip, hostname, sender, recipient);
        Long timeKey = removeDeferedTimeKey(flowKey);
        if (timeKey != null) {
            Query query = getQuery(timeKey);
            if (query != null) {
                String oldResult = query.getResult();
                if (oldResult.equals("GREYLIST") || oldResult.equals("LISTED")) {
                    if (query.isOrigin(ip, hostname) && query.isMailFromTo(sender, recipient)) {
                        if (query.setResult(oldResult, newResult)) {
                            Object[] resultSet = new Object[2];
                            resultSet[0] = timeKey;
                            resultSet[1] = query;
                            storeDB(timeKey, query);
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
    
    public static boolean hasHistory() {
        File folder = new File("./history/");
        return folder.exists();
    }
    
    public Query loadHistory(long timeKey) {
        try {
            History history = getHistoryByTime(timeKey, false);
            if (history == null) {
                return null;
            } else {
                return history.load(User.this, timeKey);
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public synchronized Query getQuery(long time) {
        if (queryMap == null) {
            return null;
        } else {
            Query query = queryMap.get(time);
            if (query != null) {
                return query;
            } else if (isAdmin()) {
                for (User user : User.getUserList()) {
                    if (user.queryMap != null) {
                        query = user.queryMap.get(time);
                        if (query != null) {
                            return query;
                        }
                    }
                }
                return null;
            } else {
                return null;
            }
        }
    } 
    
    public synchronized TreeSet<Long> getTimeKeySet() {
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
        for (User user : User.getUserList()) {
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
    
    public static TreeMap<Long,Query> getAllQueryHeadMap(Long begin, int limit) {
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        for (User user : User.getUserList()) {
            resultMap.putAll(user.getQueryHeadMap(begin, limit));
        }
        return resultMap;
    }
    
    public synchronized TreeSet<Long> getQuerySet(Long begin, int limit) {
        if (queryMap == null) {
            return new TreeSet<>();
        } else if (begin == null) {
            TreeSet<Long> resultSet = new TreeSet<>();
            for (long timeKey : queryMap.descendingKeySet()) {
                if (resultSet.size() < limit) {
                    resultSet.add(timeKey);
                } else {
                    break;
                }
            }
            return resultSet;
        } else {
            TreeSet<Long> tempSet = new TreeSet<>();
            tempSet.addAll(queryMap.headMap(begin).keySet());
            TreeSet<Long> resultSet = new TreeSet<>();
            for (long timeKey : tempSet.descendingSet()) {
                if (resultSet.size() < limit) {
                    resultSet.add(timeKey);
                } else {
                    break;
                }
            }
            return resultSet;
        }
    }
    
    public Query getQuery(Long timeKey) {
        if (timeKey == null) {
            return null;
        } else if (queryMap == null) {
            return null;
        } else {
            return queryMap.get(timeKey);
        }
    }
    
    public TreeMap<Long,Query> getQueryHeadMap(Long begin, int limit) {
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        for (long timeKey : getQuerySet(begin, limit)) {
            Query query = getQuery(timeKey);
            if (query == null) {
                break;
            } else {
                resultMap.put(timeKey, query);
            }
        }
        return resultMap;
    }
    
    private synchronized boolean putQuery(long time, Query query) {
        if (query == null) {
            return false;
        } else {
            if (queryMap == null) {
                queryMap = new TreeMap<>();
            }
            queryMap.put(time, query);
            return CHANGED = true;
        }
    }
    
    private TreeMap<Long,Query> cloneQueryMap(User other) {
        TreeMap<Long,Query> resultMap = new TreeMap<>();
        for (long time : getTimeKeySet()) {
            Query query = getQuery(time);
            if (query != null) {
                resultMap.put(time, other.cloneQuery(query));
            }
        }
        return resultMap;
    }
    
    public Entry<Long,Query> getByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return null;
        } else {
            Long timeFound = getTimeByIdentification(messageID);
            Query queryFound = getQuerySafe(timeFound);
            if (queryFound == null) {
                for (long time : getTimeKeySet().descendingSet()) {
                    Query query = getQuerySafe(time);
                    if (query != null && query.isMessage(messageID)) {
                        timeFound = time;
                        queryFound = query;
                        putIdentification(messageID, time);
                        break;
                    }
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
                            statement.setQueryTimeout(5);
                            ResultSet rs = statement.executeQuery(command);
                            if (rs.next()) {
                                timeFound = rs.getLong("time");
                                queryFound = new Query(rs);
                                putIdentification(messageID, timeFound);
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
            if (timeFound == null) {
                return null;
            } else if (queryFound == null) {
                return null;
            } else {
                return new SimpleImmutableEntry<>(timeFound, queryFound);
            }
        }
    }
    
    public String blockByMessageID(String messageID) {
        if (messageID == null || messageID.length() == 0) {
            return "INVALID MESSAGE";
        } else {
            Long timeFound = getTimeByIdentification(messageID);
            Query queryFound = getQuerySafe(timeFound);
            if (queryFound == null) {
                for (long time : getTimeKeySet().descendingSet()) {
                    Query query = getQuerySafe(time);
                    if (query != null && query.isMessage(messageID)) {
                        timeFound = time;
                        queryFound = query;
                        putIdentification(messageID, time);
                        break;
                    }
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
                            statement.setQueryTimeout(5);
                            ResultSet rs = statement.executeQuery(command);
                            if (rs.next()) {
                                timeFound = rs.getLong("time");
                                queryFound = new Query(rs);
                                putIdentification(messageID, timeFound);
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
            if (timeFound == null || queryFound == null) {
                return "MESSAGE NOT FOUND";
            } else if (queryFound.isWhiteKey() && queryFound.isDesirable()) {
                if (queryFound.setSpam(timeFound)) {
                    return "COMPLAINED " + queryFound.getTokenSet();
                } else {
                    return "ALREADY COMPLAINED";
                }
            } else if (queryFound.isHarmful()) {
                if (queryFound.blockKey(timeFound, "HARMFUL")) {
                    return "BLOCKED " + queryFound.getBlockKey();
                } else if (queryFound.setSpam(timeFound)) {
                    return "COMPLAINED " + queryFound.getTokenSet();
                } else {
                    return "ALREADY COMPLAINED";
                }
            } else if (queryFound.blockForRecipient(timeFound)) {
                queryFound.setSpam(timeFound);
                return "BLOCKED " + queryFound.getBlockKey() + ">" + queryFound.getRecipient();
            } else if (queryFound.setSpam(timeFound)) {
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
                for (long time : getTimeKeySet().descendingSet()) {
                    Query query = getQuerySafe(time);
                    if (query != null && query.isSubject(subject)) {
                        queryMap.put(time, query);
                        blockKeySet.add(query.getBlockKey());
                    }
                }
                if (blockKeySet.size() == 1) {
                    long time = queryMap.firstKey();
                    Query query = queryMap.get(time);
                    if (query.isWhiteKey() && query.isDesirable()) {
                        if (query.setSpam(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.isHarmful()) {
                        if (query.blockKey(time, "HARMFUL")) {
                            return "BLOCKED " + query.getBlockKey();
                        } else if (query.setSpam(time)) {
                            return "COMPLAINED " + query.getTokenSet();
                        } else {
                            return "ALREADY COMPLAINED";
                        }
                    } else if (query.blockForRecipient(time)) {
                        query.setSpam(time);
                        return "BLOCKED " + query.getBlockKey() + ">" + query.getRecipient();
                    } else if (query.setSpam(time)) {
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
            for (User user : User.getUserList()) {
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
            for (long time : getTimeKeySet().descendingSet()) {
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
                                case BULK:
                                    return "ADDED " + query.getSenderSimplified(false, true) + ";BULK";
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
        } else if (isValidIP(token)) {
            token = SubnetIPv6.tryTransformToIPv4(token);
            if (Subnet.isReservedIP(token)) {
                return null;
            } else {
                return Subnet.normalizeIP(token);
            }
        } else if (isValidEmail(token)) {
            return Domain.normalizeEmail(token);
        } else if (Domain.isOfficialTLD(token)) {
            return null;
        } else if (isHostname(token)) {
            return Domain.normalizeHostname(token, false);
        } else {
            return null;
        }
    }
    
    private static String normalizeSigner(String signer) {
        if (signer == null) {
            return null;
        } else if (isHostname(signer)) {
            return Domain.normalizeHostname(signer, false);
        } else {
            return null;
        }
    }

    public boolean adviseMailerDaemonHOLDING() {
        try {
            boolean advised = false;
            for (long time : getTimeKeySet()) {
                Query query = getQuery(time);
                if (query != null && query.isHolding()) {
                    if (query.hasDefinedKey()) {
                        if (query.adviseMailerDaemonHOLDING(time)) {
                            advised = true;
                        }
                    }
                }
            }
            return advised;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean isExpiredHOLD(long time) {
        long expireTime = Core.getDeferTimeHOLD() * 60000L;
        long thresholdTime = System.currentTimeMillis() - expireTime;
        return time < thresholdTime;
    }
    
    public static boolean isExpiredRED(long time) {
        long expireTime = Core.getDeferTimeRED() * 60000L;
        long thresholdTime = System.currentTimeMillis() - expireTime;
        return time < thresholdTime;
    }
    
    private static final HoldThread HOLD = new HoldThread();
    
    public static void startThread() {
        HOLD.start();
    }
    
    public static void startIndex() {
        long time = System.currentTimeMillis();
        User.getHistoryByTime(time, false);
        User.getHistoryByTime(time = time - Server.DAY_TIME, false);
        User.getHistoryByTime(time = time - Server.DAY_TIME, false);
        User.getHistoryByTime(time = time - Server.DAY_TIME, false);
        User.getHistoryByTime(time = time - Server.DAY_TIME, false);
        User.getHistoryByTime(time - Server.DAY_TIME, false);
    }
    
    public static void terminateThread() {
        HOLD.terminate();
    }
    
    private static long NOTIFY_TIME = 10 * MINUTE_TIME;

    public static void setNotifyTime(long time) {
        NOTIFY_TIME = time;
    }
        
    private static class HoldThread extends Thread {
        
        private HoldThread() {
            super("HOLDTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private boolean keepRunning = true;
        
        private synchronized boolean keepRunning() {
            return keepRunning;
        }
        
        public synchronized void terminate() {
            keepRunning = false;
            notify();
            interrupt();
        }
        
        public synchronized void waitNotify() throws InterruptedException {
            wait(NOTIFY_TIME);
        }
        
        private final TreeMap<String,TreeMap<Long,Query>> adminKeyMap = new TreeMap<>();
        
        private synchronized void clearAdminKeyMap() {
            adminKeyMap.clear();
        }
        
        private synchronized TreeSet<String> getAdminKeySet() {
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(adminKeyMap.keySet());
            return keySet;
        }
        
        private synchronized TreeMap<Long,Query> getAdminTreeMap(String key) {
            return adminKeyMap.get(key);
        }
        
        private synchronized void putAdminTreeMap(
                String key, long time, Query query
        ) {
            TreeMap<Long,Query> queryMap = adminKeyMap.get(key);
            if (queryMap == null) {
                queryMap = new TreeMap<>();
                adminKeyMap.put(key, queryMap);
            }
            queryMap.put(time, query);
        }
        
        private final TreeMap<String,TreeMap<Long,Query>> recipientKeyMap = new TreeMap<>();
        
        private synchronized void clearRecipientKeyMap() {
            recipientKeyMap.clear();
        }
        
        private synchronized TreeSet<String> getRecipientKeySet() {
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(recipientKeyMap.keySet());
            return keySet;
        }
        
        private synchronized TreeMap<Long,Query> getRecipientTreeMap(String key) {
            return recipientKeyMap.get(key);
        }
        
        private synchronized void putRecipientTreeMap(
                String key, long time, Query query
        ) {
            TreeMap<Long,Query> queryMap = recipientKeyMap.get(key);
            if (queryMap == null) {
                queryMap = new TreeMap<>();
                recipientKeyMap.put(key, queryMap);
            }
            queryMap.put(time, query);
        }
        
        @Override
        public void run() {
            Server.logInfo("started hold thread.");
            while (Core.isRunning() && keepRunning()) {
                try {
                    waitNotify();
                    if (keepRunning()) {
                        Server.logInfo("started hold process.");
                        long timeUser = System.currentTimeMillis() - 2 * Server.HOUR_TIME;
                        long timeAdmin = System.currentTimeMillis() - 22 * Server.HOUR_TIME;
                        long timeBegin = System.currentTimeMillis() - Server.MINUTE_TIME;
                        clearAdminKeyMap();
                        clearRecipientKeyMap();
                        int threadCount = 2 * Runtime.getRuntime().availableProcessors();
                        final LinkedList<User> userQueue = new LinkedList<>();
                        for (User user : getUserList()) {
                            if (user.usingHeader()) {
                                userQueue.add(user);
                            }
                        }
                        if (threadCount > 32) {
                            threadCount = 32;
                        } else if (threadCount > userQueue.size()) {
                            threadCount = userQueue.size();
                        }
                        if (threadCount > 0) {
                            final Semaphore semaphore = new Semaphore(threadCount);
                            while (semaphore.tryAcquire()) {
                                final int threadID = threadCount - semaphore.availablePermits();
                                Thread thread = new Thread("HOLDTH" + Core.formatCentena(threadID)) {
                                    @Override
                                    public void run() {
                                        try {
                                            User user;
                                            while (Core.isRunning() && (user = userQueue.poll()) != null) {
                                                TreeMap<String,TreeMap<Long,Query>> userKeyMap = new TreeMap<>();
                                                for (long time : user.getTimeHead(timeBegin)) {
                                                    Query query;
                                                    if (!Core.isRunning()) {
                                                        break;
                                                    } else if (!keepRunning()) {
                                                        break;
                                                    } else if ((query = user.getQuery(time)) == null) {
                                                        continue;
                                                    } else if (query.isSenderHijacked()) {
                                                        query.adviseFromHIJACK(time);
                                                        Abuse.offer(time, query);
                                                    } else if (query.isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                                                        Abuse.offer(time, query);
                                                    } else if (query.isResult("BLOCK")) {
                                                        Block.offer(time, query);
                                                        Abuse.offer(time, query);
                                                    } else if (query.isResult("FLAG")) {
                                                        if (!query.hasHeaderInformation()) {
                                                            query.setResult("GREYLIST");
                                                            storeDB(time, query);
                                                        }
                                                    } else if (query.isResult("HOLD")) {
                                                        if (query.hasMalwareNotIgnored()) {
                                                            query.banOrBlockForAdmin(time, "MALWARE");
                                                            query.banOrBlock(time, "MALWARE");
                                                        } else if (query.hasExecutableBlocked()) {
                                                            query.banOrBlockForAdmin(time, "EXECUTABLE");
                                                            query.banOrBlock(time, "EXECUTABLE");
                                                        } else if (query.hasPhishingBlocked()) {
                                                            query.banOrBlock(time, "PHISHING");
                                                        }
                                                        if (isExpiredHOLD(time)) {
                                                            processExpired(time, query);
                                                            storeDB(time, query);
                                                            user.dropQuery(time);
                                                        } else if (query.hasHeaderInformation()) {
                                                            if (query.hasDefinedKey()) {
                                                                query.adviseMailerDaemonHOLDING(time);
                                                            } else {
                                                                if (query.isNotAdvisedUser()) {
                                                                    String key = query.getWhiteKey() + " " + query.getBlockKey();
                                                                    TreeMap<Long,Query> queryMap = userKeyMap.get(key);
                                                                    if (queryMap == null) {
                                                                        queryMap = new TreeMap<>();
                                                                        userKeyMap.put(key, queryMap);
                                                                    }
                                                                    queryMap.put(time, query);
                                                                }
                                                                String key = query.getBlockKey();
                                                                putRecipientTreeMap(key, time, query);
                                                                if (!query.isAdminAdvised()) {
                                                                    putAdminTreeMap(key, time, query);
                                                                }
                                                            }
                                                            storeDB(time, query);
                                                        } else {
                                                            query.setResult("GREYLIST");
                                                            storeDB(time, query);
                                                        }
                                                    } else if (isExpiredRED(time)) {
                                                        boolean changed1 = query.setResult("LISTED", "REJECT");
                                                        boolean changed2 = query.setResult("GREYLIST", "REJECT");
                                                        if (changed1 || changed2) {
                                                            storeDB(time, query);
                                                            query.addUnacceptable();
                                                        }
                                                        if (hasHistory() || Core.hasMySQL()) {
                                                            user.dropQuery(time);
                                                        }
                                                    } else if (query.isResult("ACCEPT") && query.isBlockKey() && !query.isWhiteKey()) {
                                                        Abuse.offer(time, query);
                                                    } else if (query.isResult("INEXISTENT") && query.isBlockKey() && !query.isWhiteKey()) {
                                                        Abuse.offer(time, query);
                                                    } else if (query.isResult("REJECT") && query.isBlockKey()) {
                                                        Abuse.offer(time, query);
                                                    } else if (query.isResult("REJECT") && query.hasMalwareNotIgnored()) {
                                                        Abuse.offer(time, query);
                                                    }
                                                }
                                                if (keepRunning()) {
                                                    int maxSize = 0;
                                                    long timeKey = Long.MAX_VALUE;
                                                    TreeMap<Long,Query> resultMap = null;
                                                    for (String key : userKeyMap.keySet()) {
                                                        TreeMap<Long,Query> queryMap = userKeyMap.get(key);
                                                        long firstTime = queryMap.firstKey();
                                                        if (firstTime < timeUser) {
                                                            int size = queryMap.size();
                                                            if (queryMap.size() > 32) {
                                                                user.adviseUserHOLD(queryMap);
                                                            } else if ((System.currentTimeMillis() - firstTime) > Server.DAY_TIME) {
                                                                user.adviseUserHOLD(queryMap);
                                                            } else if (maxSize < size) {
                                                                maxSize = size;
                                                                timeKey = firstTime;
                                                                resultMap = queryMap;
                                                            } else if (maxSize == size && timeKey > firstTime) {
                                                                timeKey = firstTime;
                                                                resultMap = queryMap;
                                                            }
                                                        }
                                                    }
                                                    user.adviseUserHOLD(resultMap);
                                                }
                                            }
                                        } finally {
                                            semaphore.release();
                                        }
                                    }
                                };
                                thread.start();
                            }
                            semaphore.acquire(threadCount);
                        }
                        if (keepRunning()) {
                            int maxSize = 0;
                            long timeKey = Long.MAX_VALUE;
                            TreeMap<Long,Query> resultMap = null;
                            for (String key : getAdminKeySet()) {
                                if (!Core.isRunning()) {
                                    break;
                                } else {
                                    TreeMap<Long,Query> queryMap = getAdminTreeMap(key);
                                    if (queryMap != null) {
                                        long firstTime = queryMap.firstKey();
                                        long lastTime = queryMap.lastKey();
                                        if (queryMap.size() > 32) {
                                            User.adviseAdminHOLD(queryMap);
                                        } else if ((System.currentTimeMillis() - firstTime) > 3 * Server.DAY_TIME) {
                                            User.adviseAdminHOLD(queryMap);
                                        } else if (lastTime < timeAdmin) {
                                            int size = queryMap.size();
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
                                }
                            }
                            if (resultMap != null && maxSize > 0) {
                                User.adviseAdminHOLD(resultMap);
                            }
                        }
                        if (keepRunning()) {
                            for (String key : getRecipientKeySet()) {
                                if (!Core.isRunning()) {
                                    break;
                                } else {
                                    TreeMap<Long,Query> queryMap = getRecipientTreeMap(key);
                                    if (queryMap != null) {
                                        int max = (int) ((System.currentTimeMillis() - queryMap.firstKey()) / Server.HOUR_TIME);
                                        int count = 0;
                                        for (long time : queryMap.keySet()) {
                                            User.Query query = queryMap.get(time);
                                            if (query.adviseRecipientHOLD(time)) {
                                                count++;
                                            } else if (query.adviseSenderHOLD(time)) {
                                                count++;
                                            }
                                            if (count > max) {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Server.logInfo("finished hold process.");
                    }
                } catch (InterruptedException ex) {
                    Server.logWarning("interrupted hold thread.");
                    break;
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            Server.logInfo("terminated hold thread.");
        }
    }
    
    public boolean sendTOTP() {
        otp_fail = 0;
        return ServerHTTP.enviarOTP(locale, this);
    }
    
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
            if (Core.isRunning()) {
                long time2 = System.currentTimeMillis();
                Connection connection = Core.aquireConnectionMySQL();
                if (connection != null) {
                    try {
                        try {
                            try (PreparedStatement statement = connection.prepareStatement(
                                    MYSQL_STORE_COMMAND_2_9_0
                            )) {
                                statement.setQueryTimeout(60);
                                for (User user : getUserList()) {
                                    for (long time : user.getTimeKeySet()) {
                                        Query query = user.getQuery(time);
                                        if (!Core.isRunning()) {
                                            return false;
                                        } else if (query != null) {
                                            if (query.storeDB_2_9_0(statement, time)) {
                                                query.storeHistory(time);
                                                connection.commit();
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                }
                                Server.logMySQL(time2, "user_query stored");
                            }
                        } catch (SQLException ex1) {
                            try (PreparedStatement statement = connection.prepareStatement(
                                    MYSQL_STORE_COMMAND_2_8_0
                            )) {
                                statement.setQueryTimeout(60);
                                for (User user : getUserList()) {
                                    for (long time : user.getTimeKeySet()) {
                                        Query query = user.getQuery(time);
                                        if (!Core.isRunning()) {
                                            return false;
                                        } else if (query != null) {
                                            if (query.storeDB_2_8_0(statement, time)) {
                                                query.storeHistory(time);
                                                connection.commit();
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                }
                                Server.logMySQL(time2, "user_query stored");
                            }
                        }
                    } finally {
                        Core.releaseConnectionMySQL();
                    }
                }
                return true;
            } else {
                return false;
            }
        } catch (SQLException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static StoreThread STORE_THREAD = null;
    
    private static synchronized StoreThread getStoreThread() {
        if (STORE_THREAD == null) {
            STORE_THREAD = new StoreThread();
            STORE_THREAD.start();
        }
        return STORE_THREAD;
    }
    
    public static void storeDB(long time, Query query) {
        if (query != null && !query.STORED) {
            StoreThread storeThread = Core.hasMySQL() ? getStoreThread() : null;
            if (storeThread == null) {
                query.storeHistory(time);
            } else {
                storeThread.put(time, query);
            }
        }
    }
    
    public static void storeDB2(long time, Query query) {
        if (query != null) {
            User user = query.getUser();
            user.putQuery(time, query);
            StoreThread storeThread = Core.hasMySQL() ? getStoreThread() : null;
            if (storeThread == null) {
                query.storeHistory(time);
            } else {
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
                            Query query = entry.getValue();
                            long time = entry.getKey();
                            query.waitHeader();
                            query.storeHistory(time);
                            Connection connection = Core.aquireConnectionMySQL();
                            if (connection == null) {
                                put(time, query);
                            } else {
                                try {
                                    try {
                                        try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_9_0)) {
                                            statement.setQueryTimeout(60);
                                            if (query.storeDB_2_9_0(statement, time)) {
                                                connection.commit();
                                            }
                                        }
                                    } catch (SQLException ex1) {
                                        Server.logError(ex1);
                                        try (PreparedStatement statement = connection.prepareStatement(MYSQL_STORE_COMMAND_2_8_0)) {
                                            statement.setQueryTimeout(60);
                                            if (query.storeDB_2_8_0(statement, time)) {
                                                connection.commit();
                                            }
                                        }
                                    }
                                } finally {
                                    Core.releaseConnectionMySQL();
                                }
                            }
                        }
                        Server.logTrace("queue finished.");
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
    
    private Query cloneQuery(Query other) {
        if (other == null) {
            return null;
        } else {
            return new Query(other);
        }
    }
        
    public class Query extends Filterable implements Serializable {
        
        private static final long serialVersionUID = 1L;
        
        private String client;
        private String ip;
        private String helo;
        private String hostname = null;
        private String sender;
        private SPF.Qualifier qualifier;
        private String recipient;
        private String subaddress = null;
        private boolean inexistent = false;
        private final TreeSet<String> tokenSet = new TreeSet<>();
        private TreeSet<String> signerSet = null;
        private String result;
        private String from = null;
        private String replyto = null;
        private String subject = null;
        private String messageID = null;
        private String queueID = null;
        private Timestamp date = null;
        private URL unsubscribe = null;
        private TreeMap<String,Boolean> linkMap = null;
        private TreeSet<String> executableSet = null;
        private String malware = null;
        private byte[] body = null;
        private String charset = null;
        
        private boolean adminAdvised = false;
        private boolean senderAdvised = false;
        private boolean recipientAdvised = false;
        private boolean userAdvised = false;
        private boolean abuseAdvised = false;
        private String abuseEmail = null;
        
        private String filter = null;
        
        private transient String inreplyto = null;
        private transient boolean forgedFrom = false;
        private transient boolean spoofedRecipient = false;
        private transient Date arrival = null;

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
            this.subaddress = other.subaddress;
            this.loadTokenSet(Core.getSequence(other.tokenSet, ";"));
            this.loadSignerSet(Core.getSequence(other.signerSet, ";"));
            this.result = other.result;
            this.from = other.from;
            this.replyto = other.replyto;
            this.subject = other.subject;
            this.messageID = other.messageID;
            this.queueID = other.queueID;
            this.date = other.date;
            this.unsubscribe = other.cloneUnsubscribe();
            this.loadLinkMap(Core.getSequence(other.linkMap, ";", 65535));
            this.loadExecutableSet(Core.getSequence(other.executableSet, ";"));
            this.malware = other.malware;
            this.body = other.cloneBody();
            this.charset = other.charset;
            this.adminAdvised = other.adminAdvised;
            this.senderAdvised = other.senderAdvised;
            this.recipientAdvised = other.recipientAdvised;
            this.userAdvised = other.userAdvised;
            this.abuseAdvised = other.abuseAdvised;
            this.abuseEmail = other.abuseEmail;
            this.filter = other.filter;
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
            this.adminAdvised = rs.getBoolean("adminAdvised");
            this.senderAdvised = rs.getBoolean("senderAdvised");
            this.recipientAdvised = rs.getBoolean("recipientAdvised");
            this.userAdvised = rs.getBoolean("userAdvised");
            this.abuseAdvised = rs.getBoolean("abuseAdvised");
            this.STORED = true;
            this.CHANGED = new BinarySemaphore(false);
        }
        
        public boolean equals(Query other) {
            if (other == null) {
                return false;
            } else if (!Objects.deepEquals(this.client, other.client)) {
                return false;
            } else if (!Objects.deepEquals(this.ip, other.ip)) {
                return false;
            } else if (!Objects.deepEquals(this.helo, other.helo)) {
                return false;
            } else if (!Objects.deepEquals(this.hostname, other.hostname)) {
                return false;
            } else if (!Objects.deepEquals(this.sender, other.sender)) {
                return false;
            } else if (!Objects.deepEquals(this.qualifier, other.qualifier)) {
                return false;
            } else if (!Objects.deepEquals(this.recipient, other.recipient)) {
                return false;
            } else if (!Objects.deepEquals(this.subaddress, other.subaddress)) {
                return false;
            } else if (!Objects.deepEquals(this.inexistent, other.inexistent)) {
                return false;
            } else if (!Objects.deepEquals(this.tokenSet, other.tokenSet)) {
                return false;
            } else if (!Objects.deepEquals(this.signerSet, other.signerSet)) {
                return false;
            } else if (!Objects.deepEquals(this.result, other.result)) {
                return false;
            } else if (!Objects.deepEquals(this.from, other.from)) {
                return false;
            } else if (!Objects.deepEquals(this.replyto, other.replyto)) {
                return false;
            } else if (!Objects.deepEquals(this.subject, other.subject)) {
                return false;
            } else if (!Objects.deepEquals(this.messageID, other.messageID)) {
                return false;
            } else if (!Objects.deepEquals(this.queueID, other.queueID)) {
                return false;
            } else if (!Objects.deepEquals(this.date, other.date)) {
                return false;
            } else if (!Objects.deepEquals(this.unsubscribe, other.unsubscribe)) {
                return false;
            } else if (!Objects.deepEquals(this.linkMap, other.linkMap)) {
                return false;
            } else if (!Objects.deepEquals(this.executableSet, other.executableSet)) {
                return false;
            } else if (!Objects.deepEquals(this.malware, other.malware)) {
                return false;
            } else if (!Objects.deepEquals(this.adminAdvised, other.adminAdvised)) {
                return false;
            } else if (!Objects.deepEquals(this.senderAdvised, other.senderAdvised)) {
                return false;
            } else if (!Objects.deepEquals(this.recipientAdvised, other.recipientAdvised)) {
                return false;
            } else if (!Objects.deepEquals(this.userAdvised, other.userAdvised)) {
                return false;
            } else if (!Objects.deepEquals(this.abuseAdvised, other.abuseAdvised)) {
                return false;
            } else if (!Objects.deepEquals(this.abuseEmail, other.abuseEmail)) {
                return false;
            } else if (!Objects.deepEquals(this.filter, other.filter)) {
                return false;
            } else {
                return true;
            }
        }
        
        public Query(byte version, DataInput input) throws Exception {
            int length = input.readInt();
            byte[] data = new byte[length];
            input.readFully(data);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            try (GZIPInputStream gzis = new GZIPInputStream(bais)) {
                try (DataInputStream dis =  new DataInputStream(gzis)) {
                    this.client = Core.readUTF(dis);
                    this.ip = Core.readUTF(dis);
                    this.helo = Core.readUTF(dis);
                    this.hostname = Core.readUTF(dis);
                    this.sender = Core.readUTF(dis);
                    this.qualifier = Core.readQualifier(dis);
                    this.recipient = Core.readUTF(dis);
                    this.subaddress = Core.readUTF(dis);
                    this.tokenSet.addAll(Core.readSmallSetUTF(dis));
                    this.result = Core.readUTF(dis);
                    this.malware = Core.readUTF(dis);
                    this.abuseEmail = Core.readUTF(dis);
                    this.filter = Core.readUTF(dis);
                    boolean[] b = Core.readBooleanArray(dis);
                    this.inexistent = b[0];
                    this.adminAdvised = b[1];
                    this.senderAdvised = b[2];
                    this.recipientAdvised = b[3];
                    this.userAdvised = b[4];
                    this.abuseAdvised = b[5];
                    boolean hasHeader = b[6];
                    boolean hasBody = b[7];
                    if (hasHeader) {
                        this.from = Core.readUTF(dis);
                        this.replyto = Core.readUTF(dis);
                        this.subject = Core.readUTF(dis);
                        this.messageID = Core.readUTF(dis);
                        this.queueID = Core.readUTF(dis);
                        this.date = Core.readTimestamp(dis);
                        this.unsubscribe = Core.readURL(dis);
                    }
                    if (hasBody) {
                        this.signerSet = Core.readSmallSetUTF(dis);
                        this.linkMap = Core.readMapBooleanUTF(dis);
                        this.executableSet = Core.readSmallSetUTF(dis);
                    }
                    this.STORED = true;
                    this.CHANGED = new BinarySemaphore(false);
                }
            }
        }
                
        private byte[] toByteArray() throws Exception {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
                try (DataOutputStream dos =  new DataOutputStream(gzos)) {
                    Core.writeUTF(dos, client);
                    Core.writeUTF(dos, ip);
                    Core.writeUTF(dos, helo);
                    Core.writeUTF(dos, hostname);
                    Core.writeUTF(dos, sender);
                    Core.writeQualifier(dos, qualifier);
                    Core.writeUTF(dos, recipient);
                    Core.writeUTF(dos, subaddress);
                    Core.writeSmallUTF(dos, tokenSet);
                    Core.writeUTF(dos, result);
                    Core.writeUTF(dos, malware);
                    Core.writeUTF(dos, abuseEmail);
                    Core.writeUTF(dos, filter);
                    boolean hasHeader = hasHeaderInformation();
                    boolean hasBody = hasBodyInformation();
                    Core.writeBooleanArray(
                            dos, inexistent, adminAdvised, senderAdvised,
                            recipientAdvised, userAdvised, abuseAdvised,
                            hasHeader, hasBody
                    );
                    if (hasHeader) {
                        Core.writeUTF(dos, from);
                        Core.writeUTF(dos, replyto);
                        Core.writeUTF(dos, subject);
                        Core.writeUTF(dos, messageID);
                        Core.writeUTF(dos, queueID);
                        Core.writeTimestamp(dos, date);
                        Core.writeURL(dos, unsubscribe);
                    }
                    if (hasBody) {
                        Core.writeSmallUTF(dos, signerSet);
                        Core.writeUTF(dos, linkMap);
                        Core.writeSmallUTF(dos, executableSet);
                    }
                }
            }
            return baos.toByteArray();
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
            } else if (linkMap == null) {
                linkMap = map;
                return true;
            } else {
                linkMap.putAll(map);
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
                    statement.setString(14, result.equals("QUEUE") ? "HOLD" : result);
                    statement.setString(15, from);
                    statement.setString(16, replyto);
                    statement.setString(17, subject);
                    statement.setString(18, messageID);
                    statement.setTimestamp(19, date);
                    statement.setString(20, getUnsubscribeString());
                    statement.setString(21, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(22, malware);
                    statement.setNull(23, Types.BLOB);
                    statement.setBoolean(24, adminAdvised);
                    statement.setBoolean(25, senderAdvised);
                    statement.setBoolean(26, recipientAdvised);
                    statement.setString(27, whiteKey);
                    statement.setString(28, blockKey);
                    statement.setString(29, result.equals("QUEUE") ? "HOLD" : result);
                    statement.setString(30, from);
                    statement.setString(31, replyto);
                    statement.setString(32, subject);
                    statement.setString(33, messageID);
                    statement.setTimestamp(34, date);
                    statement.setString(35, getUnsubscribeString());
                    statement.setString(36, Core.getSequence(linkMap, ";", 65535));
                    statement.setString(37, malware);
                    statement.setNull(38, Types.BLOB);
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
        
        private boolean storeDB_2_9_0(PreparedStatement statement, long time) {
            if (this.CHANGED.acquireIf(true)) {
                long start = System.currentTimeMillis();
                try {
                    String whiteKey = getWhiteKey();
                    String blockKey = getBlockKey();
                    statement.setLong(1, time);
                    statement.setString(2, getEmail());
                    statement.setString(3, client);
                    statement.setString(4, ip == null ? "" : ip);
                    statement.setString(5, helo);
                    statement.setString(6, hostname);
                    statement.setString(7, sender);
                    statement.setString(8, SPF.Qualifier.name(qualifier));
                    statement.setString(9, recipient);
                    statement.setString(10, Core.getSequence(tokenSet, ";"));
                    statement.setString(11, Core.getSequence(signerSet, ";"));
                    statement.setString(12, whiteKey);
                    statement.setString(13, blockKey);
                    statement.setString(14, result.equals("QUEUE") ? "HOLD" : result);
                    statement.setString(15, from);
                    statement.setString(16, replyto);
                    statement.setString(17, subject);
                    if (messageID == null) {
                        statement.setString(18, null);
                    } else if (messageID.length() > 512) {
                        statement.setString(18, null);
                    } else {
                        statement.setString(18, messageID);
                    }
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
                    statement.setString(32, result.equals("QUEUE") ? "HOLD" : result);
                    statement.setString(33, from);
                    statement.setString(34, replyto);
                    statement.setString(35, subject);
                    if (messageID == null) {
                        statement.setString(36, null);
                    } else if (messageID.length() > 512) {
                        statement.setString(36, null);
                    } else {
                        statement.setString(36, messageID);
                    }
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
                return true;
            }
        }
        
        private Query(
                String clientFQDN,
                Client client,
                String ip,
                String helo,
                String hostname,
                String sender,
                SPF.Qualifier qualifier,
                String recipient,
                String subaddress,
                TreeSet<String> tokenSet,
                String result,
                String filter
        ) throws ProcessException {
            if (client == null) {
                throw new ProcessException("INVALID CLIENT");
            } else if (!isValidIP(ip)) {
                throw new ProcessException("INVALID IP");
            } else if (sender != null && !sender.isEmpty() && !sender.contains("@")) {
                throw new ProcessException("INVALID SENDER");
            } else if (recipient != null && !isValidRecipient(recipient)) {
                throw new ProcessException("INVALID RECIPIENT");
            } else if (tokenSet == null) {
                throw new ProcessException("INVALID TOKEN SET");
            } else if (result == null) {
                throw new ProcessException("INVALID RESULT");
            } else {
               this.client = clientFQDN == null ? client.getDomain() : clientFQDN;
               this.ip = Subnet.normalizeIP(ip);
               this.helo = helo == null ? null : helo.toLowerCase();
               this.hostname = Domain.normalizeHostname(hostname, false);
               this.hostname = this.hostname == null ? "" : this.hostname;
               this.sender = (sender == null || sender.isEmpty() ? null : sender);
               this.qualifier = qualifier;
               this.recipient = recipient;
               this.subaddress = subaddress;
               this.tokenSet.addAll(tokenSet);
               this.result = result;
               this.filter = filter;
               this.STORED = false;
               this.CHANGED = new BinarySemaphore(true);
               User.CHANGED = true;
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
                String subaddress,
                TreeSet<String> tokenSet,
                String result,
                String filter
        ) throws ProcessException {
            if (!Regex.isHostname(client)) {
                throw new ProcessException("INVALID CLIENT");
            } else if (!isValidIP(ip)) {
                throw new ProcessException("INVALID IP");
            } else if (sender != null && !sender.isEmpty() && !sender.contains("@")) {
                throw new ProcessException("INVALID SENDER");
            } else if (recipient != null && !isValidRecipient(recipient)) {
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
               this.sender = (sender == null || sender.isEmpty() ? null : sender);
               this.qualifier = qualifier;
               this.recipient = recipient;
               this.subaddress = subaddress;
               this.tokenSet.addAll(tokenSet);
               this.result = result;
               this.filter = filter;
               this.STORED = false;
               this.CHANGED = new BinarySemaphore(true);
               User.CHANGED = true;
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
                String subaddress,
                TreeSet<String> tokenSet,
                String result,
                String from,
                String replyTo,
                Date date,
                URL unsubscribe,
                TreeSet<String> signerSet,
                String subject,
                String messageID,
                String queueID,
                Date arrival
        ) {
           this.client = Domain.normalizeHostname(client, false);
           this.ip = Subnet.normalizeIP(ip);
           this.helo = helo == null ? null : helo.toLowerCase();
           this.hostname = Domain.normalizeHostname(hostname, false);
           this.hostname = this.hostname == null ? "" : this.hostname;
           this.sender = (sender == null || sender.isEmpty() ? null : sender);
           this.qualifier = qualifier;
           this.recipient = recipient;
           this.subaddress = subaddress;
           this.tokenSet.addAll(tokenSet);
           this.result = result;
           this.from = from;
           this.replyto = replyTo;
           this.date = (date == null ? null : new Timestamp(date.getTime()));
           this.unsubscribe = unsubscribe;
           if (signerSet != null && !signerSet.isEmpty()) {
               this.signerSet = new TreeSet<>();
               this.signerSet.addAll(signerSet);
           }
           this.subject = subject;
           this.messageID = messageID;
           this.queueID = queueID;
           this.arrival = arrival;
           User.this.usingHeader = true;
           this.STORED = false;
           this.CHANGED = new BinarySemaphore(true);
           User.CHANGED = true;
        }
        
        public boolean storeHistory(long timeKey) {
            if (hasHistory()) {
                try {
                    Long position = null;
                    History history = getHistoryByTime(timeKey, true);
                    if (history != null) {
                        position = history.store(timeKey, this);
                    }
                    if (position == null) {
                        return false;
                    } else {
                        return true;
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            } else {
                return false;
            }
        }
        
        @Override
        public String getClient() {
            return client;
        }
        
        public Client getClientObj() {
            TreeSet<Client> clientSet = Client.getClientSet(client);
            if (clientSet == null) {
                return null;
            } else if (clientSet.size() == 1) {
                return clientSet.first();
            } else {
                return null;
            }
        }
        
        @Override
        public Locale getLocale() {
            return locale;
        }
        
        public Locale getBodyLocale() {
            if (body == null) {
                return locale;
            } else if (client.equals(Core.getHostname())) {
                return locale;
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
                    String html = baOS.toString(getSupportedCharsetToString());
                    Document document = Jsoup.parse(html);
                    Elements elements = document.getElementsByAttribute("lang");
                    Element element = elements == null ? null : elements.first();
                    String lang = element == null ? null : element.attr("lang");
                    if (lang == null || lang.isEmpty()) {
                        return locale;
                    } else if (lang.equals("pt-br")) {
                        return LocaleUtils.toLocale("pt_BR");
                    } else {
                        return LocaleUtils.toLocale(lang);
                    }
                } catch (ZipException ex) {
                    body = null;
                    charset = null;
                    return locale;
                } catch (EOFException ex) {
                    body = null;
                    charset = null;
                    return locale;
                } catch (IllegalArgumentException ex) {
                    return locale;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return locale;
                }
            }
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

        @Override
        public String getIP() {
            return ip;
        }
        
        public boolean hasActiveAbuseEmail() {
            String email = getAbuseSender();
            if (email == null) {
                return false;
            } else if (Trap.containsAnythingExact(email)) {
                return false;
            } else {
                return NoReply.isSubscribed(email);
            }
        }
        
        public boolean hasDynamicIP() {
            return Generic.isDynamicIP(ip);
        }
        
        public String getCIDR() {
            if (ip.contains(":")) {
                return SubnetIPv6.normalizeCIDRv6(ip + "/64");
            } else {
                return ip + "/32";
            }
        }

        @Override
        public String getHELO() {
            if (helo == null) {
                return "";
            } else {
                return helo;
            }
        }
        
        public String getOrigin(boolean pontuacao) {
            String host = getFQDN();
            if (host == null) {
                return ip;
            } else {
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getUnblockURLSafe() {
            try {
                return getUnblockURL();
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        public String getUnblockURL() throws ProcessException {
            return Core.getUnblockURL(
                    getEmail(),
                    getIP(),
                    getSender(),
                    getFQDN(),
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
            String senderLocal = getSender();
            if (senderLocal == null) {
                return null;
            } else {
                int index = senderLocal.indexOf('@');
                String host = senderLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getHeaderFromHostname(boolean pontuacao) {
            String fromLocal = getFrom();
            if (fromLocal == null) {
                return null;
            } else {
                int index = fromLocal.indexOf('@');
                String host = fromLocal.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        private String getHeaderFromHostnameSafe(boolean pontuacao) {
            String hostnameLocal = getHeaderFromHostname(pontuacao);
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
            String trueSender = getTrueSender();
            if (trueSender == null) {
                return null;
            } else if (trueSender.isEmpty()) {
                return null;
            } else {
                int index = trueSender.indexOf('@');
                String host = trueSender.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        @Override
        public boolean isInvitation() {
            return User.this.isInvitation(recipient, subaddress);
        }
        
        @Override
        public String getSender() {
            return sender;
        }
        
        public boolean isFromFreemail() {
            if (from == null) {
                return false;
            } else {
                return Provider.isFreeMail(from) && isSigned(from);
            }
        }
        
        public boolean isSpoofingFrom() {
            return getSpoofingFrom() != null;
        }
        
        public boolean isFromBlocked() {
            return getFromBlocked() != null;
        }
        
        public boolean isNotComplianceFQDN() {
            if (hostname == null) {
                return false;
            } else {
                return NoReply.containsFQDN(hostname);
            }
        }
        
        public boolean isEmptyPTR() {
            if (hostname == null) {
                return Reverse.getPointerSetSafe(ip).isEmpty();
            } else {
                return false;
            }
        }
        
        public String getReplyToValid() {
            if (isSenderMailerDeamon()) {
                return null;
            } else if (isSigned(replyto) && isValidEmail(replyto) && !NoReply.contains(replyto, true)) {
                return replyto;
            } else if (isSigned(from, true) && isValidEmail(from) && !NoReply.contains(from, true)) {
                return from;
            } else if (isSigned(sender) && isValidEmail(sender) && !NoReply.contains(sender, true)) {
                return sender;
            } else {
                return null;
            }
        }
        
        public void addHarmful(long timeKey) {
            SPF.setSpam(timeKey, tokenSet);
            Abuse.addHarmful(getAbuseOrigin());
            CIDR.addHarmful(ip);
            String fqdn = getFQDN();
            Generic.addHarmful(helo);
            FQDN.addHarmful(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addHarmful(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addHarmful(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addHarmful(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addHarmful(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addHarmful(email, recipient);
            }
        }

        public void addUndesirable(long timeKey) {
            SPF.setSpam(timeKey, tokenSet);
            Abuse.addUndesirable(getAbuseOrigin());
            CIDR.addUndesirable(ip);
            String fqdn = getFQDN();
            Generic.addUndesirable(helo);
            FQDN.addUndesirable(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addUndesirable(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addUndesirable(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addUndesirable(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addUndesirable(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addUndesirable(email, recipient);
            }
        }

        public void addUnacceptable() {
            Abuse.addUnacceptable(getAbuseOrigin());
            CIDR.addUnacceptable(ip);
            String fqdn = getFQDN();
            Generic.addUnacceptable(helo);
            FQDN.addUnacceptable(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addUnacceptable(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addUnacceptable(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addUnacceptable(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addUnacceptable(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addUnacceptable(email, recipient);
            }
        }

        public void addAcceptable() {
            Abuse.addAcceptable(getAbuseOrigin());
            CIDR.addAcceptable(ip);
            String fqdn = getFQDN();
            Generic.addAcceptable(helo);
            FQDN.addAcceptable(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addAcceptable(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addAcceptable(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addAcceptable(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addAcceptable(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addAcceptable(email, recipient);
            }
        }

        public void addDesirable(long timeKey) {
            SPF.setHam(timeKey, tokenSet);
            Abuse.addDesirable(getAbuseOrigin());
            CIDR.addDesirable(ip);
            String fqdn = getFQDN();
            Generic.addDesirable(helo);
            FQDN.addDesirable(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addDesirable(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addDesirable(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addDesirable(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addDesirable(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addDesirable(email, recipient);
            }
        }

        public void addBeneficial(long timeKey) {
            SPF.setHam(timeKey, tokenSet);
            Abuse.addBeneficial(getAbuseOrigin());
            CIDR.addBeneficial(ip);
            String fqdn = getFQDN();
            Generic.addBeneficial(helo);
            FQDN.addBeneficial(fqdn);
            if (!isSenderMailerDeamon()) {
                net.spfbl.data.SPF.addBeneficial(sender, qualifier);
                if (signerSet != null) {
                    for (String signer : signerSet) {
                        DKIM.addBeneficial(signer);
                    }
                }
                if (!isBounceMessage()) {
                    Dictionary.addBeneficial(subject, locale, recipient);
                    for (String link : getLinkKeySet()) {
                        URI.addBeneficial(link);
                    }
                }
            }
            if (!isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING)) {
                Recipient.addBeneficial(email, recipient);
            }
        }
        
        @Override
        public Qualifier getQualifier() {
            return qualifier;
        }

        @Override
        public String getFQDN() {
            if (hostname != null) {
                return hostname.length() == 0 ? null : hostname;
            } else if (FQDN.addFQDN(ip, helo, true)) {
                return hostname = helo;
            } else {
                return hostname = "";
            } 
        }
        
        public String getValidHostDomainSafe() {
            return getValidHostDomainSafe(false);
        }
        
        public String getValidHostDomainSafe(boolean pontuation) {
            try {
                String host = getFQDN();
                return Domain.extractDomain(host, pontuation);
            } catch (ProcessException ex) {
                return null;
            }
        }
        
        public User getUser() {
            return User.this;
        }
        
        public Properties[] getSessionProperties() {
            return User.this.getSessionProperties();
        }
        
        @Override
        public String getUserEmail() {
            return User.this.getEmail();
        }
        
        public TreeSet<String> getRecipientSet() {
            if (recipient == null) {
                return null;
            } else {
                TreeSet<String> recipientSet = new TreeSet<>();
                recipientSet.add(recipient);
                return recipientSet;
            }
        }

        public String getRecipient() {
            return recipient;
        }
        
        public String getRecipientNotNull() {
            if (recipient == null) {
                return "";
            } else {
                return recipient;
            }
        }

        public String getResult() {
            return result;
        }
        
        public boolean isResult(String result) {
            return this.result.equals(result);
        }
        
        public boolean wasAccepted() {
            return result.equals("WHITE") || result.equals("ACCEPT");
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
        
        public boolean isFQDN(String hostname) {
            if (hostname == null) {
                return false;
            } else {
                return hostname.equals(this.hostname);
            }
        }
        
        public boolean isHELO(String helo) {
            if (helo == null) {
                return false;
            } else {
                return helo.equals(this.helo);
            }
        }
        
        public boolean isQueueID(String queueID) {
            if (queueID == null) {
                return false;
            } else {
                return queueID.equals(this.queueID);
            }
        }
        
        public boolean isQueueID(String client, String queueID) {
            if (client == null) {
                return false;
            } else if (queueID == null) {
                return false;
            } else {
                return client.equals(this.client) && queueID.equals(this.queueID);
            }
        }
        
        public boolean isMessageID(String messageID) {
            if (messageID == null) {
                return false;
            } else {
                return messageID.equals(this.messageID);
            }
        }
        
        public boolean isOrigin(String ip, String hostname) {
            if (hostname == null) {
                return isIP(ip);
            } else {
                return Regex.isHostname(hostname);
            }
        }
        
        public boolean isSender(String sender) {
            if (sender == null) {
                return false;
            } else {
                return sender.equals(this.sender);
            }
        }
        
        public boolean isFrom(String from) {
            if (from == null) {
                return false;
            } else {
                return from.equals(this.from);
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
        
        public boolean isFromBlockedTLD() {
            if (from == null) {
                return false;
            } else {
                int index = from.indexOf('@') + 1;
                String domain = from.substring(index);
                String tld = Domain.extractTLDSafe(domain, true);
                return Block.containsExact(User.this, tld);
            }
        }
        
        public boolean isFromNotComplaince() {
            if (from == null) {
                return false;
            } else {
                int index = from.indexOf('@') + 1;
                String domain = from.substring(index);
                if (domain.length() == 0) {
                    return true;
                } else {
                    return NoReply.containsFQDN(domain);
                }
            }
        }
        
        public boolean headerFromIsInvalid() {
            if (from == null) {
                return false;
            } else if (isSigned(from)) {
                return false;
            } else {
                int index = from.indexOf('@') + 1;
                String domain = from.substring(index);
                if (domain.length() == 0) {
                    return true;
                } else {
                    try {
                        ArrayList<String> mxSet = Reverse.getMXSet(domain);
                        if (mxSet == null) {
                            return true;
                        } else {
                            return mxSet.isEmpty();
                        }
                    } catch (CommunicationException ex) {
                        return false;
                    } catch (ServiceUnavailableException ex) {
                        return false;
                    } catch (NameNotFoundException ex) {
                        return true;
                    } catch (NamingException ex) {
                        Server.logError(ex);
                        return false;
                    }
                }
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
            String blockKey = Block.keyBlockKey(User.this.getEmail(), getIP(), getHELO(), getSender(),
                    getFQDN(), getQualifierName(), getRecipient()
            );
            if (Block.containsExact(blockKey)) {
                return true;
            } else {
                blockKey = Block.getBlockKey(User.this.getEmail(), getIP(),
                        getFQDN(), getRecipientDomain(true)
                );
                return Block.containsExact(blockKey);
            }
        }
        
        public boolean hasDefinedKey() {
            if (isWhiteKey()) {
                return true;
            } else if (isBlockKey()) {
                return true;
            } else if (isWhiteKeyByAdmin()) {
                return true;
            } else if (isBlockKeyByAdmin()) {
                return true;
            } else if (isBanned()) {
                return true;
            } else {
                return false;
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
                } else if (Regex.isHostname(link)) {
                    keySet.add("HREF=." + link);
                } else {
                    keySet.add("HREF=" + link);
                }
            }
            keySet.addAll(getExecutableSetNN());
            return keySet;
        }
        
        public void processComplainForWhite() {
            String whiteKey = getWhiteKey();
            for (long timeKey : getTimeKeySet().descendingSet()) {
                Query query = getQuerySafe(timeKey);
                if (query != null && whiteKey.equals(query.getWhiteKey())) {
                    if (query.isWhite()) {
                        query.clearBlock(timeKey);
                        if (!query.hasMalware()) {
                            query.setHam(timeKey);
                        }
                    }
                }
            }
        }
        
        public void processComplainForBlock() {
            String blockKey = getBlockKey();
            for (long timeKey : getTimeKeySet().descendingSet()) {
                Query query = getQuerySafe(timeKey);
                if (query != null && blockKey.equals(query.getBlockKey())) {
                    if (query.isBlock()) {
                        query.clearWhite(timeKey);
                        setSpam(timeKey);
                    }
                }
            }
        }
        
        public void clearWhite(long timeKey) {
            if (!isRecipientAbuse()) {
                try {
                    String whitekey = getWhiteKey();
                    White.dropExact(getUserEmail() + ":" + whitekey);
                    if (Core.hasAdminEmail()) {
                        White.dropExact(Core.getAdminEmail() + ":" + whitekey);
                    }
                } catch (ProcessException ex) {
                    Server.logError(ex);
                }
                try {
                    String mailFrom = getSender();
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
                    White.clear(timeKey, null, User.this, ip, mailFrom, getFQDN(), qualifierLocal, recipient);
                } catch (ProcessException ex) {
                    Server.logError(ex);
                }
                if (sender == null) {
                    try {
                        White.clear(timeKey, null, User.this, ip, null, getFQDN(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                } else {
                    try {
                        White.clear(timeKey, null, User.this, ip, sender, getFQDN(), qualifier == null ? "NONE" : qualifier.name(), recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(sender)) {
                    try {
                        White.clear(timeKey, null, User.this, ip, sender, getFQDN(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (from != null) {
                    try {
                        White.clear(timeKey, null, User.this, ip, from, getFQDN(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(from)) {
                    try {
                        White.clear(timeKey, null, User.this, ip, from, getFQDN(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (replyto != null) {
                    try {
                        White.clear(timeKey, null, User.this, ip, replyto, getFQDN(), "NONE", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(replyto)) {
                    try {
                        White.clear(timeKey, null, User.this, ip, replyto, getFQDN(), "PASS", recipient);
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                try {
                    White.clear(timeKey, null, User.this, ip, null, getFQDN(), "NONE", recipient);
                } catch (ProcessException ex) {
                    Server.logError(ex);
                }
            }
        }
        
        public void clearBlock(long timeKey) {
            if (CIDR.isDesirable(getIP())) {
                Block.clearCIDR(timeKey, getIP(), getUserEmail());
            }
            if (FQDN.isDesirable(getValidHostDomainSafe())) {
                Block.clearFQDN(timeKey, getValidHostDomainSafe(), getUserEmail());
            }
            if (canClearBLOCK() && !isFromReserved() && !isToReserved() && !NoReply.contains(getTrueSender(), true)) {
                try {
                    String blockKey = getBlockKey();
                    Block.dropExact(getUserEmail() + ":" + blockKey);
                    if (Core.hasAdminEmail()) {
                        Block.dropExact(Core.getAdminEmail() + ":" + blockKey);
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
                try {
                    String banKey = getBannedKey();
                    Block.dropExact(getUserEmail() + ":" + banKey + ">@");
                    if (Core.hasAdminEmail()) {
                        Block.dropExact(Core.getAdminEmail() + ":" + banKey + ">@");
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
                try {
                    String mailFrom = getSender();
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
                    Block.clear(timeKey, null, User.this, ip, helo, mailFrom, getFQDN(), qualifierLocal, recipient, "WHITE");
                } catch (ProcessException ex) {
                    Server.logError(ex);
                }
                if (sender == null) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, null, getFQDN(), "NONE", recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                } else {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, sender, getFQDN(), qualifier == null ? "NONE" : qualifier.name(), recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(sender)) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, sender, getFQDN(), "PASS", recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (from != null) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, from, getFQDN(), "NONE", recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(from)) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, from, getFQDN(), "PASS", recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (replyto != null) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, replyto, getFQDN(), "NONE", recipient, "WHITE");
                    } catch (ProcessException ex) {
                        Server.logError(ex);
                    }
                }
                if (isSigned(replyto)) {
                    try {
                        Block.clear(timeKey, null, User.this, ip, helo, replyto, getFQDN(), "PASS", recipient, "WHITE");
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
                        Block.clearHREF(timeKey, User.this, link, email);
                    }
                }
            }
        }
        
        public void blockExecutables(long timeKey) {
            if (executableSet != null) {
                for (String signature : executableSet) {
                    if (!Ignore.containsExact(getEmail() + ":" + signature)) {
                        if (Block.addExact(signature)) {
                            Server.logDebug(timeKey, "new BLOCK '" + signature + "' added by 'EXECUTABLE'.");
                            Peer.sendBlockToAll(signature);
                        }
                    }
                }
            }
        }
        
        public void blockPhishings(long timeKey) {
            if (linkMap != null) {
                for (String link : linkMap.keySet()) {
                    String domain = null;
                    Flag flag = URI.getFlag(link);
                    if (flag == Flag.BENEFICIAL) {
                        continue;
                    } else if (flag == Flag.DESIRABLE) {
                        continue;
                    } else if (Core.isSignatureURL(link)) {
                        domain = Core.getSignatureHostnameURL(link);
                        if (Provider.containsFQDN(domain)) {
                            continue;
                        } else if (Ignore.containsFQDN(domain)) {
                            continue;
                        }
                        domain = null;
                    } else if (isSameRootDomain(link)) {
                        continue;
                    } else if (Regex.isHostname(link)) {
                        link = Domain.normalizeHostname(link, true);
                        if (Provider.containsFQDN(link)) {
                            continue;
                        } else if (Ignore.containsFQDN(link)) {
                            continue;
                        } else {
                            domain = Domain.extractDomainSafe(link, true);
                        }
                    } else if (isValidEmail(link)) {
                        if ((domain = Domain.extractDomainSafe(link, true)) != null) {
                            if (Ignore.containsExact(domain)) {
                                continue;
                            } else if (Ignore.containsFQDN(domain.substring(1))) {
                                continue;
                            } else if (getEmail().endsWith(domain)) {
                                continue;
                            } else if (getRecipientNotNull().endsWith(domain)) {
                                continue;
                            } else if (Provider.containsExact(domain)) {
                                domain = null;
                            }
                        }
                    }
                    if (NoReply.containsFQDN(domain)) {
                        if (Block.addExact("HREF=" + domain)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + domain + "' added by 'PHISHING'.");
                        }
                        if (Block.addExact(getEmail() + ":HREF=" + domain)) {
                            Server.logDebug(timeKey, "new BLOCK '" + getEmail() + ":HREF=" + domain + "' added by 'PHISHING'.");
                        }
                    } else if (domain == null && isValidIP(link)) {
                        link = Subnet.normalizeIP(link);
                        if (Block.addExact("HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + link + "' added by 'PHISHING'.");
                        }
                    } else if (domain == null && Core.isSignatureURL(link)) {
                        if (Block.addExact(link)) {
                            Server.logDebug(timeKey, "new BLOCK '" + link + "' added by 'PHISHING'.");
                        }
                    } else if (flag == Flag.HARMFUL) {
                        if (Block.addExact("HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + link + "' added by 'HARMFUL'.");
                        }
                        if (Block.addExact(getEmail() + ":HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK '" + getEmail() + ":HREF=" + link + "' added by 'HARMFUL'.");
                        }
                    } else if (Generic.containsGenericFQDN(link) || Generic.isGenericEC2(link)) {
                        if (Block.addExact("HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=" + link + "' added by 'GENERIC'.");
                        }
                        if (Block.addExact(getEmail() + ":HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK '" + getEmail() + ":HREF=" + link + "' added by 'GENERIC'.");
                        }
                    } else if (flag == Flag.UNDESIRABLE) {
                        if (Block.addExact(getEmail() + ":HREF=" + link)) {
                            Server.logDebug(timeKey, "new BLOCK '" + getEmail() + ":HREF=" + link + "' added by 'UNDESIRABLE'.");
                        }
                    }
                }
            }
        }
        
        public boolean blockKey(long timeKey, String cause) {
            clearWhite(timeKey);
            setSpam(timeKey);
            if (Block.addExact(getUserEmail() + ":" + getBlockKey())) {
                Server.logDebug(timeKey, "new BLOCK '" + getUserEmail() + ":"
                        + getBlockKey() + "' caused by '"
                        + cause + "'."
                );
                return true;
            } else {
                return false;
            }
        }
        
        public boolean ban(long timeKey, String cause) {
            blockExecutables(timeKey);
            blockPhishings(timeKey);
            String key = Block.keyBlockKey(
                    User.this, ip, helo, hostname,
                    sender, qualifier,
                    getRecipientDomain(true)
            );
            if (Block.addExact(key)) {
                Server.logDebug(timeKey, "new BLOCK '"
                        + key + "' caused by '"
                        + cause + "'."
                );
                return true;
            } else {
                return false;
            }
        }
        
        public boolean ban(long timeKey, String email, String cause) {
            if (email == null) {
                return false;
            } else if (cause == null) {
                return false;
            } else {
                blockExecutables(timeKey);
                blockPhishings(timeKey);
                String key = Block.keyBlockKey(
                        email, ip, helo, sender,
                        hostname, qualifier, "@"
                );
                if (Block.addExact(key)) {
                    Server.logDebug(timeKey, "new BLOCK '"
                            + key + "' caused by '"
                            + cause + "'."
                    );
                    return true;
                } else {
                    return false;
                }
            }
        }
        
        private boolean block(long timeKey, String token, String cause) {
            if (Block.addExact(token)) {
                Server.logDebug(timeKey, "new BLOCK '"
                        + token + "' caused by '"
                        + cause + "'."
                );
                return true;
            } else {
                return false;
            }
        }
        
        public boolean banOrBlockForAdmin(long timeKey, String cause) {
            String email = Core.getAdminEmail();
            if (email == null) {
                return false;
            } else if (isPass() && Provider.isFreeMail(getSender())) {
                return ban(timeKey, email, cause);
            } else if (Ignore.containsFQDN(getFQDN())) {
                return block(timeKey, email + ':' + getBlockKey(), cause);
            } else if (Provider.containsFQDN(getFQDN())) {
                return block(timeKey, email + ':' + getBlockKey(), cause);
            } else if (isPass() && Ignore.contains(getSender())) {
                return block(timeKey, email + ':' + getBlockKey(), cause);
            } else if (isPass() && Provider.containsDomain(getSender())) {
                return block(timeKey, email + ':' + getBlockKey(), cause);
            } else if (isSenderMailerDeamon()) {
                return block(timeKey, email + ':' + getBlockKey(), cause);
            } else {
                return ban(timeKey, email, cause);
            }
        }
        
        public boolean blockForRecipient(long time) {
            return blockForRecipient(time, true);
        }
        
        public boolean blockForRecipient(long time, boolean clear) {
            if (recipient == null) {
                return false;
            } else {
                if (clear) {
                    clearWhite(time);
                }
                SPF.setSpam(time, tokenSet);
                return Block.addSafe(
                        User.this,
                        getBlockKey() + ">" + recipient
                );
            }
        }
        
        public boolean blockForAdmin(long time) {
            String email = Core.getAdminEmail();
            if (email == null) {
                return false;
            } else {
                String blockKey = getBlockKey();
                return Block.addExact(email + ':' + blockKey);
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
        
        public boolean block(long timeKey, String situationName) {
            try {
                Situation situation = Situation.valueOf(situationName);
                return block(timeKey, situation);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean setSpam(long time) {
            return SPF.setSpam(time, tokenSet);
        }
        
        public boolean setHam(long time) {
            return SPF.setHam(time, tokenSet);
        }
        
        public boolean block(long timeKey, Situation situation) {
            try {
                clearWhite(timeKey);
                setSpam(timeKey);
                switch (situation) {
                    case AUTHENTIC:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        return Block.add(User.this, getSenderSimplified(true, true));
                    case BULK:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        return Block.add(User.this, getSenderSimplified(true, true) + ";BULK");
                    case NONE:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        String domain1 = this.getOriginDomain(false);
                        if (domain1 == null) {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";NONE");
                        } else {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";" + domain1);
                        }
                    case ZONE:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        String domain2 = this.getOriginDomain(false);
                        if (domain2 == null) {
                            return Block.add(User.this, getSenderDomain(true) + ";NOTPASS");
                        } else {
                            return Block.add(User.this, getSenderDomain(true) + ";" + domain2);
                        }
                    case IP:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        return Block.add(User.this, getSenderDomain(true) + ";NOTPASS");
                    case SAME:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        String validator = getValidator(false);
                        if (validator == null) {
                            return false;
                        } else {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";" + validator);
                        }
                    case DOMAIN:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
                        String senderSimplified = getSenderSimplified(true, true);
                        if (senderSimplified == null) {
                            return false;
                        } else {
                            return Block.add(User.this, senderSimplified);
                        }
                    case ORIGIN:
                    case ALL:
                        Block.addExact(getUserEmail() + ":" + getBlockKey());
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
        
        public boolean whiteKey(long timeKey) {
            clearBlock(timeKey);
            SPF.setHam(timeKey, tokenSet);
            return White.addExact(getUserEmail() + ":" + getWhiteKey());
        }
        
        public boolean whiteKeyForRecipient(long timeKey) {
            if (recipient == null) {
                return false;
            } else {
                clearBlock(timeKey);
                SPF.setHam(timeKey, tokenSet);
                return White.addExact(
                        getUserEmail() + ":"
                                + getWhiteKey()
                                + ">" + recipient
                );
            }
        }
        
        public boolean whiteKeyForAdmin() {
            String email = Core.getAdminEmail();
            if (email == null) {
                return false;
            } else {
                return White.addExact(email + ":" + getWhiteKey());
            }
        }
        
        public boolean white(long timeKey, Situation situation) {
            try {
                if (situation == null) {
                    return false;
                } else {
                    String domain;
                    clearBlock(timeKey);
                    SPF.setHam(timeKey, tokenSet);
                    switch (situation) {
                        case ORIGIN:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
                            domain = getValidHostDomainSafe();
                            if (domain == null) {
                                return White.addExact(getUserEmail() + ":mailer-daemon@;" + getIP());
                            } else {
                                return White.addExact(getUserEmail() + ":mailer-daemon@" + domain + ";" + domain);
                            }
                        case IP:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
                            return White.add(User.this, getSenderSimplified(false, true) + ";" + getIP());
                        case ZONE:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
                            domain = getValidHostDomainSafe();
                            if (domain == null) {
                                return false;
                            } else {
                                return White.add(User.this, getSenderSimplified(false, true) + ";" + domain);
                            }
                        case AUTHENTIC:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
                            return White.add(User.this, getSenderSimplified(false, true) + ";PASS");
                        case BULK:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
                            return White.add(User.this, getSenderSimplified(false, true) + ";BULK");
                        case SAME:
                            White.addExact(getUserEmail() + ":" + getWhiteKey());
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
                                boolean resubscribed = NoReply.resubscribe(recipientAddr);
                                return added || removed || resubscribed;
                            }
                        case MALWARE:
                            String malwareLocal = getMalware();
                            if (malwareLocal == null) {
                                return false;
                            } else if (Ignore.addExact(getEmail() + ":MALWARE=" + malwareLocal)) {
                                Server.logDebug(timeKey, "false positive MALWARE '" + malwareLocal + "' detected by '" + getEmail() + "'.");
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
        
        public boolean hasQueueID() {
            return queueID != null;
        }
        
        public boolean hasClientQueueID() {
            return client != null && queueID != null;
        }
        
        public String getClientQueueID() {
            return queueID + "@" + client;
        }
        
        public boolean hasReplyTo() {
            return replyto != null;
        }
        
        public boolean hasHeaderFrom() {
            return from != null;
        }
        
        public boolean hasSubject() {
            return subject != null;
        }
        
        public boolean hasBodyInformation() {
            if (signerSet != null) {
                return true;
            } else if (linkMap != null) {
                return true;
            } else if (executableSet != null) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean hasBodyInformation2() {
            if (signerSet != null) {
                return true;
            } else if (linkMap != null) {
                return true;
            } else if (executableSet != null) {
                return true;
            } else if (malware != null) {
                return true;
            } else if (body != null) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean hasHeaderInformation() {
            if (from != null) {
                return true;
            } else if (replyto != null) {
                return true;
            } else if (subject != null) {
                return true;
            } else if (messageID != null) {
                return true;
            } else if (queueID != null) {
                return true;
            } else if (date != null) {
                return true;
            } else if (unsubscribe != null) {
                return true;
            } else {
                return false;
            }
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
        
        public boolean hasMalwareIgnored() {
            if (malware == null) {
                return false;
            } else if (Ignore.containsExact(getEmail() + ":MALWARE=" + malware)) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean isHolding() {
            return result.equals("HOLD");
        }
        
        public boolean isFlagged() {
            return result.equals("FLAG");
        }
        
        public boolean isFinished() {
            return !result.equals("HOLD") && !result.equals("LISTED") && !result.equals("GREYLIST");
        }
        
        public boolean isDelivered() {
            return result.equals("WHITE") || result.equals("ACCEPT");
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
        
        public void setRecipientAdvised() {
            this.CHANGED.acquire();
            this.recipientAdvised = true;
            User.CHANGED = true;
            this.CHANGED.release(true);
        }
        
        public boolean isUserAdvised() {
            return userAdvised;
        }
        
        public boolean isAbuseAdvised() {
            return abuseAdvised;
        }
        
        public String getAbuseReported() {
            return abuseEmail;
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
        
        public boolean isBlock() {
            return getBlock() != null;
        }
        
        public String getBlockedCIDR() {
            return Block.findCIDR(ip);
        }
        
        public boolean isBlockedCIDR() {
            return CIDR.containsIP(ip);
        }
        
        public boolean isAnyLinkBLOCK(long tikeKey, boolean findIP) {
            for (String token : getLinkKeySet()) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        return true;
                    } else {
                        token = Core.getSignatureHostURL(token);
                    }
                }
                if (Block.findHREF(tikeKey, User.this, token, findIP) != null) {
                    setLinkBlocked(token);
                    return true;
                }
            }
            return false;
        }
        
        public String getBlockHREF(long timeKey, boolean findIP) {
            String block = null;
            for (String token : getLinkKeySet()) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        return token;
                    } else {
                        token = Core.getSignatureHostURL(token);
                    }
                }
                if ((block = Block.findHREF(timeKey, User.this, token, findIP)) != null) {
                    setLinkBlocked(token);
                    break;
                }
            }
            return block;
        }
        
        public boolean isSubjectBlockedREGEX() {
            return Block.matchesWithText(User.this, getSubject());
        }
        
        public boolean isSubjectEmpty() {
            String subjectLocal = getSubject();
            if (subjectLocal == null) {
                return usingHeader();
            } else {
                return subjectLocal.isEmpty();
            }
        }
        
        public boolean isBodySuspect() {
            return getBodySuspect() != null;
        }
        
        public String getBodySuspect() {
            String bodyPlain = getTextPlainBody();
            if (bodyPlain == null) {
                return null;
            } else if (sizeLinkKeySet() == 0 && Core.hasBitcoinPattern(bodyPlain)) {
                // Found a Bitcoin wallet but 
                // the body don't have just one link.
                // Suspect to be a fake extortion.
                return "hasBitcoinPattern";
            } else {
                return null;
            }
        }
        
        public boolean hasBitcoinInBody() {
            return Core.hasBitcoinPattern(getTextPlainBody());
        }
        
        public boolean isAnyLinkSuspect(boolean findIP) {
            return getAnyLinkSuspect(findIP) != null;
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
        
        public boolean isRoutable() {
            if (recipient == null) {
                return true;
            } else {
                return getTrapTime() == null;
            }
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
            } else if (isRecipientAdmin()) {
                return true;
            } else if (isRecipientAbuse()) {
                return true;
            } else {
                return false;
            }
        }
        
        public boolean isFromReserved() {
            if (sender == null) {
                return true;
            } else if (sender.startsWith("postmaster@")) {
                return true;
            } else if (sender.startsWith("abuse@")) {
                return true;
            } else if (sender.startsWith("mailer-daemon@")) {
                return true;
            } else if (from == null) {
                return hasHeaderInformation();
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
        
        public boolean isSenderBlock(boolean validation) {
            if (validation) {
                String senderLocal = getTrueSender();
                if (!Provider.isFreeMail(senderLocal) && sentByBULK()) {
                    return Block.containsExact(User.this, getSenderDomain(true) + ";BULK");
                } else {
                    return Block.containsExact(User.this, getSenderDomain(true) + ";NOTPASS");
                }
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
        
        public boolean isBulkBlock() {
            return Block.containsExact(User.this, getSenderDomain(true) + ";BULK");
        }
        
        public boolean isSenderTrustable() {
            String senderLocal = getTrueSender();
            if (senderLocal == null) {
                return false;
            } else if (senderLocal.isEmpty()) {
                return false;
            } else if (isSigned(senderLocal)) {
                return true;
            } else if (isPass() && isMailFrom(senderLocal)) {
                return true;
            } else if (Provider.containsDomain(getFQDN())) {
                return true;
            } else {
                String domainSender = getSenderDomain(false);
                if (domainSender == null) {
                    return false;
                } else {
                    String domainHostname = getValidHostDomainSafe();
                    return domainSender.equals(domainHostname);
                }
            }
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
        
        public boolean isSenderRecent() {
            if (sender == null) {
                return false;
            } else {
                SPF spf = SPF.getSPF(sender);
                if (spf == null) {
                    return false;
                } else {
                    return spf.isRecent();
                }
            }
        }
        
        public boolean isBeneficial() {
            if (isSenderFreemail()) {
                return Reputation.isBeneficial(
                        ip, hostname, helo, sender, qualifier, null, null
                );
            } else {
                return Reputation.isBeneficial(
                        ip, hostname, helo, sender, qualifier, from, signerSet
                );
            }
        }
        
        @Override
        public TreeSet<String> getLinkSet() {
            if (linkMap == null) {
                return null;
            } else {
                TreeSet<String> resultSet = new TreeSet<>();
                resultSet.addAll(linkMap.keySet());
                return resultSet;
            }
        }
        
        @Override
        public TreeSet<String> getExecutableSet() {
            return executableSet;
        }
        
        public TreeSet<String> getExecutableSetNN() {
            if (executableSet == null) {
                return new TreeSet<>();
            } else {
                return executableSet;
            }
        }
        
        public TreeSet<String> getTokenSet() {
            TreeSet<String> resultSet = new TreeSet<>();
            resultSet.addAll(tokenSet);
            return resultSet;
        }
        
        public String getFilter() {
            return filter;
        }
        
        public Filter getFilterEnum() {
            if (filter == null) {
                return null;
            } else {
                try {
                    int index = filter.indexOf(';');
                    if (index == -1) {
                        return Filter.valueOf(filter);
                    } else {
                        return Filter.valueOf(filter.substring(0, index));
                    }
                } catch (IllegalArgumentException ex) {
                    return null;
                }
            }
        }
        
        @Override
        public boolean isFilter(Filter... filterArray) {
            if (filterArray == null) {
                return false;
            } else if (this.filter == null) {
                return false;
            } else {
                for (Filter filter : filterArray) {
                    if (this.filter.equals(filter.name())) {
                        return true;
                    } else if (this.filter.startsWith(filter.name() + ';')) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        public boolean isSenderHijacked() {
            String malware = getMalware();
            if (malware == null) {
                return false;
            } else if (malware.startsWith("SPFBL.Subject.")) {
                return true;
            } else if (malware.startsWith("SPFBL.Encrypted.")) {
                return true;
            } else if (malware.startsWith("Porcupine.Malware.")) {
                return true;
            } else if (malware.startsWith("Porcupine.Phishing.")) {
                return true;
            } else if (malware.startsWith("Sanesecurity.Badmacro.")) {
                return true;
            } else if (malware.startsWith("Sanesecurity.Foxhole.")) {
                return true;
            } else {
                return false;
            }
        }
        
        @Override
        public String getMalware() {
            return malware;
        }
        
        public String getMalwareOrExecutable() {
            if (malware != null) {
                return malware;
            } else if (executableSet != null && !executableSet.isEmpty()) {
                return "SPFBL." + executableSet.first();
            } else {
                return null;
            }
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
        
        private transient String instance = null;
        
        public boolean isInstance(String instance) {
            if (instance == null) {
                return false;
            } else if (instance.trim().length() == 0) {
                return false;
            } else {
                return instance.trim().equals(this.instance);
            }
        }
        
        public boolean setPostfixHOLD(String instance) {
            if (instance == null) {
                return false;
            } else if (instance.trim().length() == 0) {
                return false;
            } else {
                this.CHANGED.acquire();
                this.result = "HOLD";
                this.instance = instance.trim();
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            }
        }
        
        public boolean setPostfixFLAG(String instance) {
            if (instance == null) {
                return false;
            } else if (instance.trim().length() == 0) {
                return false;
            } else {
                this.CHANGED.acquire();
                this.result = "FLAG";
                this.instance = instance.trim();
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
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
        
        public boolean setResultFilter(String result, String filter) {
            if (result == null && filter == null) {
                return false;
            } else if (result == null) {
                this.CHANGED.acquire();
                this.filter = filter;
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            } else if (result.equals("MALWARE")) {
                this.CHANGED.acquire();
                this.malware = "FOUND";
                this.result = "REJECT";
                this.filter = filter;
                this.STORED = false;
                this.CHANGED.release(true);
                return User.CHANGED = true;
            } else if (!result.equals(this.result)) {
                this.CHANGED.acquire();
                this.result = result;
                this.filter = filter;
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
            } else if (filter.equals("aceita") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("aceitas") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("aceito") && isResult("ACCEPT")) {
                return true;
            } else if (filter.equals("aceitos") && isResult("ACCEPT")) {
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
            } else if (filter.equals("suspected") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspect") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspects") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspeito") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspeita") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspeitos") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("suspeitas") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("flagged") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("junk") && isResult("FLAG")) {
                return true;
            } else if (filter.equals("trap") && isResult("TRAP")) {
                return true;
            } else if (filter.equals("spamtrap") && isResult("TRAP")) {
                return true;
            } else if (filter.equals("malware") && hasMalware()) {
                return true;
            } else if (filter.equals("virus") && hasMalware()) {
                return true;
            } else if (filter.equals("vírus") && hasMalware()) {
                return true;
            } else if (isValidIPv4(filter)) {
                filter = SubnetIPv4.normalizeIPv4(filter);
                return filter.equals(getIP());
            } else if (isValidIPv6(filter)) {
                filter = SubnetIPv6.normalizeIPv6(filter);
                return filter.equals(getIP());
            } else if (isValidEmail(filter)) {
                if (filter.equals(getSender())) {
                    return true;
                } else if (filter.equals(getFrom())) {
                    return true;
                } else if (filter.equals(getReplyTo())) {
                    return true;
                } else if (filter.equals(getRecipient())) {
                    return true;
                } else {
                    TreeSet<String> linkSet = getLinkSet();
                    if (linkSet == null) {
                        return false;
                    } else {
                        for (String token : linkSet) {
                            if (filter.equals(token)) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
            } else if (Domain.hasTLD(filter)) {
                filter = Domain.normalizeHostname(filter, true);
                if (filter.endsWith("." + getHELO())) {
                    return true;
                } else if (filter.endsWith("." + getClient())) {
                    return true;
                } else if (filter.endsWith("." + getFQDN())) {
                    return true;
                } else if (filter.endsWith("." + getMailFromHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getHeaderFromHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getReplyToHostnameSafe(false))) {
                    return true;
                } else if (filter.endsWith("." + getRecipientHostname(false))) {
                    return true;
                } else {
                    TreeSet<String> linkSet = getLinkSet();
                    if (linkSet == null) {
                        return false;
                    } else {
                        for (String token : linkSet) {
                            int index = token.indexOf('@') + 1;
                            if (index > 0) {
                                token = "." + token.substring(index);
                            }
                            if (filter.endsWith(token)) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
            } else {
                Date date = User.this.getDate(filter);
                if (date == null) {
                    return false;
                } else if (time < date.getTime()) {
                    return false;
                } else {
                    return time < date.getTime() + 86400000;
                }
            }
        }
        
        @Override
        public String getFrom() {
            return from;
        }
        
        @Override
        public String getReplyTo() {
            return replyto;
        }
        
        @Override
        public String getInReplyTo() {
            return inreplyto;
        }

        public Timestamp getMessageDate() {
            return date;
        }
        
        public Date getMessageDate(Calendar calendar) {
            if (date == null) {
                return null;
            } else if (calendar == null) {
                return date;
            } else {
                calendar.setTime(date);
                return calendar.getTime();
            }
        }
        
        @Override
        public String getSubject() {
            return subject;
        }
        
        public String getSubjectWordSet(int minimum) {
            return Dictionary.toString(subject, locale, recipient, minimum);
        }
        
        public String getSubject(int maxLength) {
            if (subject == null) {
                return null;
            } else if (subject.length() > maxLength) {
                return subject.substring(0, maxLength).trim() + "...";
            } else {
                return subject;
            }
        }
        
        @Override
        public String getMessageID() {
            return messageID;
        }
        
        @Override
        public String getQueueID() {
            return queueID;
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
        
        public URL cloneUnsubscribe() {
            if (unsubscribe == null) {
                return null;
            } else {
                try {
                    return new URL(unsubscribe.toExternalForm());
                } catch (MalformedURLException ex) {
                    return null;
                }
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
        
        public boolean hasSignatureURL() {
            if (linkMap == null) {
                return false;
            } else if (linkMap.isEmpty()) {
                return false;
            } else {
                for (String link : linkMap.keySet()) {
                    if (Core.isSignatureURL(link)) {
                        return true;
                    } else if (isValidIP(link)) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        public boolean hasLinkBlocked() {
            if (linkMap == null) {
                return false;
            } else if (linkMap.isEmpty()) {
                return false;
            } else {
                for (String link : linkMap.keySet()) {
                    Boolean blocked = linkMap.get(link);
                    if (blocked == true) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        public boolean isInvalidDate(long time) {
            if (date == null) {
                return false;
            } else {
                return Math.abs(time - date.getTime()) > (21 * Server.DAY_TIME);
            }
        }
        
        private int sizeLinkKeySet() {
            if (linkMap == null) {
                return 0;
            } else {
                return linkMap.size();
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
        
        @Override
        public TreeSet<String> getSignerSet() {
            return signerSet;
        }
        
        private TreeSet<String> getLinkKeySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (linkMap != null) {
                keySet.addAll(linkMap.keySet());
            }
            return keySet;
        }
        
        private TreeSet<String> getLinkKeySetSimple() {
            TreeSet<String> keySet = new TreeSet<>();
            if (linkMap != null) {
                for (String link : linkMap.keySet()) {
                    link = Core.tryGetSignatureRootURL(link);
                    keySet.add(link);
                }
            }
            return keySet;
        }
        
        public boolean addLink(long timeKey, String link) {
            if ((link = normalizeLink(link)) == null) {
                return false;
            } else if (link.equals(getUserEmail())) {
                return false;
            } else if (link.equals(getRecipient())) {
                return false;
            } else {
                boolean blacklisted;
                if (isToPostmaster()) {
                    blacklisted = false;
                } else if (isRecipientAdmin()) {
                    blacklisted = false;
                } else if (isRecipientAbuse()) {
                    blacklisted = false;
                } else if (Block.findHREF(timeKey, User.this, link, false) == null) {
                    blacklisted = false;
                } else {
                    blacklisted = true;
                }
                this.CHANGED.acquire();
                try {
                    if (this.linkMap == null) {
                        this.linkMap = new TreeMap<>();
                    }
                    this.linkMap.put(link, blacklisted);
                    this.STORED = false;
                    User.CHANGED = true;
                    return blacklisted;
                } finally {
                    this.CHANGED.release(true);
                }
            }
        }
        
        public String setLinkSet(long timeKey, TreeSet<String> linkSet) {
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
                        setMalware(timeKey, malware);
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
                        } else if (isRecipientAdmin()) {
                            resultMap.put(link, false);
                        } else if (isRecipientAbuse()) {
                            resultMap.put(link, false);
                        } else if ((block = Block.findHREF(timeKey, User.this, link, false)) == null) {
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
        
        public String setMalware(long time, String malware) {
            if (malware == null) {
                return null;
            } else if ((malware = malware.length() == 0 ? "FOUND" : malware).equals(this.malware)) {
                return null;
            } else if (isRecipientAbuse()) {
                this.CHANGED.acquire();
                this.malware = malware;
                this.filter = "MALWARE_TO_ABUSE";
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                return "ACCEPT";
            } else if (Ignore.containsExact(getEmail() + ":MALWARE=" + malware)) {
                this.CHANGED.acquire();
                if (this.malware == null) {
                    this.malware = malware;
                }
                if (this.filter == null) {
                    this.filter = "MALWARE_IGNORED";
                }
                this.STORED = false;
                User.CHANGED = true;
                this.CHANGED.release(true);
                return "ACCEPT";
            } else {
                this.CHANGED.acquire();
                this.malware = malware;
                this.result = "REJECT";
                this.filter = "MALWARE_NOT_IGNORED";
                this.STORED = false;
                this.CHANGED.release(true);
                User.CHANGED = true;
                if (isUndesirable()) {
                    banOrBlock(time, "MALWARE");
                }
                return "REJECT";
            }
        }
        
        public String getTextPlainBody() {
            return getTextPlainBody(-1);
        }
        
        public String getTextPlainBody(int limit) {
            if (body == null) {
                return null;
            } else if (charset == null) {
                return null;
            } else if (client.equals(Core.getHostname())) {
                try {
                    String text = new String(body, getSupportedCharset());
                    text = Dictionary.normalizeCharacters(text);
                    text = text.replaceAll("(^\\h*)|(\\h*$)", "");
                    text = text.trim();
                    if (limit == -1) {
                        return text;
                    } else if (text.length() < 8) {
                        text = null;
                    } else if (text.length() > limit) {
                        int last = text.lastIndexOf(' ', limit);
                        if (last > 0) {
                            limit = last;
                        }
                        text = text.substring(0, limit);
                        text = text.trim() + "...";
                    }
                    return text;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
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
                    String html = baOS.toString(getSupportedCharsetToString());
                    Document document = Jsoup.parse(html);
                    document = document.normalise();
                    String text = document.text();
                    text = Dictionary.normalizeCharacters(text);
                    text = text.replaceAll("(^\\h*)|(\\h*$)", "");
                    text = text.trim();
                    if (limit == -1) {
                        return text;
                    } else if (text.length() < 8) {
                        text = null;
                    } else if (text.length() > limit) {
                        int last = text.lastIndexOf(' ', limit);
                        if (last > 0) {
                            limit = last;
                        }
                        text = text.substring(0, limit);
                        text = text.trim() + "...";
                    }
                    return text;
                } catch (ZipException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (EOFException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        }
        
        private StringBuilder getStringBuilderHeader() {
            String encoded = null;
            try {
                if (subject != null) {
                    encoded = MimeUtility.encodeText(subject);
                }
            } catch (UnsupportedEncodingException ex) {
                Server.logError(ex);
            }
            StringBuilder builder = new StringBuilder();
            builder.append("Subject: ");
            if (encoded != null) {
                builder.append(encoded);
            }
            builder.append("\r\n");
            builder.append("From: <");
            if (from != null) {
                builder.append(from);
            } else if (sender != null) {
                builder.append(sender);
            }
            builder.append(">\r\n");
            if (recipient != null) {
                builder.append("To: <");
                builder.append(recipient);
                builder.append(">\r\n");
            }
            if (date != null) {
                builder.append("Date: ");
                builder.append(Core.getEmailDate(date));
                builder.append("\r\n");
            }
            if (replyto != null) {
                builder.append("Reply-To: <");
                builder.append(replyto);
                builder.append(">\r\n");
            }
            if (messageID != null) {
                builder.append("Message-ID: <");
                builder.append(messageID);
                builder.append(">\r\n");
            }
            if (unsubscribe != null) {
                builder.append("List-Unsubscribe: <");
                builder.append(unsubscribe);
                builder.append(">\r\n");
            }
            return builder;
        }
        
        public MimeMessage getMimeMessageHeader() {
            if (queueID != null && client != null) {
                File incomingFile = new File("./incoming/" + queueID + "@" + client);
                if (incomingFile.exists()) {
                    try {
                        MimeMessage message;
                        try (FileInputStream inputStream = new FileInputStream(incomingFile)) {
                            message = new MimeMessage(null, inputStream);
                        }
                        return message;
                    } catch (java.io.IOException ex) {
                        // Do nothing.
                    } catch (javax.mail.internet.ParseException ex) {
                        // Do nothing.
                    } catch (javax.mail.MessagingException ex) {
                        // Do nothing.
                    } catch (Exception ex) {
                        Server.logError(incomingFile.toString());
                        Server.logError(ex);
                    }
                }
            }
            if (recipient == null) {
                return null;
            } else if (sender == null && from == null) {
                return null;
            } else if (subject == null && date == null && messageID == null) {
                return null;
            } else if (body == null || charset == null || isSenderMailerDeamon()) {
                try {
                    StringBuilder builder = getStringBuilderHeader();
                    builder.append("Content-Type: text/html; charset=UTF-8\r\n\r\n");
                    builder.append("<html><body><hr></body></html>");
                    byte[] bytes = builder.toString().getBytes();
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    
                    Properties props = new Properties();
                    props.putAll(System.getProperties());
                    Session session = Session.getInstance(props);
                    return new MimeMessage(session, inputStream);
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            } else if (client.equals(Core.getHostname())) {
                try {
                    String text = new String(body, getSupportedCharset());
                    StringBuilder builder = getStringBuilderHeader();
                    builder.append("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
                    builder.append(text);
                    byte[] bytes = builder.toString().getBytes();
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    Properties props = new Properties();
                    props.putAll(System.getProperties());
                    Session session = Session.getInstance(props);
                    return new MimeMessage(session, inputStream);
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
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
                    String html = baOS.toString(getSupportedCharsetToString());
                    Document document = Jsoup.parse(html);
                    document = document.normalise();
                    StringBuilder builder = getStringBuilderHeader();
                    builder.append("Content-Type: text/html; charset=UTF-8\r\n\r\n");
                    builder.append(document.html());
                    byte[] bytes = builder.toString().getBytes();
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    Properties props = new Properties();
                    props.putAll(System.getProperties());
                    Session session = Session.getInstance(props);
                    return new MimeMessage(session, inputStream);
                } catch (ZipException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (EOFException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        }
        
        public MimeMessage getMimeMessageBody() {
            if (queueID != null && client != null) {
                File incomingFile = new File("./incoming/" + queueID + "@" + client);
                if (incomingFile.exists()) {
                    try {
                        MimeMessage message;
                        try (FileInputStream inputStream = new FileInputStream(incomingFile)) {
                            message = new MimeMessage(null, inputStream);
                        }
                        if (message.getSize() > 0) {
                            ServerSMTP.removeDangerousObjects(message);
                            return message;
                        }
                    } catch (javax.mail.internet.ParseException ex) {
                        // Do nothing.
                    } catch (javax.mail.MessagingException ex) {
                        // Do nothing.
                    } catch (Exception ex) {
                        Server.logError(incomingFile.toString());
                        Server.logError(ex);
                    }
                }
            }
            if (recipient == null) {
                return null;
            } else if (sender == null && from == null) {
                return null;
            } else if (subject == null && date == null && messageID == null) {
                return null;
            } else if (body == null) {
                return null;
            } else if (charset == null) {
                return null;
            } else if (client.equals(Core.getHostname())) {
                try {
                    String text = new String(body, getSupportedCharset());
                    StringBuilder builder = getStringBuilderHeader();
                    builder.append("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
                    builder.append(text);
                    byte[] bytes = builder.toString().getBytes();
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    
                    Properties props = new Properties();
                    props.putAll(System.getProperties());
                    Session session = Session.getInstance(props);
                    return new MimeMessage(session, inputStream);
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
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
                    String html = baOS.toString(getSupportedCharsetToString());
                    Document document = Jsoup.parse(html);
                    ServerSMTP.removeDangerousObjects(document);
                    document = document.normalise();
                    StringBuilder builder = getStringBuilderHeader();
                    builder.append("Content-Type: text/html; charset=UTF-8\r\n\r\n");
                    builder.append(document.html());
                    byte[] bytes = builder.toString().getBytes();
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    Properties props = new Properties();
                    props.putAll(System.getProperties());
                    Session session = Session.getInstance(props);
                    return new MimeMessage(session, inputStream);
                } catch (ZipException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (EOFException ex) {
                    body = null;
                    charset = null;
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        }
        
        public boolean hasBody() {
            return body != null;
        }
        
        public byte[] cloneBody() {
            if (body == null) {
                return null;
            } else {
                return Arrays.copyOf(body, body.length);
            }
        }
        
        public boolean isTextBodyEmpty() {
            String text = getTextPlainBody();
            if (text == null) {
                return true;
            } else {
                return text.isEmpty();
            }
        }
        
        public boolean hasLinkMap() {
            return linkMap != null;
        }
        
        public boolean setBody(byte[] data, String charsetName) {
            if (data == null) {
                return false;
            } else if (charsetName == null) {
                return false;
            } else {
                this.CHANGED.acquire();
                this.body = data;
                this.charset = charsetName;
                this.CHANGED.release(true);
                this.STORED = false;
                User.CHANGED = true;
                return true;
            }
        }
        
        private Charset getSupportedCharset() {
            String supportedCharset = getSupportedCharsetToString();
            if (supportedCharset == null) {
                return null;
            } else {
                return Charset.forName(supportedCharset);
            }
        }
        
        private String getSupportedCharsetToString() {
            String lower;
            if (charset == null) {
                return null;
            } else if ((lower = charset.toLowerCase()).equals("7bit")) {
                return "US-ASCII";
            } else if (lower.contains("8bit")) {
                return "ISO-8859-1";
            } else if (Core.isSupportedCharset(charset)) {
                return charset;
            } else if (lower.contains("utf-8")) {
                return "UTF-8";
            } else if (lower.contains("iso-8859-1")) {
                return "ISO-8859-1";
            } else if (lower.contains("iso-2022-jp")) {
                return "ISO-2022-JP";
            } else if (lower.contains("cp-850")) {
                return "CP850";
            } else if (lower.contains("ansi_x3.110-1983")) {
                return "ISO-8859-1";
            } else {
                Server.logError("not supported charset: " + charset);
                return "UTF-8";
            }
        }
        
        public boolean needHeader() {
            if (isFail()) {
                return false;
            } else if (Boolean.FALSE.equals(containsRecipient())) {
                return false;
            } else if (usingHeader()) {
                String hostnameLocal = getFQDN();
                String senderLocal = getSender();
                if (senderLocal == null) {
                    return false;
                } else if (isPass() && Provider.isFreeMail(senderLocal)) {
                    return true;
                } else if (hostnameLocal == null) {
                    return false;
                } else if (isBlockSMTP()) {
                    return false;
                } else if (Provider.containsFQDN(hostnameLocal)) {
                    return true;
                } else if (Generic.containsGenericSoft(hostnameLocal)) {
                    return false;
                } else if (Generic.containsGenericSoft(senderLocal)) {
                    return false;
                } else if (isBlockKey()) {
                    return false;
                } else if (isBlockKeyByAdmin()) {
                    return false;
                } else if (isBlockedForRecipient()) {
                    return false;
                } else if (Block.containsWHOIS(User.this, getTrueSender())) {
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
            } else if (usingHeader()) {
                waitHeader(10000);
                return hasSubject() || hasMessageID();
            } else {
                return false;
            }
        }
        
        public boolean banOrBlock(long timeKey, String cause) {
            if (isWhiteKey()) {
                blockKey(timeKey, cause);
                return false;
            } else if (isRecipientAbuse()) {
                blockKey(timeKey, cause);
                return false;
            } else if (isPass() && Provider.isFreeMail(getSender())) {
                ban(timeKey, cause);
                return false;
            } else if (Ignore.containsFQDN(getFQDN())) {
                blockKey(timeKey, cause);
                return false;
            } else if (Provider.containsFQDN(getFQDN())) {
                blockKey(timeKey, cause);
                return false;
            } else if (isPass() && Ignore.contains(getSender())) {
                blockKey(timeKey, cause);
                return false;
            } else if (isPass() && Provider.containsDomain(getSender())) {
                blockKey(timeKey, cause);
                return false;
            } else if (isSenderMailerDeamon()) {
                blockKey(timeKey, cause);
                return false;
            } else if (isWhite()) {
                blockKey(timeKey, cause);
                return false;
            } else if (isFail()) {
                ban(timeKey, cause);
                return true;
            } else if (isValidIP(getHELO())) {
                ban(timeKey, cause);
                return true;
            } else if (isNotComplianceFQDN()) {
                ban(timeKey, cause);
                return true;
            } else if (isFromFreemail()) {
                ban(timeKey, cause);
                return true;
            } else if (isSpoofingFrom()) {
                ban(timeKey, cause);
                return true;
            } else if (isSpoofingFQDN()) {
                ban(timeKey, cause);
                return true;
            } else if (isFromBlocked()) {
                ban(timeKey, cause);
                return true;
            } else if (isFromNotComplaince()) {
                ban(timeKey, cause);
                return true;
            } else if (headerFromIsInvalid()) {
                ban(timeKey, cause);
                return true;
            } else if (isEmptyPTR()) {
                ban(timeKey, cause);
                return true;
            } else {
                blockKey(timeKey, cause);
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
        
        public void setHeader(
                long timeKey,
                String client,
                String from,
                String replyto,
                String subject,
                String messageID,
                String inReplyTo,
                String queueID,
                Date date,
                URL unsubscribe,
                Date arrival
        ) {
            this.CHANGED.acquire();
            try {
                this.client = client;
                this.from = from;
                this.replyto = replyto;
                this.subject = subject;
                this.messageID = messageID;
                this.queueID = queueID;
                this.inreplyto = inReplyTo;
                if (date != null) {
                    this.date = new Timestamp(date.getTime());
                }
                this.unsubscribe = unsubscribe;
                this.arrival = arrival;
                this.STORED = false;
            } finally {
                this.CHANGED.release(true);
                this.STORED = false;
                User.CHANGED = true;
            }
        }
        
        public String setHeader(
                long timeKey,
                Client client,
                String from,
                String replyto,
                String subject,
                String messageID,
                String inReplyTo,
                String queueID,
                String date,
                String unsubscribe,
                Action actionBLOCK,
                Action actionRED
        ) {
            boolean forgedFrom = false;
            boolean spoofedRecipient = false;
            if (from == null || from.isEmpty()) {
                from = null;
            } else {
                from = from.replaceAll("[\\s\\r\\n\\t]+", " ");
                InternetAddress address = ServerSMTP.extractInternetAddress(from, true);
                if (address == null) {
                    from = null;
                } else {
                    String fqdn;
                    String fromAddress = address.getAddress();
                    String personal = Core.tryToDecodeMIME(address.getPersonal());
                    if (isValidEmail(fromAddress)) {
                        from = Domain.normalizeEmail(fromAddress);
                        if (Core.equals(from, recipient) && isNotSigned(from)) {
                            spoofedRecipient = true;
                        } else if (personal != null && !personal.isEmpty()) {
                            if (personal.contains("@")) {
                                personal = personal.replaceAll("[\\s\\r\\n\\t]+", " ");
                                address = ServerSMTP.extractInternetAddress(personal, true);
                                if (address != null) {
                                    personal = address.getAddress().toLowerCase();
                                    String domain1 = Domain.extractDomainSafe(from, false);
                                    String domain2 = Domain.extractDomainSafe(personal, false);
                                    if (!Objects.equals(domain1, domain2)) {
                                        forgedFrom = true;
                                    }
                                    if (personal.equals(recipient) && isNotSigned(personal)) {
                                        spoofedRecipient = true;
                                    }
                                }
                            }
                            if (personal.contains(getRecipientHostname(false)) && isNotSigned(personal)) {
                                spoofedRecipient = true;
                            }
                        }
                    } else if (fromAddress.equals("MAILER-DAEMON") && (fqdn = getFQDN()) != null) {
                        from = "mailer-daemon@" + fqdn;
                    } else {
                        from = null;
                    }
                }
            }
            if (replyto == null || replyto.length() == 0) {
                replyto = null;
            } else if (!Domain.isMailFrom(replyto = replyto.toLowerCase())) {
                replyto = null;
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
            Timestamp emailDate;
            if (date == null) {
                emailDate = new Timestamp(timeKey);
            } else if (date.length() == 0) {
                emailDate = null;
            } else {
                Date newDate = Core.parseEmailDateSafe(date);
                if (newDate == null) {
                    emailDate = null;
                } else {
                    emailDate = new Timestamp(newDate.getTime());
                    if (Math.abs(timeKey - emailDate.getTime()) > 31104000000L) {
                        emailDate = null;
                    }
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
                            String protocol = unsubscribeURL.getProtocol();
                            if (protocol.matches("^https?$")) {
//                                addLink(timeKey, unsubscribeURL.getHost());
                            } else {
                                unsubscribeURL = null;
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
                this.queueID = queueID;
                this.inreplyto = inReplyTo;
                this.date = emailDate;
                this.unsubscribe = unsubscribeURL;
                this.spoofedRecipient = spoofedRecipient;
                this.forgedFrom = forgedFrom;
                this.STORED = false;
            } finally {
                this.CHANGED.release(true);
                User.this.usingHeader = true;
                this.STORED = false;
                User.CHANGED = true;
            }
            putIdentification(messageID, timeKey);
            putIdentification(queueID, getClient(), timeKey);
            return processFilter(timeKey, client, actionRED);
        }
        
        public String processFilter(long timeKey, Client client, Action actionRED) {
            String resultReturn;
            String resultFilter = getFilter();
            Filter filter = Filterable.tryToGetFilter(resultFilter);
            SimpleImmutableEntry<Filter,String> resultEntry = processFilter(client, filter);
            if (resultEntry != null) {
                filter = resultEntry.getKey();
                if (resultFilter == null || !resultFilter.startsWith(filter + ";")) {
                    String reason = resultEntry.getValue();
                    resultFilter = filter.name() + (reason == null ? "" : ';' + reason);
                }
            }
            if (filter == null) {
                addAcceptable();
                resultReturn = null;
                resultFilter = null;
            } else {
                Server.logDebug(timeKey, "FILTER " + resultFilter);
                switch (filter) {
                    case IN_REPLY_TO_DESIRABLE: // 100,00%
                    case ENVELOPE_BENEFICIAL: // 99,90%
                    case ORIGIN_WHITELISTED: // 99,88%
                    case RECIPIENT_BENEFICIAL: // 99,68%
                        whiteKeyForAdmin();
                    case SENDER_MAILER_DEAMON_TRUSTED: // 99,64%
                    case DKIM_BENEFICIAL: // 99,82%
                    case SUBJECT_BENEFICIAL: // 99,74%
                    case IN_REPLY_TO_EXISTENT: // 99,71%
                    case ORIGIN_WHITE_KEY_ADMIN: // 99,68%
                    case CIDR_BENEFICIAL: // 99,67%
                    case SPF_DESIRABLE: // 99,65%
                    case ABUSE_BENEFICIAL: // 99,64%
                    case FQDN_BENEFICIAL: // 99,58%
                    case RECIPIENT_DESIRABLE: // 99,55%
                    case SPF_BENEFICIAL: // 99,53%
                    case FQDN_DESIRABLE: // 99,38%
                    case ENVELOPE_DESIRABLE: // 50,00%
                        whiteKey(timeKey);
                    case BULK_BOUNCE: // 99,91%
                        addBeneficial(timeKey);
                        resultReturn = "WHITE";
                        break;
                    case SENDER_MAILER_DEAMON: // 99,87%
                    case BULK_BENEFICIAL: // 98,41%
                    case RECIPIENT_ABUSE: // 96,59%
                    case FQDN_PROVIDER: // 96,65%
                    case SUBJECT_DESIRABLE: // 91,89%
                    case DKIM_DESIRABLE: // 95,58%
                    case RECIPIENT_POSTMASTER: // 96,40%
                    case SENDER_ESSENTIAL: // 90,75%
                    case FQDN_ESSENTIAL: // 60,59%
                    case ORIGIN_WHITE_KEY_USER: // 50,00%
                    case MALWARE_IGNORED: // 50,00%
                    case RECIPIENT_HACKED: // 50,00%
                    case FROM_ESSENTIAL: // 20,09%
                        addAcceptable();
                        resultReturn = null;
                        break;
                    case FROM_SPOOFED_SENDER: // 99,88%
                    case IP_DYNAMIC: // 95,96%
                    case HELO_ANONYMOUS: // 75,00%
                    case SENDER_SPOOFING: // 75,00%
                        ban(timeKey, Core.getAdminEmail(), filter.name());
                        ban(timeKey, filter.name());
                        addHarmful(timeKey);
                        resultReturn = "BLOCK";
                        break;
                    case ORIGIN_BANNED: // 50,00%
                        addHarmful(timeKey);
                        resultReturn = "BLOCK";
                        break;
                    case MALWARE_NOT_IGNORED: // 99,99%
                    case HREF_UNDESIRABLE: // 99,98%
                    case EXECUTABLE_UNDESIRABLE: // 99,60%
                    case FROM_NOT_SIGNED: // 99,56%
                    case FROM_UNROUTABLE: // 99,21%
                    case FROM_SPOOFED_RECIPIENT: // 99,13%
                    case EXECUTABLE_BLOCKED: // 97,96%
                    case PHISHING_BLOCKED: // 97,73%
                        banOrBlockForAdmin(timeKey, filter.name());
                    case ABUSE_HARMFUL: // 99,98%
                    case SUBJECT_HARMFUL: // 99,86%
                    case FROM_NXDOMAIN: // 50,00%
                    case SENDER_NXDOMAIN: // 50,00%
                    case ENVELOPE_HARMFUL: // 50,00%
                    case RECIPIENT_SPOOFING: // 50,00%
                        banOrBlock(timeKey, filter.name());
                        addHarmful(timeKey);
                        resultReturn = "BLOCK";
                        break;
                    case RECIPIENT_UNDESIRABLE: // 99,96%
                    case ABUSE_BLOCKED: // 99,95%
                    case SUBJECT_UNDESIRABLE: // 99,82%
                    case FROM_BLOCKED: // 99,69%
                    case FROM_FORGED: // 99,40%
                    case RECIPIENT_HARMFUL: // 99,40%
                    case ORIGIN_BLOCK_KEY_ADMIN: // 99,38%
                    case DKIM_HARMFUL: // 98,84%
                    case RECIPIENT_PRIVATE: // 98,31%
                    case FROM_ABSENT: // 97,00%
                    case DOMAIN_INEXISTENT: // 96,97%
                    case ORIGIN_HARMFUL: // 50,00%
                        blockKey(timeKey, filter.name());
                    case ORIGIN_BLOCK_KEY_USER: // 50,00%
                        addUndesirable(timeKey);
                        resultReturn = "BLOCK";
                        break;
                    case FQDN_SPOOFED: // 87,50%
                    case SPF_HARMFUL: // 83,24%
                    case ENVELOPE_BLOCKED: // 82,95%
                    case ORIGIN_BLOCKED: // 78,70%
                    case FQDN_RED: // 77,48%
                    case EXECUTABLE_NOT_IGNORED: // 67,79%
                    case SPF_UNDESIRABLE: // 66,64%
                    case RECIPIENT_RESTRICT: // 66,34%
                    case SENDER_RED: // 65,23%
                    case ENVELOPE_INVALID: // 63,14%
                    case FROM_FREEMAIL: // 58,82%
                    case FQDN_UNDESIRABLE: // 57,38%
                    case SPF_FAIL: // 51,29%
                    case SPF_SPOOFING: // 50,00%
                    case ENVELOPE_UNDESIRABLE: // 50,00%
                    case ORIGIN_UNDESIRABLE: // 50,00%
                    case CIDR_HARMFUL: // 50,00%
                    case FQDN_HARMFUL: // 50,00%
                    case SENDER_INVALID: // 50,00%
                    case DKIM_UNDESIRABLE: // 50,00%
                    case SPF_NXDOMAIN: // 50,00%
                    case HREF_SUSPECT: // 47,96%
                    case SPF_SOFTFAIL: // 35,38%
                    case FROM_SUSPECT: // 34,73%
                    case DOMAIN_EMERGED: // 26,63%
                        if (actionRED == Action.FLAG) {
                            resultReturn = "FLAG";
                        } else if (actionRED == Action.HOLD) {
                            resultReturn = "HOLD";
                        } else {
                            addUndesirable(timeKey);
                            resultReturn = "REJECT";
                        }
                        break;                            
                    default:
                        Server.logError("filter not defined: " + resultFilter);
                        addAcceptable();
                        resultReturn = null;
                }
            }
            setResultFilter(resultReturn, resultFilter);
            return resultReturn;
        }
        
        @Override
        public boolean isForgedFrom() {
            return forgedFrom;
        }
        
        @Override
        public boolean isSpoofedRecipient() {
            return spoofedRecipient;
        }
        
        @Override
        public URL getUnsubscribe() {
            return unsubscribe;
        }
        
        @Override
        public Date getDate() {
            return date;
        }
        
        public Date getArrival() {
            return arrival;
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
        
        public Situation getSenderWhiteSituation() {
            if (isWhiteKey()) {
                String validator = getValidator(true);
                if (validator == null) {
                    return Situation.ORIGIN;
                } else if (validator.equals("PASS")) {
                    return Situation.AUTHENTIC;
                } else if (validator.equals("BULK")) {
                    return Situation.BULK;
                } else if (isValidIP(validator)) {
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
                if (validator.equals("BULK")) {
                    return Situation.BULK;
                } else if (isValidIP(validator)) {
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
        
        public boolean requestReleaseToRecipient(long time) {
            String senderLocal = getTrueSender();
            String recipientLocal = getRecipient();
            String unholdURL;
            String blockURL;
            if (recipientAdvised) {
                return true;
            } else if (inexistent) {
                return false;
            } else if (senderLocal == null) {
                return false;
            } else if (senderLocal.isEmpty()) {
                return false;
            } else if (recipientLocal == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else if (!isValidEmail(senderLocal)) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isWhiteKeyByAdmin()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
                return false;
            } else if ((unholdURL = Core.getUnholdURL(User.this, time)) == null) {
                return false;
            } else if ((blockURL = Core.getBlockURL(User.this, time)) == null) {
                return false;
            } else {
                try {
                    Locale locale = User.this.getLocale();
                    InternetAddress[] recipients;
                    InternetAddress[] replyTo;
                    if (NoReply.isUnsubscribed(recipientLocal)) {
                        recipients = InternetAddress.parse(getUserEmail());
                        replyTo = InternetAddress.parse(senderLocal);
                    } else {
                        recipients = InternetAddress.parse(recipientLocal);
                        replyTo = User.this.getInternetAddresses();
                    }
                    MimeMessage forwardMessage;
                    Document templateHTML;
                    File logoFile;
                    String subjectLocal;
                    Element linkSender;
                    Element btnRelease;
                    Element btnBlock;
                    Element btnUnsubscribe;
                    String unsubscribeURL;
                    if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                        return false;
                    } else if ((forwardMessage = getMimeMessageBody()) == null) {
                        return false;
                    } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                        return false;
                    } else if ((templateHTML = Core.getTemplateWarningRetentionRecipient(User.this, locale)) == null) {
                        return false;
                    } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                        return false;
                    } else if ((linkSender = templateHTML.getElementById("sender")) == null) {
                        return false;
                    } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                        return false;
                    } else if ((btnBlock = templateHTML.getElementById("urlBlock")) == null) {
                        return false;
                    } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                        return false;
                    } else {
                        linkSender.attr("href", "mailto:" + senderLocal);
                        linkSender.text(senderLocal);
                        btnRelease.attr("href", unholdURL);
                        btnBlock.attr("href", blockURL);
                        btnUnsubscribe.attr("href", unsubscribeURL);
                        templateHTML = templateHTML.normalise();
                        
                        MimeMessage message = Core.newMessage(true);
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(replyTo);
                        message.setSubject(subjectLocal + " #" + Long.toString(time, 32));
                        // Build warning part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                        htmlPart.setDisposition(MimeBodyPart.INLINE);
                        // Build logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        // Join all parts.
                        MimeMultipart contentRelated = new MimeMultipart("related");
                        contentRelated.addBodyPart(htmlPart);
                        contentRelated.addBodyPart(logoPart);
                        MimeBodyPart contentPart = new MimeBodyPart();
                        contentPart.setContent(contentRelated);
                        MimeMultipart contentMixed = new MimeMultipart("mixed");
                        contentMixed.addBodyPart(contentPart);
                        // Build hold part.
                        if (forwardMessage.getSize() == 0) {
                            forwardMessage.setContent("Body unavailable.", "text/plain");
                        }
                        forwardMessage.saveChanges();
                        MimeBodyPart forwardPart = new MimeBodyPart();
                        forwardPart.setContent(forwardMessage, "message/rfc822");
                        forwardPart.setDisposition(MimeBodyPart.INLINE);
//                        forwardPart.setFileName(Long.toString(time, 32) + ".eml");
                        contentMixed.addBodyPart(forwardPart);
                        // Set multiplart contentRelated.
                        message.setContent(contentMixed);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
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
                } catch (SocketTimeoutException ex) {
                    return false;
                } catch (SMTPAddressFailedException afex) {
                    if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ")) {
                        this.CHANGED.acquire();
                        this.inexistent = true;
                        this.STORED = false;
                        User.CHANGED = true;
                        this.CHANGED.release(true);
                    }
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
        
        private boolean adviseSenderHOLD(long time) {
            String mailFrom;
            String recipientLocal;
            if (senderAdvised) {
                return true;
            } else if (inexistent) {
                return false;
            } else if (recipientAdvised) {
                return false;
            } else if ((mailFrom = getReplyToValid()) == null) {
                return false;
            } else if ((recipientLocal = getRecipient()) == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else if (Trap.containsAnything(User.this, mailFrom)) {
                return false;
            } else if (NoReply.contains(mailFrom, false)) {
                return false;
            } else if (NoReply.isUnsubscribed(recipientLocal) && NoReply.isUnsubscribed(getUserEmail())) {
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
                    Locale locale = getBodyLocale();
                    InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                    String holdingURL;
                    String unsubscribeURL;
                    Document templateHTML;
                    File logoFile;
                    String subjectLocal;
                    Element linkRecipient;
                    Element btnRelease;
                    Element btnUnsubscribe;
                    if ((holdingURL = Core.getHoldingURL(User.this, time)) == null) {
                        return false;
                    } else if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                        return false;
                    } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                        return false;
                    } else if ((templateHTML = Core.getTemplateWarningRetentionSender(User.this, locale)) == null) {
                        return false;
                    } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                        return false;
                    } else if ((linkRecipient = templateHTML.getElementById("recipient")) == null) {
                        return false;
                    } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                        return false;
                    } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                        return false;
                    } else {
                        linkRecipient.attr("href", "mailto:" + recipientLocal);
                        linkRecipient.text(recipientLocal);
                        btnRelease.attr("href", holdingURL);
                        btnUnsubscribe.attr("href", unsubscribeURL);
                        templateHTML = templateHTML.normalise();
                        
                        MimeMessage message = Core.newMessage(false);
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setSubject(subjectLocal + " #" + Long.toString(time, 32));
                        // Reply to original message ID.
                        String messageidLocal = getMessageID();
                        if (messageidLocal != null) {
                            message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                        }
                        // Build warning part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                        htmlPart.setDisposition(MimeBodyPart.INLINE);
                        // Build logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        // Join all parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart contentRelated.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                            Defer.end(Core.getAdminEmail() + ">" + mailFrom);
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
                } catch (NameNotFoundException ex) {
                    blockForAdmin(time);
                    return false;
                } catch (ServiceUnavailableException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (CommunicationException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (MailConnectException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SocketTimeoutException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SocketConnectException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SocketException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SMTPAddressFailedException afex) {
                    String message = afex.getMessage().toLowerCase();
                    if (afex.getReturnCode() / 100 == 4) {
                        if (!Defer.defer(Core.getAdminEmail() + ">" + mailFrom, Core.getDeferTimeRED())) {
                            NoReply.addSafe(mailFrom);
                        }
                    } else if (afex.getReturnCode() == 541 || message.contains(" 5.4.1 ")) {
                        NoReply.addSafe(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("mailbox not found")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("unavailable")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("no such user")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("address rejected")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("unrouteable address")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("currently available")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("relay not permitted")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("invalide recipients")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 553 && message.contains("allowed rcpthosts")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 551 || message.contains(" 5.1.1 ")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getMessage().contains(" 5.7.1 ")) {
                        NoReply.addSafe(mailFrom);
                    }
                    return false;
                } catch (SendFailedException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (MessagingException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (NullPointerException ex) {
                    Server.logError("adviseSenderHOLD " + time);
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        public boolean adviseSenderBLOCK(long time) {
            String mailFrom;
            String recipientLocal;
            String unblockURL;
            if (senderAdvised) {
                return true;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isInexistent()) {
                return false;
            } else if (isBanned()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
                return false;
            } else if ((mailFrom = getReplyToValid()) == null) {
                return false;
            } else if (mailFrom.contains("+")) {
                return false;
            } else if ((recipientLocal = getRecipient()) == null) {
                return false;
            } else if (Core.isAdminEmail(recipientLocal)) {
                return false;
            } else if (Core.isAbuseEmail(recipientLocal)) {
                return false;
            } else if (hasMalware()) {
                return false;
            } else if (hasExecutableBlocked()) {
                return false;
            } else if (hasPhishingBlocked()) {
                return false;
            } else if (isBlockedForRecipient()) {
                return false;
            } else if (!Domain.isRootDomain(mailFrom)) {
                return false;
            } else if (NoReply.contains(mailFrom, true)) {
                return false;
            } else if (NoReply.isUnsubscribed(recipientLocal) && NoReply.isUnsubscribed(getUserEmail())) {
                return false;
            } else if ((unblockURL = getUnblockURLSafe()) == null) {
                return false;
             } else {
                try {
                    Locale locale = getBodyLocale();
                    InternetAddress[] recipients = InternetAddress.parse(mailFrom);
                    String unsubscribeURL;
                    Document templateHTML;
                    File logoFile;
                    String subjectLocal;
                    Element linkRecipient;
                    Element btnRelease;
                    Element btnUnsubscribe;
                    if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                        return false;
                    } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                        return false;
                    } else if ((templateHTML = Core.getTemplateWarningRejectionSender(User.this, locale)) == null) {
                        return false;
                    } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                        return false;
                    } else if ((linkRecipient = templateHTML.getElementById("recipient")) == null) {
                        return false;
                    } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                        return false;
                    } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                        return false;
                    } else {
                        linkRecipient.attr("href", "mailto:" + recipientLocal);
                        linkRecipient.text(recipientLocal);
                        btnRelease.attr("href", unblockURL);
                        btnUnsubscribe.attr("href", unsubscribeURL);
                        templateHTML = templateHTML.normalise();
                        
                        MimeMessage message = Core.newMessage(false);
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setSubject(subjectLocal + " <" + recipientLocal + ">");
                        // Reply to original message ID.
                        String messageidLocal = getMessageID();
                        if (messageidLocal != null) {
                            message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                        }
                        // Build warning part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                        htmlPart.setDisposition(MimeBodyPart.INLINE);
                        // Build logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        // Join all parts.
                        MimeMultipart content = new MimeMultipart("related");
                        content.addBodyPart(htmlPart);
                        content.addBodyPart(logoPart);
                        // Set multiplart contentRelated.
                        message.setContent(content);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                            this.CHANGED.acquire();
                            this.senderAdvised = true;
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            this.blockForRecipient(time, false);
                            User.storeDB(time, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (NameNotFoundException ex) {
                    blockForAdmin(time);
                    return false;
                } catch (SocketException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (ServiceUnavailableException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (CommunicationException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (MailConnectException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SocketTimeoutException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SocketConnectException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (SMTPAddressFailedException afex) {
                    String message = afex.getMessage().toLowerCase();
                    if (afex.getReturnCode() / 100 == 4) {
                        if (!Defer.defer(Core.getAdminEmail() + ">" + mailFrom, Core.getDeferTimeRED())) {
                            NoReply.addSafe(mailFrom);
                        }
                    } else if (afex.getReturnCode() / 10 == 55 && message.contains("relay not permitted")) {
                        blockForAdmin(time);
                    } else if (afex.getReturnCode() / 10 == 55 && message.contains("relay access denied")) {
                        blockForAdmin(time);
                    } else if (afex.getReturnCode() / 10 == 55 && message.contains("allowed rcpthosts")) {
                        blockForAdmin(time);
                    } else if (afex.getReturnCode() == 541 || message.contains(" 5.4.1 ")) {
                        NoReply.addSafe(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("mailbox not found")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("unavailable")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("no such user")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("address rejected")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("unrouteable address")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("unknown user")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("currently available")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 550 && message.contains("invalide recipients")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (afex.getReturnCode() == 551 || message.contains(" 5.1.1 ")) {
                        Trap.addInexistentForever(mailFrom);
                    } else if (message.contains(" 5.7.1 ")) {
                        NoReply.addSafe(mailFrom);
                    }
                    return false;
                } catch (SendFailedException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (MessagingException ex) {
                    NoReply.addSafe(mailFrom);
                    return false;
                } catch (NullPointerException ex) {
                    Server.logError("adviseSenderHOLD " + time);
                    return false;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return false;
                }
            }
        }
        
        private boolean adviseFromHIJACK(long time) {
            String from;
            if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else if (isBounceMessage()) {
                return false;
            } else if (!isSenderHijacked()) {
                return false;
            } else if (!Core.hasAdminEmail()) {
                return false;
            } else if ((from = getFrom()) == null) {
                return false;
            } else if (from.startsWith("mailer-daemon@")) {
                return false;
            } else if (NoReply.isUnsubscribed(from)) {
                return false;
            } else if (NoReply.contains(from, true)) {
                return false;
            } else if (!isSigned(from)) {
                return false;
            } else {
                return User.adviseFromHIJACK(time, from, getLocale());
            }
        }
        
        public boolean adviseRecipientHOLD(long timeKey) {
            String fromLocal = getFrom();
            String recipientEmail = getRecipient();
            String unholdURL;
            String blockURL;
            if (recipientAdvised) {
                return true;
            } else if (inexistent) {
                return false;
            } else if (senderAdvised) {
                return false;
            } else if (fromLocal == null) {
                return false;
            } else if (recipientEmail == null) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else if (isWhiteKey()) {
                return false;
            } else if (isBlockKey()) {
                return false;
            } else if (isWhiteKeyByAdmin()) {
                return false;
            } else if (isBlockKeyByAdmin()) {
                return false;
            } else if (isBanned()) {
                return false;
            } else if (isFromUnroutable()) {
                String domain = getHeaderFromHostname(false);
                Server.logDebug(timeKey, "FILTER FROM_UNROUTABLE;@" + domain);
                setFilter("FROM_UNROUTABLE;@" + getHeaderFromHostname(false));
                blockKey(timeKey, "NOTROUTEABLE");
                adviseMailerDaemonHOLDING(timeKey);
                return false;
            } else if (isSubjectEmpty()) {
                return false;
            } else if (isFromBlockedTLD()) {
                return false;
            } else if (isFromNotComplaince()) {
                return false;
            } else if (isSenderMailerDeamon()) {
                return false;
            } else if (isNotSigned(fromLocal, true)) {
                return false;
            } else if (NoReply.contains(recipientEmail, false)) {
                return false;
            } else if (hasMalware()) {
                return false;
            } else if (hasExecutable()) {
                return false;
            } else if (isSpoofingFrom()) {
                return false;
            } else if (isSpoofingFQDN()) {
                return false;
            } else if (isFromBlocked()) {
                return false;
            } else if (hasSignatureURL()) {
                return false;
            } else if (hasLinkBlocked()) {
                return false;
            } else if (isAnyLinkSuspect(true)) {
                return false;
            } else if (hasBitcoinInBody()) {
                return false;
            } else if (isSubjectBlockedREGEX()) {
                return false;
            } else if ((unholdURL = Core.getUnholdURL(User.this, timeKey)) == null) {
                return false;
            } else if ((blockURL = Core.getBlockURL(User.this, timeKey)) == null) {
                return false;
            } else {
                try {
                    Locale locale = User.this.getLocale();
                    InternetAddress[] recipients = InternetAddress.parse(recipientEmail);
                    MimeMessage forwardMessage;
                    Document templateHTML;
                    File logoFile;
                    String subjectLocal;
                    Element linkSender;
                    Element btnRelease;
                    Element btnBlock;
                    Element btnUnsubscribe;
                    String unsubscribeURL;
                    if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                        return false;
                    } else if ((forwardMessage = getMimeMessageBody()) == null) {
                        return false;
                    } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                        return false;
                    } else if ((templateHTML = Core.getTemplateWarningRetentionRecipient(User.this, locale)) == null) {
                        return false;
                    } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                        return false;
                    } else if ((linkSender = templateHTML.getElementById("sender")) == null) {
                        return false;
                    } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                        return false;
                    } else if ((btnBlock = templateHTML.getElementById("urlBlock")) == null) {
                        return false;
                    } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                        return false;
                    } else {
                        linkSender.attr("href", "mailto:" + fromLocal);
                        linkSender.text(fromLocal);
                        btnRelease.attr("href", unholdURL);
                        btnBlock.attr("href", blockURL);
                        btnUnsubscribe.attr("href", unsubscribeURL);
                        templateHTML = templateHTML.normalise();
                        
                        MimeMessage message = Core.newMessage(true);
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setReplyTo(User.this.getInternetAddresses());
                        message.setSubject(subjectLocal + " #" + Long.toString(timeKey, 32));
                        // Build warning part.
                        MimeBodyPart htmlPart = new MimeBodyPart();
                        htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                        htmlPart.setDisposition(MimeBodyPart.INLINE);
                        // Build logo part.
                        MimeBodyPart logoPart = new MimeBodyPart();
                        logoPart.attachFile(logoFile);
                        logoPart.setContentID("<logo>");
                        logoPart.addHeader("Content-Type", "image/png");
                        // Join all parts.
                        MimeMultipart contentRelated = new MimeMultipart("related");
                        contentRelated.addBodyPart(htmlPart);
                        contentRelated.addBodyPart(logoPart);
                        MimeBodyPart contentPart = new MimeBodyPart();
                        contentPart.setContent(contentRelated);
                        MimeMultipart contentMixed = new MimeMultipart("mixed");
                        contentMixed.addBodyPart(contentPart);
                        // Build hold part.
                        if (forwardMessage.getSize() == 0) {
                            forwardMessage.setContent("Body unavailable.", "text/plain");
                        }
                        forwardMessage.saveChanges();
                        MimeBodyPart forwardPart = new MimeBodyPart();
                        forwardPart.setContent(forwardMessage, "message/rfc822");
                        forwardPart.setDisposition(MimeBodyPart.INLINE);
//                        forwardPart.setFileName(Long.toString(timeKey, 32) + ".eml");
                        contentMixed.addBodyPart(forwardPart);
                        // Set multiplart contentRelated.
                        message.setContent(contentMixed);
                        message.saveChanges();
                        // Enviar mensagem.
                        if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                            this.CHANGED.acquire();
                            this.recipientAdvised = true;
                            if (User.this.isEmail(recipientEmail)) {
                                this.userAdvised = true;
                            }
                            this.STORED = false;
                            User.CHANGED = true;
                            this.CHANGED.release(true);
                            User.storeDB(timeKey, this);
                            return true;
                        } else {
                            return false;
                        }
                    }
                } catch (NameNotFoundException ex) {
                    return false;
                } catch (CommunicationException ex) {
                    return false;
                } catch (IOException ex) {
                    return false;
                } catch (ServiceUnavailableException ex) {
                    return false;
                } catch (MailConnectException ex) {
                    return false;
                } catch (SMTPAddressFailedException afex) {
                    if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ")) {
                        this.CHANGED.acquire();
                        this.inexistent = true;
                        this.STORED = false;
                        User.CHANGED = true;
                        this.CHANGED.release(true);
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
        
        public boolean adviseUserHOLD(long time) {
            if (userAdvised) {
                return true;
            } else {
                TreeMap<Long,Query> queryMap = new TreeMap<>();
                queryMap.put(time, this);
                return User.this.adviseUserHOLD(queryMap);
            }
        }
        
        public boolean adviseAdminHOLD(long time) {
            if (adminAdvised) {
                return true;
            } else {
                TreeMap<Long,Query> queryMap = new TreeMap<>();
                queryMap.put(time, this);
                return User.adviseAdminHOLD(queryMap);
            }
        }
        
        public boolean reportAbuse(long time, String email) throws Exception {
            if (abuseAdvised) {
                return true;
            } else if (email == null) {
                return false;
            } else if (!Core.hasAdminEmail()) {
                return false;
            } else if (!Core.hasOutputSMTP()) {
                return false;
            } else if (Trap.containsAnythingExact(email)) {
                Abuse.dropAllEmail(email);
                return false;
            } else if (NoReply.isUnsubscribed(email)) {
                return false;
            } else {
                MimeMessage original = getMimeMessageHeader();
                boolean sendUnblockURL = !isFilter(ABUSE_SUBMISSION, USER_SPAM, USER_PHISHING);
                MimeMessage message = newAbuseReportMessage(
                        time, email, original, sendUnblockURL
                );
                if (ServerSMTP.sendMessage(Locale.US, message, email, null)) {
                    setAbuseAdvised(email);
                    User.storeDB(time, this);
                    setSpam(time);
                    return true;
                } else {
                    return false;
                }
            }
        }
        
        public void setAbuseAdvised(String email) {
            this.CHANGED.acquire();
            this.abuseAdvised = true;
            this.abuseEmail = email;
            this.STORED = false;
            User.CHANGED = true;
            this.CHANGED.release(true);
        }
        
        public void setFilter(String filter) {
            this.CHANGED.acquire();
            this.filter = filter;
            this.STORED = false;
            User.CHANGED = true;
            this.CHANGED.release(true);
        }
        
        public MimeMessage newAbuseReportMessage(
                long time,
                String email,
                MimeMessage original,
                boolean sendUnblockURL
        ) throws Exception {
            String arrivalDate = Core.getEmailDate(getArrival());
            if (arrivalDate == null) {
                if (original != null) {
                    arrivalDate = Core.getEmailDate(original.getReceivedDate());
                }
                if (arrivalDate == null) {
                    arrivalDate = Core.getEmailDate(new Date(time));
                }
            }
            InternetAddress[] recipients = InternetAddress.parse(email);
            boolean removalRequest = isBlockKey() || isBlockedForRecipient() || isBlockSMTP();
            String unblockURL = !sendUnblockURL || isInexistent() || isBlockedForRecipient() ? null : getUnblockURL();
            MimeMessage message = Abuse.newAbuseReportMessage(
                    time,
                    recipients,
                    User.this.getEmail(),
                    getClient(),
                    getMalwareOrExecutable(),
                    getSender(),
                    getRecipient(),
                    arrivalDate,
                    getIP(),
                    getFQDN(),
                    getQualifierName(),
                    getMessageID(),
                    getLinkKeySetSimple(),
                    getFilterEnum(),
                    removalRequest,
                    unblockURL,
                    original
            );
            return message;
        }
        
        public String getQueueRelease32(long timeKey) {
            String ticket = "release";
            try {
                ticket += ' ' + getUserEmail();
                ticket = encrypt32(timeKey, ticket);
                ticket = ticket.replace("=", "");
                return ticket.toLowerCase();
            } catch (Exception ex) {
                Server.logError(new Exception("compress fail: " + ticket, ex));
                return null;
            }
        }
        
        public String getQueueRemove32(long timeKey) {
            String ticket = "remove";
            try {
                ticket += ' ' + getUserEmail();
                ticket = encrypt32(timeKey, ticket);
                ticket = ticket.replace("=", "");
                return ticket.toLowerCase();
            } catch (Exception ex) {
                Server.logError(new Exception("compress fail: " + ticket, ex));
                return null;
            }
        }
        
        public boolean adviseMailerDaemonHOLDING(long timeKey) {
            InternetAddress adminMail = Core.getAdminInternetAddress();
            String mailerClient = getClient();
            String queueMessageID = getQueueID();
            if (Core.isMyHostname(mailerClient)) {
                return Core.processDelivery(timeKey);
            } else if (adminMail == null) {
                return false;
            } else if (queueMessageID == null || queueMessageID.length() == 0) {
                return false;
            } else if (!Core.isDirectSMTP()) {
                return false;
            } else if (!Core.isRunning()) {
                return false;
            } else {
                try {
                    String command;
                    if (isWhiteKey()) {
                        command = "release";
                    } else if (isBanned()) {
                        command = "remove";
                    } else if (isBlockKey()) {
                        command = "remove";
                    } else if (isWhiteKeyByAdmin()) {
                        command = "release";
                    } else if (isBlockKeyByAdmin()) {
                        command = "remove";
                    } else if (isSenderMailerDeamon() && isRecipientHacked()) {
                        command = "release";
                    } else {
                        return false;
                    }
                    String messageidLocal = getMessageID();
                    InternetAddress sender;
                    InternetAddress[] recipients = new InternetAddress[1];
                    recipients[0] = new InternetAddress("mailer-daemon@" + mailerClient);
                    MimeMessage message = Core.newMessage(false);
                    message.addRecipients(Message.RecipientType.TO, recipients);
                    if (messageidLocal != null) {
                        message.addHeader("In-Reply-To", '<' + messageidLocal + '>');
                    }
                    if (command.equals("release")) {
                        String ticket = getQueueRelease32(timeKey);
                        sender = new InternetAddress(ticket + "@" + Core.getHostname());
                        message.setSubject(queueMessageID);
                        message.setContent(
                                "The message frozen in queue as " + queueMessageID + " "
                                        + "must be released by user order.",
                                "text/plain;charset=US-ASCII"
                        );
                    } else if (command.equals("remove")) {
                        String ticket = getQueueRemove32(timeKey);
                        sender = new InternetAddress(ticket + "@" + Core.getHostname());
                        message.setSubject(queueMessageID);
                        message.setContent(
                                "The message frozen in queue as " + queueMessageID + " "
                                        + "must be remove by user order.",
                                "text/plain;charset=US-ASCII"
                        );
                    } else {
                        return false;
                    }
                    message.saveChanges();
                    // Enviar mensagem.
                    Properties props = ServerSMTP.newProperties(mailerClient, 25, false);
                    if (ServerSMTP.sendMessage(props, message, sender, recipients)) {
                        TreeSet<Long> timeKeySet = getTimeKeySet();
                        timeKeySet.add(timeKey);
                        for (long timeKey2 : timeKeySet) {
                            Query query2 = getQuerySafe(timeKey2);
                            if (query2.isResult("HOLD") && query2.isQueueID(queueMessageID)) {
                                if (query2.isWhiteKey()) {
                                    query2.setResult("WHITE");
                                    query2.addBeneficial(timeKey);
                                } else if (query2.isBanned()) {
                                    query2.setResultFilter("BLOCK", "ORIGIN_BANNED;" + getBannedKey());
                                    query2.addHarmful(timeKey);
                                } else if (query2.isBlockKey()) {
                                    query2.setResult("BLOCK");
                                    query2.addUndesirable(timeKey);
                                } else if (query2.isWhiteKeyByAdmin()) {
                                    query2.whiteKey(timeKey);
                                    query2.setResultFilter("WHITE", "ORIGIN_WHITE_KEY_ADMIN");
                                    query2.addBeneficial(timeKey);
                                } else if (query2.isBlockKeyByAdmin()) {
                                    query2.blockKey(timeKey, "ORIGIN_BLOCK_KEY_ADMIN");
                                    query2.setResultFilter("BLOCK", "ORIGIN_BLOCK_KEY_ADMIN;" + getBlockKey());
                                    query2.addUndesirable(timeKey);
                                } else if (command.equals("release")) {
                                    query2.setResult("ACCEPT");
                                    query2.addAcceptable();
                                } else if (command.equals("remove")) {
                                    query2.setResult("REJECT");
                                    query2.addUnacceptable();
                                }
                                User.storeDB2(timeKey2, query2);
                            }
                        }
                        return true;
                    } else {
                        return false;
                    }
                } catch (MailConnectException ex) {
                    return false;
                } catch (SocketConnectException ex) {
                    return false;
                } catch (SocketTimeoutException ex) {
                    return false;
                } catch (SMTPSendFailedException ex) {
                    if (ex.getReturnCode() / 100 == 5) {
                        String message = ex.getMessage();
                        boolean inexistent = message.matches("(?s).*\\b5\\.1\\.1\\b.*");
                        if (inexistent) {
                            Recipient.set(
                                    getUserEmail(), getRecipient(),
                                    INEXISTENT
                            );
                        }
                        // Message ID not found.
                        if (isResult("HOLD")) {
                            String reason;
                            if (isWhiteKey()) {
                                if (inexistent) {
                                    setResult("INEXISTENT");
                                    addUnacceptable();
                                } else {
                                    setResult("WHITE");
                                    addBeneficial(timeKey);
                                }
                            } else if ((reason = getWhiteReason()) != null) {
                                if (inexistent) {
                                    setResult("INEXISTENT");
                                    addUnacceptable();
                                } else {
                                    whiteKey(timeKey);
                                    setResultFilter("WHITE", "ORIGIN_WHITELISTED");
                                    addBeneficial(timeKey);
                                }
                            } else if (isBanned()) {
                                setResultFilter("BLOCK", "ORIGIN_BANNED;" + getBannedKey());
                                addHarmful(timeKey);
                            } else if (isBlockKey()) {
                                setResult("BLOCK");
                                addUndesirable(timeKey);
                            } else if (inexistent) {
                                setResult("INEXISTENT");
                                addUnacceptable();
                            } else if (isWhiteKeyByAdmin()) {
                                whiteKey(timeKey);
                                setResultFilter("WHITE", "ORIGIN_WHITE_KEY_ADMIN");
                                addBeneficial(timeKey);
                            } else if (isBlockKeyByAdmin()) {
                                blockKey(timeKey, "ORIGIN_BLOCK_KEY_ADMIN");
                                setResultFilter("BLOCK", "ORIGIN_BLOCK_KEY_ADMIN;" + getBlockKey());
                                addUndesirable(timeKey);
                            } else if (message.matches("(?s).*\\b5\\.6\\.6\\b.*")) {
                                setResult("FLAG");
                                addUnacceptable();
                            }
                            User.storeDB2(timeKey, this);
                        }
                        return true;
                    } else {
                        return false;
                    }
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
                    + (getTrueSender() == null ? "" : " " + getTrueSender())
                    + " " + getQualifierName() + " > " + recipient + " = " + result;
        }

        public SimpleImmutableEntry<Filter, String> processFilter(Object object) {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
    }
    
    public boolean adviseRecipientBLOCK(
            String sender,
            String recipient,
            String unblockURL
    ) {
        if (sender == null) {
            return false;
        } else if (recipient == null) {
            return false;
        } else if (unblockURL == null) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!Core.isRunning()) {
            return false;
        } else {
            try {
                Locale locale = User.this.getLocale();
                InternetAddress[] recipients;
                InternetAddress[] replyTo;
                String userEmail = getEmail();
                if (NoReply.isUnsubscribed(recipient)) {
                    recipients = InternetAddress.parse(userEmail);
                    replyTo = InternetAddress.parse(sender);
                } else if (Trap.containsAnything(userEmail, recipient)) {
                    recipients = InternetAddress.parse(userEmail);
                    replyTo = InternetAddress.parse(sender);
                } else {
                    recipients = InternetAddress.parse(recipient);
                    replyTo = User.this.getInternetAddresses();
                }
                String unsubscribeURL;
                Document templateHTML;
                File logoFile;
                String subjectLocal;
                Element linkSender;
                Element btnRelease;
                Element btnUnsubscribe;
                if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                    return false;
                } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                    return false;
                } else if ((templateHTML = Core.getTemplateWarningRejectionRecipient(User.this, locale)) == null) {
                    return false;
                } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                    return false;
                } else if ((linkSender = templateHTML.getElementById("sender")) == null) {
                    return false;
                } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                    return false;
                } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                    return false;
                } else {
                    linkSender.attr("href", "mailto:" + sender);
                    linkSender.text(sender);
                    btnRelease.attr("href", unblockURL);
                    btnUnsubscribe.attr("href", unsubscribeURL);
                    templateHTML = templateHTML.normalise();

                    MimeMessage message = Core.newMessage(true);
                    message.addRecipients(Message.RecipientType.TO, recipients);
                    message.setReplyTo(replyTo);
                    message.setSubject(subjectLocal + " <" + sender + ">");
                    // Build warning part.
                    MimeBodyPart htmlPart = new MimeBodyPart();
                    htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                    htmlPart.setDisposition(MimeBodyPart.INLINE);
                    // Build logo part.
                    MimeBodyPart logoPart = new MimeBodyPart();
                    logoPart.attachFile(logoFile);
                    logoPart.setContentID("<logo>");
                    logoPart.addHeader("Content-Type", "image/png");
                    // Join all parts.
                    MimeMultipart content = new MimeMultipart("related");
                    content.addBodyPart(htmlPart);
                    content.addBodyPart(logoPart);
                    // Set multiplart contentRelated.
                    message.setContent(content);
                    message.saveChanges();
                    // Enviar mensagem.
                    return ServerSMTP.sendMessage(locale, message, recipients, null);
                }
            } catch (NameNotFoundException ex) {
                return false;
            } catch (CommunicationException ex) {
                return false;
            } catch (SocketConnectException ex) {
                return false;
            } catch (SocketTimeoutException ex) {
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
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!Core.isRunning()) {
            return false;
        } else if (NoReply.contains(adminEmail, true)) {
            return false;
        } else {
            long timeKey = queryMap.lastKey();
            try {
                Query lastQuery = queryMap.get(timeKey);
                String trueSender = lastQuery.getTrueSender();
                String senderDomain = Domain.extractHost(trueSender, false);
                String senderTLD = Domain.extractTLD(senderDomain, true);
                String userEmail = lastQuery.getUserEmail();
                String blockKey = lastQuery.getBlockKey();
                String unholdURL = Core.getUnholdAdminURL(timeKey, userEmail, blockKey);
                String blockURL = Core.getBlockURL(timeKey, adminEmail);
                String banURL = Core.getBanURL(timeKey, adminEmail);
                String banSubjectURL = Core.getBanBySubjectURL(timeKey, adminEmail);
                if (unholdURL == null) {
                    return false;
                } else if (blockURL == null) {
                    return false;
                } else if (banURL == null) {
                    return false;
                } else if (banSubjectURL == null) {
                    return false;
                } else if (Block.containsExact(adminEmail, senderTLD)) {
                    Server.logDebug(timeKey, "FILTER TLD_BLOCKED;" + senderTLD);
                    lastQuery.setFilter("TLD_BLOCKED;" + senderTLD);
                    lastQuery.banOrBlockForAdmin(timeKey, "TLD_BLOCKED");
                    lastQuery.adviseMailerDaemonHOLDING(timeKey);
                    return false;
                } else {
                    User user = User.get(adminEmail);
                    Locale locale = user == null ? Core.getDefaultLocale(adminEmail) : user.getLocale();
                    
                    String subject;
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        subject = queryMap.size() + " retenções agrupadas por '" + blockKey + "'";
                    } else {
                        subject = queryMap.size() + " retentions grouped by '" + blockKey + "'";
                    }
                    TreeSet<String> userSet = new TreeSet<>();
                    TreeSet<String> subjectSet = new TreeSet<>();
                    TreeSet<String> subjectWordSet = new TreeSet<>();
                    TreeSet<String> senderSet = new TreeSet<>();
                    TreeSet<String> fromSet = new TreeSet<>();
                    TreeSet<String> recipientSet = new TreeSet<>();
                    TreeSet<String> bodySet = new TreeSet<>();
                    TreeSet<String> linkSet = new TreeSet<>();
                    TreeSet<String> executableSet = new TreeSet<>();
                    TreeSet<String> ipSet = new TreeSet<>();
                    TreeSet<String> abuseSet = new TreeSet<>();
                    LinkedList<MimeMessage> messageList = new LinkedList<>();
                    for (long time : queryMap.keySet()) {
                        Query query = queryMap.get(time);
                        userEmail = query.getUserEmail();
                        String sender = query.getSender();
                        Qualifier qualifier = query.getQualifier();
                        TreeSet<String> signerSet = query.getSignerSet();
                        String from = query.getFrom();
                        String recipient = query.getRecipient();
                        String subject2 = query.getSubject(256);
                        String subject3 = query.getSubjectWordSet(2);
                        String textBody = query.getTextPlainBody(256);
                        String abuse = query.getAbuseOrigin();
                        if (userEmail != null) {
                            Flag flag = Recipient.getFlag(userEmail);
                            userSet.add("[" + flag + "] " + userEmail);
                        }
                        if (sender != null) {
                            Flag flag = query.getFlagSPF(sender, qualifier);
                            senderSet.add("[" + flag + "] " + sender);
                        }
                        if (from != null) {
                            Flag flag = query.getFlagDKIM(from, signerSet);
                            fromSet.add("[" + flag + "] " + from);
                        }
                        if (recipient != null) {
                            Flag flag = query.getRecipientFlag();
                            recipientSet.add("[" + flag + "] " + recipient);
                        }
                        if (subject2 != null) {
                            Flag flag = query.getSubjectFlag();
                            subjectSet.add("[" + flag + "] " + subject2);
                        }
                        Flag flag = query.getSubjectFlag();
                        if (flag == BENEFICIAL) {
                            banSubjectURL = null;
                        } else if (flag == DESIRABLE) {
                            banSubjectURL = null;
                        } else if (query.isBounceMessage()) {
                            banSubjectURL = null;
                        } else if (query.isSenderMailerDeamon()) {
                            banSubjectURL = null;
                        } else if (subject3 != null) {
                            subjectWordSet.add(subject3);
                        }
                        if (textBody != null) {
                            bodySet.add(textBody);
                        }
                        if (abuse == null) {
                            ipSet.add(query.getIP());
                        } else {
                            flag = Abuse.getFlag(abuse);
                            if (NoReply.isSubscribed(abuse)) {
                                abuseSet.add("[" + flag + "] " + abuse);
                            } else {
                                abuseSet.add("[" + flag + "] <strike>" + abuse + "</strike>");
                            }
                            
                        }
                        for (String link : query.getLinkKeySetSimple()) {
                            flag = URI.getFlag(link);
                            linkSet.add("[" + flag + "] " + link);
                        }
                        MimeMessage message = query.getMimeMessageHeader();
                        if (message != null) {
                            messageList.add(message);
                        }
                        executableSet.addAll(query.getExecutableSetNN());
                    }
                    while (userSet.size() > 32) {
                        userSet.pollLast();
                    }
                    while (subjectSet.size() > 32) {
                        subjectSet.pollLast();
                    }
                    while (subjectWordSet.size() > 32) {
                        subjectWordSet.pollLast();
                    }
                    while (senderSet.size() > 32) {
                        senderSet.pollLast();
                    }
                    while (fromSet.size() > 32) {
                        fromSet.pollLast();
                    }
                    while (recipientSet.size() > 32) {
                        recipientSet.pollLast();
                    }
                    while (bodySet.size() > 32) {
                        bodySet.pollLast();
                    }
                    while (linkSet.size() > 32) {
                        linkSet.pollLast();
                    }
                    while (executableSet.size() > 32) {
                        executableSet.pollLast();
                    }
                    while (ipSet.size() > 32) {
                        ipSet.pollLast();
                    }
                    while (abuseSet.size() > 32) {
                        abuseSet.pollLast();
                    }

                    InternetAddress[] recipients = {Core.getAdminInternetAddress()};
                    MimeMessage message = Core.newMessage(true);
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
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        ServerHTTP.buildMessage(builder, "Aviso de retenção de mensagens");
                        ServerHTTP.buildText(builder, "Algumas mensagens foram retidas com os assuntos:");
                    } else {
                        ServerHTTP.buildMessage(builder, "Message retention notice");
                        ServerHTTP.buildText(builder, "Some messages were retained with the subjects:");
                    }
                    builder.append("    <ul>\n");
                    for (String subjectItem : subjectSet) {
                        builder.append("    <li>");
                        builder.append(StringEscapeUtils.escapeHtml4(subjectItem));
                        builder.append("</li>\n");
                    }
                    builder.append("    </ul>\n");
                    if (!senderSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "As mensagens foram enviadas pelos seguintes remetentes de envelope:");
                        } else {
                            ServerHTTP.buildText(builder, "Messages have been sent from the following envelope senders:");
                        }
                        builder.append("    <ul>\n");
                        for (String sender : senderSet) {
                            builder.append("    <li>");
                            builder.append(sender);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (!fromSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "As mensagens foram enviadas pelos seguintes remetentes de cabeçalho:");
                        } else {
                            ServerHTTP.buildText(builder, "Messages have been sent from the following header senders:");
                        }
                        builder.append("    <ul>\n");
                        for (String from : fromSet) {
                            builder.append("    <li>");
                            builder.append(from);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        ServerHTTP.buildText(builder, "Os destinatários das mensagens são:");
                    } else {
                        ServerHTTP.buildText(builder, "The recipients of the messages are:");
                    }
                    builder.append("    <ul>\n");
                    for (String recipient : recipientSet) {
                        builder.append("    <li>");
                        builder.append(recipient);
                        builder.append("</li>\n");
                    }
                    builder.append("    </ul>\n");
                    if (!executableSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "<b>Atenção! As seguintes assinaturas de executáveis foram encontradas no corpo das mensagens:</b>");
                        } else {
                            ServerHTTP.buildText(builder, "<b>Attention! The following executable signatures were found in the message body:</b>");
                        }
                        builder.append("    <ul>\n");
                        for (String signature : executableSet) {
                            builder.append("    <li>");
                            builder.append(signature);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (!bodySet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Os seguintes textos foram encontrados nos corpos das mensagens:");
                        } else {
                            ServerHTTP.buildText(builder, "The following texts were found in the message bodies:");
                        }
                        builder.append("    <ul>\n");
                        for (String text : bodySet) {
                            builder.append("    <li>");
                            builder.append(StringEscapeUtils.escapeHtml4(text));
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (!linkSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Os seguintes links foram encontrados no corpo das mensagens:");
                        } else {
                            ServerHTTP.buildText(builder, "The following links have been found in the message body:");
                        }
                        builder.append("    <ul>\n");
                        for (String link : linkSet) {
                            builder.append("    <li>");
                            builder.append(link);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (!userSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Estas mensagens foram processadas pelos seguintes usuários:");
                        } else {
                            ServerHTTP.buildText(builder, "These messages were processed by the following users:");
                        }
                        builder.append("    <ul>\n");
                        for (String email : userSet) {
                            builder.append("    <li>");
                            builder.append(email);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (!ipSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Os seguintes IPs não tem registro de FBL:");
                        } else {
                            ServerHTTP.buildText(builder, "The following IPs have no FBL registration:");
                        }
                        builder.append("    <ul>\n");
                        for (String ip : ipSet) {
                            builder.append("    <li>");
                            builder.append(ip);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    } else if (!abuseSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Equipes abuse encontrados:");
                        } else {
                            ServerHTTP.buildText(builder, "Abuse teams found:");
                        }
                        builder.append("    <ul>\n");
                        for (String abuse : abuseSet) {
                            builder.append("    <li>");
                            builder.append(abuse);
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                    }
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        ServerHTTP.buildText(builder, "Se você considera essas mensagens legítimas, acessar esta URL para solicitar a liberação:");
                        ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                        ServerHTTP.buildText(builder, "Se você considera essas mensagens SPAM, acessar esta URL para bloquear o remetente:");
                        ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                        ServerHTTP.buildText(builder, "Se você considera essas mensagens uma ameaça, acessar esta URL para banir o remetente:");
                        ServerHTTP.buildText(builder, "<a href=\"" + banURL + "\">" + banURL + "</a>");
                    } else {
                        ServerHTTP.buildText(builder, "If you consider these messages legitimate, access this URL to request the release:");
                        ServerHTTP.buildText(builder, "<a href=\"" + unholdURL + "\">" + unholdURL + "</a>");
                        ServerHTTP.buildText(builder, "If you consider these SPAM messages, access this URL to block the sender:");
                        ServerHTTP.buildText(builder, "<a href=\"" + blockURL + "\">" + blockURL + "</a>");
                        ServerHTTP.buildText(builder, "If you consider these threat messages, access this URL to ban the sender:");
                        ServerHTTP.buildText(builder, "<a href=\"" + banURL + "\">" + banURL + "</a>");
                    }
                    if (banSubjectURL != null && !subjectWordSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            ServerHTTP.buildText(builder, "Se você considera essas mensagens uma ameaça, acessar esta URL para banir o assunto:");
                        } else {
                            ServerHTTP.buildText(builder, "If you consider these threat messages, access this URL to ban the subject:");
                        }
                        builder.append("    <ul>\n");
                        for (String subjectItem : subjectWordSet) {
                            builder.append("    <li>");
                            builder.append(StringEscapeUtils.escapeHtml4(subjectItem));
                            builder.append("</li>\n");
                        }
                        builder.append("    </ul>\n");
                        ServerHTTP.buildText(builder, "<a href=\"" + banSubjectURL + "\">" + banSubjectURL + "</a>");
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
                    File logoFile = Core.getLogoFile(null);
                    logoPart.attachFile(logoFile);
                    logoPart.setContentID("<logo>");
                    logoPart.addHeader("Content-Type", "image/png");
                    logoPart.setDisposition(MimeBodyPart.INLINE);
                    // Join all parts.
                    MimeMultipart contentRelated = new MimeMultipart("related");
                    contentRelated.addBodyPart(htmlPart);
                    contentRelated.addBodyPart(logoPart);
                    MimeBodyPart contentPart = new MimeBodyPart();
                    contentPart.setContent(contentRelated);
                    MimeMultipart contentMixed = new MimeMultipart("mixed");
                    contentMixed.addBodyPart(contentPart);
                    // Set multiplart contentRelated.
                    message.setContent(contentMixed);
                    message.saveChanges();
                    // Enviar mensagem.
                    if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                        for (long time : queryMap.keySet()) {
                            Query query = queryMap.get(time);
                            query.CHANGED.acquire();
                            query.adminAdvised = true;
                            query.STORED = false;
                            User.CHANGED = true;
                            query.CHANGED.release(true);
                            User.storeDB(time, query);
                        }
                        return true;
                    } else {
                        return false;
                    }
                }
            } catch (NameNotFoundException ex) {
                return false;
            } catch (CommunicationException ex) {
                return false;
            } catch (MailConnectException ex) {
                return false;
            } catch (SocketConnectException ex) {
                return false;
            } catch (SocketTimeoutException ex) {
                return false;
            } catch (SendFailedException ex) {
                return false;
            } catch (MessagingException ex) {
                return false;
            } catch (NullPointerException ex) {
                Server.logError("adviseAdminHOLD " + timeKey);
                Server.logError(ex);
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    private MimeMessage[] getMimeMessageHeader(
            TreeMap<Long,Query> queryMap
    ) {
        if (queryMap == null) {
            return null;
        } else if (queryMap.isEmpty()) {
            return null;
        } else {
            LinkedList<MimeMessage> messageList = new LinkedList<>();
            for (long time : queryMap.keySet()) {
                try {
                    Query query = queryMap.get(time);
                    MimeMessage message = query.getMimeMessageHeader();
                    if (message != null) {
                        if (message.getSize() > 0) {
                            ServerSMTP.removeDangerousObjects(message);
                        }
                        messageList.add(message);
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            if (messageList.isEmpty()) {
                return null;
            } else {
                int size = messageList.size();
                MimeMessage[] messageArray = new MimeMessage[size];
                for (int index = 0; index < size; index++) {
                    messageArray[index] = messageList.poll();
                }
                return messageArray;
            }
        }
    }
    
    private boolean hasExecutableNotIgnored(
            TreeMap<Long,Query> queryMap
    ) {
        if (queryMap == null) {
            return false;
        } else if (queryMap.isEmpty()) {
            return false;
        } else {
            for (long time : queryMap.keySet()) {
                Query query = queryMap.get(time);
                if (query.hasExecutableNotIgnored()) {
                    return true;
                }
            }
            return false;
        }
    }
    
    private boolean adviseUserHOLD(TreeMap<Long,Query> queryMap) {
        long timeKey;
        Query query;
        String fromLocal;
        String unholdURL;
        String blockURL;
        String banURL;
        String userEmail = getEmail();
        if (userEmail == null) {
            return false;
        } else if (queryMap == null) {
            return false;
        } else if (queryMap.isEmpty()) {
            return false;
        } else if ((timeKey = queryMap.lastKey()) == 0) {
            return false;
        } else if ((query = queryMap.get(timeKey)) == null) {
            return false;
        } else if ((fromLocal = query.getSenderSimplified(false, false)) == null) {
            return false;
        } else if (NoReply.containsTLD(fromLocal)) {
            return false;
        } else if (NoReply.contains(userEmail, true)) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!Core.isRunning()) {
            return false;
        } else if ((unholdURL = Core.getUnholdURL(timeKey, userEmail)) == null) {
            return false;
        } else if ((blockURL = Core.getBlockURL(timeKey, userEmail)) == null) {
            return false;
        } else if ((banURL = Core.getBanURL(timeKey, userEmail)) == null) {
            return false;
        } else {
            try {
                Locale locale = User.this.getLocale();
                InternetAddress[] recipients = InternetAddress.parse(userEmail);
                MimeMessage[] forwardMessageArray;
                Document templateHTML;
                File logoFile;
                String subjectLocal;
                Element linkSender;
                Element executableWarning;
                Element unsignedWarning;
                Element advisedWarning;
                Element btnRelease;
                Element btnBlock;
                Element btnBan;
                Element btnUnsubscribe;
                String unsubscribeURL;
                if ((unsubscribeURL = Core.getListUnsubscribeURL(locale, recipients[0])) == null) {
                    return false;
                } else if ((forwardMessageArray = getMimeMessageHeader(queryMap)) == null) {
                    return false;
                } else if ((logoFile = Core.getLogoFile(User.this)) == null) {
                    return false;
                } else if ((templateHTML = Core.getTemplateWarningRetentionUser(User.this, locale)) == null) {
                    return false;
                } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                    return false;
                } else if ((linkSender = templateHTML.getElementById("sender")) == null) {
                    return false;
                } else if ((executableWarning = templateHTML.getElementById("executable")) == null) {
                    return false;
                } else if ((unsignedWarning = templateHTML.getElementById("unsigned")) == null) {
                    return false;
                } else if ((advisedWarning = templateHTML.getElementById("advised")) == null) {
                    return false;
                } else if ((btnRelease = templateHTML.getElementById("urlRelease")) == null) {
                    return false;
                } else if ((btnBlock = templateHTML.getElementById("urlBlock")) == null) {
                    return false;
                } else if ((btnBan = templateHTML.getElementById("urlBan")) == null) {
                    return false;
                } else if ((btnUnsubscribe = templateHTML.getElementById("urlUnsubscribe")) == null) {
                    return false;
                } else {
                    TreeSet<String> senderSet = new TreeSet<>();
                    for (long timeKey2 : queryMap.keySet()) {
                        Query query2 = queryMap.get(timeKey2);
                        String sender2 = query2.getTrueSender();
                        if (sender2 != null && sender2.endsWith(fromLocal)) {
                            senderSet.add(sender2);
                        }
                    }
                    if (senderSet.size() == 1) {
                        fromLocal = senderSet.first();
                    }
                    linkSender.attr("href", "mailto:" + fromLocal);
                    linkSender.text(fromLocal);
                    if (query.isSigned(fromLocal, true)) {
                        unsignedWarning.remove();
                    }
                    if (!hasExecutableNotIgnored(queryMap)) {
                        executableWarning.remove();
                    }
                    for (long time2 : queryMap.keySet()) {
                        Query query2 = queryMap.get(time2);
                        if (!query2.isRecipientAdvised()) {
                            advisedWarning.remove();
                            break;
                        }
                    }
                    btnRelease.attr("href", unholdURL);
                    btnBlock.attr("href", blockURL);
                    btnBan.attr("href", banURL);
                    btnUnsubscribe.attr("href", unsubscribeURL);
                    templateHTML = templateHTML.normalise();
                    MimeMessage message = Core.newMessage(true);
                    message.addRecipients(Message.RecipientType.TO, recipients);
                    message.setSubject(subjectLocal + " #" + Long.toString(timeKey, 32));
                    // Build warning part.
                    MimeBodyPart htmlPart = new MimeBodyPart();
                    htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                    htmlPart.setDisposition(MimeBodyPart.INLINE);
                    // Build logo part.
                    MimeBodyPart logoPart = new MimeBodyPart();
                    logoPart.attachFile(logoFile);
                    logoPart.setContentID("<logo>");
                    logoPart.addHeader("Content-Type", "image/png");
                    // Join all parts.
                    MimeMultipart contentRelated = new MimeMultipart("related");
                    contentRelated.addBodyPart(htmlPart);
                    contentRelated.addBodyPart(logoPart);
                    MimeBodyPart contentPart = new MimeBodyPart();
                    contentPart.setContent(contentRelated);
                    MimeMultipart contentMixed = new MimeMultipart("mixed");
                    contentMixed.addBodyPart(contentPart);
                    // Build attachment parts.
                    int attachmentCount = 0;
                    int size = htmlPart.getSize() + logoPart.getSize();
                    for (MimeMessage forwardMessage : forwardMessageArray) {
                        try {
                            if (forwardMessage.getSize() == 0) {
                                forwardMessage.setContent("Body unavailable.", "text/plain");
                            }
                            forwardMessage.saveChanges();
                            MimeBodyPart forwardPart = new MimeBodyPart();
                            forwardPart.setContent(forwardMessage, "message/rfc822");
                            forwardPart.setDisposition(MimeBodyPart.INLINE);
//                            forwardPart.setFileName(Long.toString(timeKey, 32) + ".eml");
                            contentMixed.addBodyPart(forwardPart);
                            attachmentCount++;
                            if ((size += forwardPart.getSize()) > ServerSMTP.SIZE) {
                                break;
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    // Set multiplart contentRelated.
                    message.setContent(contentMixed);
                    message.saveChanges();
                    // Enviar mensagem.
                    if (attachmentCount == 0) {
                        return false;
                    } else if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                        for (long time : queryMap.keySet()) {
                            query = queryMap.get(time);
                            query.CHANGED.acquire();
                            query.userAdvised = true;
                            query.STORED = false;
                            User.CHANGED = true;
                            query.CHANGED.release(true);
                            User.storeDB(time, query);
                        }
                        return true;
                    } else {
                        return false;
                    }
                }
            } catch (NameNotFoundException ex) {
                NoReply.addSafe(userEmail);
                return false;
            } catch (CommunicationException | MailConnectException | SocketConnectException | SocketTimeoutException ex) {
                if (!Defer.defer(">" + userEmail, Core.getDeferTimeHOLD())) {
                    NoReply.addSafe(userEmail);
                }
                return false;
            } catch (SMTPAddressFailedException ex) {
                if (ex.getReturnCode() == 551) {
                    NoReply.addSafe(userEmail);
                } else if (ex.getMessage().matches("(?s).*\\b5\\.1\\.1\\b.*")) {
                    NoReply.addSafe(userEmail);
                } else {
                    Server.logError(ex);
                }
                return false;
//            } catch (IOException ex) {
//                return false;
//            } catch (SendFailedException ex) {
//                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static String simplifySender(String sender) {
        if (sender == null) {
            return null;
        } else {
            int index = sender.indexOf('@');
            if (index > 0) {
                String domain = sender.substring(index);
                if (Provider.containsExact(domain)) {
                    return sender;
                } else {
                    return domain;
                }
            } else {
                return null;
            }
        }
    }
    
    private final static TreeMap<Long,History> HISTORY_MAP = new TreeMap<>();
    
    private synchronized static TreeSet<Long> historyHeadKeySet(long toKey) {
        TreeSet<Long> resultSet = new TreeSet<>();
        SortedMap<Long,History> headMap = HISTORY_MAP.headMap(toKey);
        resultSet.addAll(headMap.keySet());
        return resultSet;
    }
    
    private synchronized static History removeHistoryByDay(long dayKey) {
        return HISTORY_MAP.remove(dayKey);
    }
    
    public static void closeExpiredHistory() {
        if (Core.isRunning()) {
            long toKey = (System.currentTimeMillis() / Server.DAY_TIME) - 14;
            TreeSet<Long> removeSet = historyHeadKeySet(toKey);
            for (long dayKey : removeSet) {
                try {
                    History history = getHistoryByDay(dayKey);
                    if (history != null) {
                        history.close();
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    removeHistoryByDay(dayKey);
                }
            }
        }
    }
    
    public static void removeExpiredHistory() {
        if (Core.isRunning()) {
            File folder = new File("./history/");
            if (folder.isDirectory()) {
                for (File file : folder.listFiles()) {
                    if (file.isFile()) {
                        if ((System.currentTimeMillis() - file.lastModified()) > HISTORY_EXPIRES * Server.DAY_TIME) {
                            file.delete();
                        }
                    } else if (file.isDirectory()) {
                        Core.deleteFully(file);
                    }
                }
            }
        }
    }
    
    public static synchronized void closeAllHistory() {
        for (History history : HISTORY_MAP.values()) {
            try {
                history.close();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        HISTORY_MAP.clear();
    }
    
    private static History getHistoryByTime(long timeKey, boolean create) {
        long dayKey = timeKey / Server.DAY_TIME;
        History history = getHistoryByDay(dayKey);
        if (create && history == null) {
            history = creatHistoryByDay(dayKey);
        }
        return history;
    }
    
    private static History getHistoryByDay(long dayKey) {
        return HISTORY_MAP.get(dayKey);
    }
    
    private static synchronized History creatHistoryByDay(long dayKey) {
        History history = HISTORY_MAP.get(dayKey);
        if (history == null) {
            try {
                File folder = new File("./history/");
                File dataFile = new File(folder, Long.toHexString(dayKey) + ".data");
                File indexFile = new File(folder, Long.toHexString(dayKey) + ".index");
                history = new History(dataFile, indexFile);
                HISTORY_MAP.put(dayKey, history);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        return history;
    }
    
    public static TreeMap<Long,Query> getQueriesSubjectWordSetHOLD(
            TreeSet<String> subjectSet
    ) throws Exception {
        if (subjectSet == null) {
            return null;
        } else {
            TreeMap<Long,Query> resultMap = new TreeMap<>();
            for (User user : User.getUserList()) {
                for (long timeKey : user.getTimeKeySet()) {
                    Query query = user.getQuery(timeKey);
                    if (query != null && query.isHolding()) {
                        String subject = query.getSubjectWordSet(2);
                        if (subject != null && subjectSet.contains(subject)) {
                            resultMap.put(timeKey, query);
                        }
                    }
                }
            }
            return resultMap;
        }
    }
    
    private static final byte HISTORY_VERSION = 1;
    private static short HISTORY_EXPIRES = 90;
    
    public static void setHistoryExpires(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setHistoryExpires(Integer.parseInt(expires));
            } catch (Exception ex) {
                Server.logError("invalid history expires integer value '" + expires + "'.");
            }
        }
    }
    
    public static synchronized void setHistoryExpires(int expires) {
        if (expires < 1 || expires > Short.MAX_VALUE) {
            Server.logError("invalid history expires integer value '" + expires + "'.");
        } else {
            User.HISTORY_EXPIRES = (short) expires;
        }
    }
    
    private static class History {
        
        private final RandomAccessFile RAF_DATA;
        private final RandomAccessFile RAF_INDEX;
        
        private final TreeMap<Long,Index> MAP_INDEX = new TreeMap<>();
        
        private synchronized TreeSet<Long> getTimeKeySet(User user) {
            if (user == null) {
                return null;
            } else {
                int userHash = user.getEmail().hashCode();
                TreeSet<Long> resultSet = new TreeSet<>();
                for (long timeKey : MAP_INDEX.keySet()) {
                    Index index = MAP_INDEX.get(timeKey);
                    if (index != null && index.userHash == userHash) {
                        resultSet.add(timeKey);
                    }
                }
                return resultSet;
            }
        }
        
        private class Index {
            
            private final int userHash;
            private final long position;
            
            private Index(int userHash, long position) {
                this.userHash = userHash;
                this.position = position;
            }
        }
        
        private History(File dataFile, File indexFile) throws Exception {
            if (dataFile == null) {
                throw new Exception("history data file not defined.");
            } else if (indexFile == null) {
                throw new Exception("history index file not defined.");
            } else {
                boolean existsData = dataFile.exists();
                boolean existsIndex = indexFile.exists();
                RAF_DATA = new RandomAccessFile(dataFile, "rw");
                RAF_INDEX = new RandomAccessFile(indexFile, "rw");
                if (existsData) {
                    startIndex(existsIndex);
                }
            }
        }
        
        private void startIndex(boolean exists) {
            Thread thread = new Thread() {
                @Override
                public void run() {
                    try {
                        if (exists) {
                            History.this.loadIndex();
                        } else {
                            History.this.buildIndex();
                        }
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
            };
            thread.setName("HISTORYID");
            thread.setPriority(Thread.NORM_PRIORITY);
            thread.start();
        }
        
        private synchronized void loadIndex() throws IOException {
            RAF_INDEX.seek(0);
            while (true) {                
                try {
                    byte version = RAF_INDEX.readByte();
                    if (version == 1) {
                        int userHash2 = RAF_INDEX.readInt();
                        long timeKey2 = RAF_INDEX.readLong();
                        long position2 = RAF_INDEX.readLong();
                        MAP_INDEX.put(timeKey2, new Index(userHash2, position2));
                    } else {
                        Server.logError("data version undefined: " + version);
                        break;
                    }
                } catch (EOFException ex) {
                    break;
                }
            }
        }
        
        private synchronized void buildIndex() throws Exception {
            RAF_DATA.seek(0);
            while (true) {
                try {
                    long position = RAF_DATA.getFilePointer();
                    byte version = RAF_DATA.readByte();
                    if (version == 1) {
                        String userEmail = Core.readUTF(RAF_DATA);
                        if (userEmail != null) {
                            int userHash = userEmail.hashCode();
                            long timeKey = RAF_DATA.readLong();
                            int length = RAF_DATA.readInt();
                            RAF_DATA.skipBytes(length);
                            RAF_INDEX.writeByte(HISTORY_VERSION);
                            RAF_INDEX.writeInt(userHash);
                            RAF_INDEX.writeLong(timeKey);
                            RAF_INDEX.writeLong(position);
                            MAP_INDEX.put(timeKey, new Index(userHash, position));
                        }
                    } else {
                        Server.logError("data version undefined: " + version);
                        break;
                    }
                } catch (EOFException ex) {
                    break;
                }
            }
        }
        
        private synchronized void close() throws IOException {
            RAF_DATA.close();
            RAF_INDEX.close();
            MAP_INDEX.clear();
        }
        
        private Long store(long timeKey, Query query) throws Exception {
            if (query == null) {
                return null;
            } else {
                String userEmail = query.getUserEmail();
                int userHash = userEmail.hashCode();
                byte[] data = query.toByteArray();
                long position = storeData(userEmail, timeKey, data);
                Index index = new Index(userHash, position);
                storeIndex(timeKey, index);
                return position;
            }
        }
        
        private synchronized long storeData(
                String userEmail, long timeKey, byte[] data
        ) throws Exception {
            long positionData = RAF_DATA.length();
            RAF_DATA.seek(positionData);
            RAF_DATA.writeByte(HISTORY_VERSION);
            Core.writeUTF(RAF_DATA, userEmail);
            RAF_DATA.writeLong(timeKey);
            RAF_DATA.writeInt(data.length);
            RAF_DATA.write(data);
            return positionData;
        }
        
        private synchronized void storeIndex(
                long timeKey, Index index
        ) throws Exception {
            RAF_INDEX.seek(RAF_INDEX.length());
            RAF_INDEX.writeByte(HISTORY_VERSION);
            RAF_INDEX.writeInt(index.userHash);
            RAF_INDEX.writeLong(timeKey);
            RAF_INDEX.writeLong(index.position);
            MAP_INDEX.put(timeKey, index);
        }
        
        private synchronized Index getIndex(Long timeKey) {
            return MAP_INDEX.get(timeKey);
        }
        
        private Query load(User user, long timeKey) throws Exception {
            if (user == null) {
                return null;
            } else {
                int userHash = user.getEmail().hashCode();
                Index index = getIndex(timeKey);
                if (index == null) {
                    return null;
                } else if (index.userHash != userHash) {
                    return null;
                } else {
                    return load(user, timeKey, index.position);
                }
            }
        }
        
        private synchronized Query load(
                User user, long timeKey, long position
        ) throws Exception {
            try {
                RAF_DATA.seek(position);
                byte version = RAF_DATA.readByte();
                if (version == 1) {
                    String email = Core.readUTF(RAF_DATA);
                    long time = RAF_DATA.readLong();
                    if (time == timeKey && user.isEmail(email)) {
                        return user.getQuery(version, RAF_DATA);
                    } else {
                        return null;
                    }
                } else {
                    throw new Exception("data version undefined: " + version);
                }
            } catch (EOFException ex) {
                return null;
            }
        }
        
        private synchronized TreeMap<Long,Query> getAll() throws Exception {
            TreeMap<Long,Query> resultMap = new TreeMap<>();
            RAF_DATA.seek(0);
            while (true) {                
                try {
                    byte version = RAF_DATA.readByte();
                    if (version == 1) {
                        String email = Core.readUTF(RAF_DATA);
                        long time = RAF_DATA.readLong();
                        User user = User.getExact(email);
                        if (user == null) {
                            user = User.create(email, "Anonymous");
                        }
                        Query query = user.getQuery(version, RAF_DATA);
                        resultMap.put(time, query);
                    } else {
                        throw new Exception("data version undefined: " + version);
                    }
                } catch (EOFException ex) {
                    break;
                }
            }
            return resultMap;
        }
    }
    
    private static synchronized boolean adviseFromHIJACK(
            long time, String from, Locale locale
    ) {
        if (from == null) {
            return false;
        } else if (NoReply.isUnsubscribed(from)) {
            return false;
        } else {
            try {
                InternetAddress[] recipients = InternetAddress.parse(from);
                Document templateHTML;
                File logoFile;
                String subjectLocal;
                if ((logoFile = Core.getLogoFile(null)) == null) {
                    Server.logError("hijacked warning failed: logo.png not found");
                    return false;
                } else if ((templateHTML = Core.getTemplateWarningHijackedSender(locale)) == null) {
                    Server.logError("hijacked warning failed: warning.hijacked.sender.en.html not found");
                    return false;
                } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                    Server.logError("hijacked warning failed: HTML title not found");
                    return false;
                } else {
                    templateHTML = templateHTML.normalise();

                    MimeMessage message = Core.newMessage(false);
                    message.addRecipients(Message.RecipientType.TO, recipients);
                    message.setSubject(subjectLocal + " #" + Long.toString(time, 32));
                    // Build warning part.
                    MimeBodyPart htmlPart = new MimeBodyPart();
                    htmlPart.setContent(templateHTML.html(), "text/html;charset=UTF-8");
                    htmlPart.setDisposition(MimeBodyPart.INLINE);
                    // Build logo part.
                    MimeBodyPart logoPart = new MimeBodyPart();
                    logoPart.attachFile(logoFile);
                    logoPart.setContentID("<logo>");
                    logoPart.addHeader("Content-Type", "image/png");
                    // Join all parts.
                    MimeMultipart content = new MimeMultipart("related");
                    content.addBodyPart(htmlPart);
                    content.addBodyPart(logoPart);
                    // Set multiplart contentRelated.
                    message.setContent(content);
                    message.saveChanges();
                    // Enviar mensagem.
                    if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                        NoReply.addSafe(from);
                        return true;
                    } else {
                        return false;
                    }
                }
            } catch (NameNotFoundException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (SocketException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (ServiceUnavailableException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (CommunicationException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (MailConnectException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (SocketTimeoutException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (SocketConnectException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (SMTPAddressFailedException afex) {
                NoReply.addSafe(from);
                return false;
            } catch (SendFailedException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (MessagingException ex) {
                NoReply.addSafe(from);
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
}
