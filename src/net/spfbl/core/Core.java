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
package net.spfbl.core;

import net.spfbl.service.ServerP2P;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.mysql.jdbc.exceptions.MySQLTimeoutException;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import de.agitos.dkim.Canonicalization;
import de.agitos.dkim.DKIMSigner;
import de.agitos.dkim.SigningAlgorithm;
import it.sauronsoftware.junique.AlreadyLockedException;
import it.sauronsoftware.junique.JUnique;
import it.sauronsoftware.junique.MessageHandler;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.mail.Address;
import javax.mail.AuthenticationFailedException;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeUtility;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.net.ssl.HttpsURLConnection;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isReverseIPv6;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.CIDR;
import net.spfbl.data.DKIM;
import net.spfbl.data.Dictionary;
import net.spfbl.data.FQDN;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Recipient;
import net.spfbl.data.Trap;
import net.spfbl.service.ServerDNS;
import net.spfbl.service.ServerHTTP;
import net.spfbl.service.ServerSMTP;
import net.spfbl.service.ServerSPFBL;
import net.spfbl.spf.SPF.Qualifier;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.OrderBuilder;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.xbill.DNS.TextParseException;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Core {
    
    private static final byte VERSION = 3;
    private static final byte SUBVERSION = 0;
    private static final byte RELEASE = 0;
    private static final boolean TESTING = false;
    
    public static String getAplication() {
        return "SPFBL-" + getVersion() + (TESTING ? "-TESTING" : "");
    }
    
    public static String getVersion() {
        return VERSION + "." + SUBVERSION + "." + RELEASE;
    }
    
    public static boolean isTestingVersion() {
        return TESTING;
    }
    
    public static String getSubVersion() {
        return VERSION + "." + SUBVERSION;
    }
    
    private static final Regex VERSION_PATTERN = new Regex("^"
            + "[0-9]+\\.[0-9]+(\\.[0-9]+)?"
            + "$"
    );
    
    public static boolean isValidVersion(String version) {
        if (version == null) {
            return false;
        } else {
            return VERSION_PATTERN.matches(version);
        }
    }
    
    /**
     * O nível do LOG.
     */
    public static Level LOG_LEVEL = Level.INFO;

    public enum Level {
        ERROR,
        WARN,
        INFO,
        DEBUG,
        TRACE
    }
    
    public static boolean isTooBigForPeers(String command) {
        if (peerUDP == null) {
            return false;
        } else {
            return peerUDP.isTooBig(command);
        }
    }
    
    public static String sendCommandToPeer(
            String command,
            String address,
            int port,
            int ports,
            SecretKey secretKey
            ) {
        if (peerUDP == null) {
            return "DISABLED";
        } else {
            return peerUDP.send(
                    command, address,
                    port, ports, secretKey
            );
        }
    }
    
    public static boolean hasPeerConnection() {
        if (peerUDP == null) {
            return false;
        } else {
            return peerUDP.hasConnection();
        }
    }
    
    public static String getPeerConnection() {
        if (peerUDP == null) {
            return null;
        } else {
            return peerUDP.getConnection();
        }
    }
    
    public static String getPeerSecuredConnection() {
        if (peerUDP == null) {
            return null;
        } else {
            return peerUDP.getSecuredConnection();
        }
    }
    
    private static ServerHTTP serviceHTTP = null;
    
    public static int getServiceHTTPS() {
        if (serviceHTTP == null) {
            return 0;
        } else {
            return serviceHTTP.getServiceHTTPS();
        }
    }
    
    private static final Huffman HUFFMAN = Huffman.load();
    private static final Huffman HUFFMANPLUS = Huffman.loadPlus();
    
    public static String encryptURL(long time, String text) throws ProcessException {
        byte[] byteArray = Core.encodeHuffman(text, 8);
        byteArray[0] = (byte) (time & 0xFF);
        byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[7] = (byte) ((time >>> 8) & 0xFF);
        return Server.encryptURLSafe(byteArray);
    }
    
    public static String encrypt32(long time, String text) throws ProcessException {
        byte[] byteArray = Core.encodeHuffman(text, 8);
        byteArray[0] = (byte) (time & 0xFF);
        byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[7] = (byte) ((time >>> 8) & 0xFF);
        return Server.encrypt32(byteArray);
    }
    
    public static String decryptURLSafe(String ticket) {
        try {
            return decryptURL(ticket);
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    public static String decryptURL(String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray.length > 8) {
                long time = byteArray[7] & 0xFF;
                time <<= 8;
                time += byteArray[6] & 0xFF;
                time <<= 8;
                time += byteArray[5] & 0xFF;
                time <<= 8;
                time += byteArray[4] & 0xFF;
                time <<= 8;
                time += byteArray[3] & 0xFF;
                time <<= 8;
                time += byteArray[2] & 0xFF;
                time <<= 8;
                time += byteArray[1] & 0xFF;
                time <<= 8;
                time += byteArray[0] & 0xFF;
                if (System.currentTimeMillis() - time < Server.WEEK_TIME) {
                    return Core.decodeHuffman(byteArray, 8);
                } else {
                    throw new ProcessException("ERROR: EXPIRED");
                }
            } else {
                throw new ProcessException("ERROR: CORRUPTED");
            }
        }
    }
    
    public static Entry<Long,String> decrypt32(String ticket) {
        if (ticket == null) {
            return null;
        } else {
            byte[] byteArray = Server.decryptToByteArray32(ticket);
            if (byteArray == null) {
                return null;
            } else if (byteArray.length > 8) {
                long time = byteArray[7] & 0xFF;
                time <<= 8;
                time += byteArray[6] & 0xFF;
                time <<= 8;
                time += byteArray[5] & 0xFF;
                time <<= 8;
                time += byteArray[4] & 0xFF;
                time <<= 8;
                time += byteArray[3] & 0xFF;
                time <<= 8;
                time += byteArray[2] & 0xFF;
                time <<= 8;
                time += byteArray[1] & 0xFF;
                time <<= 8;
                time += byteArray[0] & 0xFF;
                if (System.currentTimeMillis() - time < Server.WEEK_TIME) {
                    String command = Core.decodeHuffman(byteArray, 8);
                    return new AbstractMap.SimpleEntry<>(time, command);
                }
            }
            return null;
        }
    }
    
    public static byte[] encodeHuffman(String text, int deslocamento) throws ProcessException {
        if (text == null) {
            return null;
        } else {
            return HUFFMANPLUS.encodeByteArray(text.toLowerCase(), deslocamento);
        }
    }
    
    public static String decodeHuffman(byte[] byteArray, int deslocamento) {
        String query = Core.HUFFMANPLUS.decode(byteArray, deslocamento);
        if (query == null) {
            return Core.HUFFMAN.decode(byteArray, deslocamento);
        } else if (query.startsWith("block ")) {
            return query;
        } else if (query.startsWith("ban ")) {
            return query;
        } else if (query.startsWith("bansubject ")) {
            return query;
        } else if (query.startsWith("holding ")) {
            return query;
        } else if (query.startsWith("release ")) {
            return query;
        } else if (query.startsWith("remove ")) {
            return query;
        } else if (query.startsWith("spam ")) {
            return query;
        } else if (query.startsWith("complain ")) {
            return query;
        } else if (query.startsWith("unblock ")) {
            return query;
        } else if (query.startsWith("unblockpp ")) {
            return query;
        } else if (query.startsWith("unhold ")) {
            return query;
        } else if (query.startsWith("unholdadmin ")) {
            return query;
        } else if (query.startsWith("unsubscribe ")) {
            return query;
        } else if (query.startsWith("white ")) {
            return query;
        } else if (query.startsWith("delist ")) {
            return query;
        } else if (query.startsWith("licence ")) {
            return query;
        } else if (isValidEmail(query)) {
            return query;
        } else {
            return Core.HUFFMAN.decode(byteArray, deslocamento);
        }
    }
    
    public static final Base32 BASE32STANDARD = new Base32(0, new byte[0], false);
    public static final Base64 BASE64URLSAFE = new Base64(0, new byte[0], true);
    public static final Base64 BASE64STANDARD = new Base64(0, new byte[0], false);
    
    public static String getReleaseURL(User user, String id) {
        if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Defer defer = Defer.getDefer(id);
            Locale locale = user == null ? null : user.getLocale();
            String url = serviceHTTP.getSecuredURL(locale);
            if (defer == null) {
                return null;
            } else if (url == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String ticket = "release " + id;
                try {
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getURL(boolean secured, Locale locale, String token) {
        if (serviceHTTP == null) {
            return null;
        } else if (token == null) {
            return null;
        } else if (secured) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                return url + token;
            }
        } else {
            String url = serviceHTTP.getURL(locale);
            if (url == null) {
                return null;
            } else {
                return url + token;
            }
        }
    }
    
    public static String getUnblockURL(
            Client client,
            User user,
            String ip,
            String sender,
            String hostname,
            String recipient
            ) {
        if (recipient == null) {
            return null;
        } else if (Trap.containsInexistent(client, user, recipient)) {
            return null;
        } else {
            // Definição do e-mail do usuário.
            String userEmail = null;
            if (user != null) {
                userEmail = user.getEmail();
            } else if (client != null) {
                userEmail = client.getEmail();
            }
            return getUnblockURL(
                    userEmail,
                    ip, sender, hostname, recipient
            );
        }
    }
    
    public static String getUnblockURL(
            String userEmail,
            String ip,
            String sender,
            String hostname,
            String recipient
            ) {
        if (userEmail == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (sender == null) {
            return null;
        } else if (recipient == null) {
            return null;
        } else if (!isValidEmail(sender)) {
            return null;
        } else if (!isValidEmail(recipient)) {
            return null;
        } else if (NoReply.contains(recipient, true)) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(null);
            if (url == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String ticket = "unblock";
                try {
                    ticket += ' ' + userEmail;
                    ticket += ' ' + ip;
                    ticket += ' ' + sender;
                    ticket += ' ' + recipient;
                    ticket += hostname == null ? "" : ' ' + hostname;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getDelistURL(
            Locale locale,
            String client,
            String ip
            ) {
        if (client == null) {
            return null;
        } else if (!isValidEmail(client)) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String ticket = "delist";
                ticket += ' ' + client;
                ticket += ' ' + ip;
                try {
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getPayPalUnblockURL(
            Locale locale,
            String user,
            String ip,
            String token,
            String playerid,
            String currency,
            String price
            ) {
        if (user == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (!isValidEmail(user)) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String ticket = "unblockpp";
                ticket += ' ' + user.toLowerCase();
                ticket += ' ' + ip.toLowerCase();
                ticket += ' ' + token;
                ticket += ' ' + playerid;
                ticket += ' ' + price;
                ticket += ' ' + currency;
                try {
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getHoldingURL(
            User user,
            long time
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = user.getLocale();
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "holding";
                try {
                    ticket += ' ' + user.getEmail();
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getUnholdURL(
            User user,
            long time
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = user.getLocale();
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "unhold";
                try {
                    ticket += ' ' + user.getEmail();
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getUnholdURL(
            long time,
            String user
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = Core.getDefaultLocale(user);
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "unhold";
                try {
                    ticket += ' ' + user;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getUnholdAdminURL(
            long time,
            String email,
            String blockKey
    ) {
        if (blockKey == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String adminEmail = Core.getAdminEmail();
            Locale locale = Core.getDefaultLocale(adminEmail);
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "unholdadmin";
                try {
                    blockKey = Core.BASE32STANDARD.encodeToString(blockKey.getBytes());
                    blockKey = blockKey.replace('=', '+').toLowerCase();
                    ticket += ' ' + email + ' ' + blockKey;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getListUnsubscribeURL(
            Locale locale,
            InternetAddress recipient
    ) {
        if (recipient == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (!isValidEmail(recipient.getAddress())) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                long time = Server.getNewUniqueTime();
                String ticket = "unsubscribe";
                try {
                    ticket += ' ' + recipient.getAddress();
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getBlockURL(
            User user,
            long time
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = user.getLocale();
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "block";
                try {
                    ticket += ' ' + user.getEmail();
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getBlockURL(
            long time,
            String user
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = Core.getDefaultLocale(user);
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "block";
                try {
                    ticket += ' ' + user;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getBanURL(
            long time,
            String user
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = Core.getDefaultLocale(user);
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "ban";
                try {
                    ticket += ' ' + user;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getBanBySubjectURL(
            long time,
            String user
    ) {
        if (user == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Locale locale = Core.getDefaultLocale(user);
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                String ticket = "bansubject";
                try {
                    ticket += ' ' + user;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getWhiteURL(
            Locale locale,
            String white,
            String client,
            String ip,
            String sender,
            String hostname,
            String recipient
    ) {
        if (white == null) {
            return null;
        } else if (client == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (sender == null) {
            return null;
        } else if (recipient == null) {
            return null;
        } else if (serviceHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                String ticket = "white";
                try {
                    ticket += ' ' + white;
                    ticket += ' ' + client;
                    ticket += ' ' + ip;
                    ticket += ' ' + sender;
                    ticket += ' ' + recipient;
                    ticket += hostname == null ? "" : ' ' + hostname;
                    return url + encryptURL(time, ticket);
                } catch (Exception ex) {
                    Server.logError(new Exception("compress fail: " + ticket, ex));
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getURL(User user) {
        if (serviceHTTP == null) {
            return null;
        } else if (user == null) {
            return serviceHTTP.getSecuredURL(null);
        } else {
            return serviceHTTP.getSecuredURL(user.getLocale());
        }
    }
    
    protected static void store() {
        storeKeystoreMap();
    }
    
    private static AdministrationTCP administrationTCP = null;
    private static ServerSPFBL querySPF = null;
    private static ServerDNS queryDNSBL = null;
    private static ServerP2P peerUDP = null;
    private static ServerSMTP serviceESMTP = null;
    
    public static boolean tryToProcessQueue() {
        if (serviceESMTP == null) {
            return false;
        } else {
            return serviceESMTP.tryToProcessQueue();
        }
    }
    
    public static boolean processDelivery(long time) {
        if (serviceESMTP == null) {
            return false;
        } else {
            return serviceESMTP.processDelivery(time);
        }
    }
    
    public static boolean loadConfiguration() {
        File confFile = new File("spfbl.conf");
        if (confFile.exists()) {
            try {
                Properties properties = new Properties();
                try (FileInputStream confIS = new FileInputStream(confFile)) {
                    properties.load(confIS);
                    Server.setSyslog(properties);
                    Server.setLogFolder(properties.getProperty("log_folder"));
                    Server.setLogExpires(properties.getProperty("log_expires"));
                    User.setHistoryExpires(properties.getProperty("history_expires"));
                    Server.setLogDNS(properties.getProperty("log_dns"));
                    Server.setLogDNS(properties.getProperty("log_p2p"));
                    Server.setPrimaryProviderDNS(properties.getProperty("dns_provider"));
                    Server.setPrimaryProviderDNS(properties.getProperty("dns_provider_primary"));
                    Server.setSecondaryProviderDNS(properties.getProperty("dns_provider_secondary"));
                    Server.setServerWHOISBR(properties.getProperty("whois_server_br"));
                    Core.setShowAdvertisement(properties.getProperty("advertisement_show"));
                    Core.setHostname(properties.getProperty("hostname"));
                    Core.setInterface(properties.getProperty("interface"));
                    Core.setProviderACME(properties.getProperty("acme_provider"));
                    Core.setOrganizationACME(properties.getProperty("acme_organization"));
                    Core.setStateACME(properties.getProperty("acme_state"));
                    Core.setCountryACME(properties.getProperty("acme_country"));
                    Core.setAdminEmail(properties.getProperty("admin_email"));
                    Core.setAbuseEmail(properties.getProperty("abuse_email"));
                    Core.setIsAuthSMTP(properties.getProperty("smtp_auth"));
                    Core.setStartTLSSMTP(properties.getProperty("smtp_starttls"));
                    Core.setHostSMTP(properties.getProperty("smtp_host"));
                    Core.setPortSMTP(properties.getProperty("smpt_port")); // Version: 2.4
                    Core.setPortSMTP(properties.getProperty("smtp_port"));
                    Core.setUserSMTP(properties.getProperty("smtp_user"));
                    Core.setPasswordSMTP(properties.getProperty("smtp_password"));
                    Core.setSelectorDKIM(properties.getProperty("dkim_selector"));
                    Core.setPrivateDKIM(properties.getProperty("dkim_private"));
                    Core.setInexistentExpires(properties.getProperty("inexistent_expires"));
                    Core.setPortADMIN(properties.getProperty("admin_port"));
                    Core.setPortADMINS(properties.getProperty("admins_port"));
                    Core.setPortSPFBL(properties.getProperty("spfbl_port"));
                    Core.setPortSPFBLS(properties.getProperty("spfbls_port"));
                    Core.setPortDNSBL(properties.getProperty("dnsbl_port"));
                    Core.setPortHTTP(properties.getProperty("http_port"));
                    Core.setPortHTTPS(properties.getProperty("https_port"));
                    Core.setPortESMTP(properties.getProperty("esmtp_port"));
                    Core.setPortESMTPS(properties.getProperty("esmtps_port"));
                    Core.setPayPalAccount(
                            properties.getProperty("paypal_account_user"),
                            properties.getProperty("paypal_account_password"),
                            properties.getProperty("paypal_account_signature")
                    );
                    Core.setPayPalPriceDelistUSD(properties.getProperty("paypal_delist_usd"));
                    Core.setPayPalPriceDelistEUR(properties.getProperty("paypal_delist_eur"));
                    Core.setPayPalPriceDelistJPY(properties.getProperty("paypal_delist_jpy"));
                    Core.setPayPalPriceDelistBRL(properties.getProperty("paypal_delist_brl"));
                    Core.setMaxUDP(properties.getProperty("udp_max"));
                    Core.setDeferTimeSOFTFAIL(properties.getProperty("defer_time_softfail"));
                    Core.setDeferTimeYELLOW(properties.getProperty("defer_time_gray")); // Obsolete.
                    Core.setDeferTimeYELLOW(properties.getProperty("defer_time_yellow"));
                    Core.setDeferTimeRED(properties.getProperty("defer_time_black")); // Obsolete.
                    Core.setDeferTimeRED(properties.getProperty("defer_time_red"));
                    Core.setDeferTimeHOLD(properties.getProperty("defer_time_hold"));
                    Core.setLevelLOG(properties.getProperty("log_level"));
                    Core.setRecaptchaKeySite(properties.getProperty("recaptcha_key_site"));
                    Core.setRecaptchaKeySecret(properties.getProperty("recaptcha_key_secret"));
                    Core.setSafeBrowsingKey(properties.getProperty("gsb_api_key"));
//                    Core.setCacheTimeStore(properties.getProperty("cache_time_store"));
                    Core.setHostnameMySQL(properties.getProperty("mysql_hostname"));
                    Core.setPortMySQL(properties.getProperty("mysql_port"));
                    Core.setSchemaMySQL(properties.getProperty("mysql_schema"));
                    Core.setUserMySQL(properties.getProperty("mysql_user"));
                    Core.setPasswordMySQL(properties.getProperty("mysql_password"));
                    Core.setSSLMySQL(properties.getProperty("mysql_ssl"));
                    Core.setExpiresMySQL(properties.getProperty("mysql_expires"));
                    ServerP2P.setConnectionLimit(properties.getProperty("peer_limit"));
                    ServerDNS.setConnectionLimit(properties.getProperty("dnsbl_limit"));
                    ServerSPFBL.setConnectionLimit(properties.getProperty("spfbl_limit"));
                    ServerHTTP.setConnectionLimit(properties.getProperty("http_limit"));
                    ServerSMTP.setConnectionLimit(properties.getProperty("smtp_limit"));
                    return true;
                }
            } catch (IOException ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static String MYSQL_HOSTNAME = null;
    private static short MYSQL_PORT = 3306;
    private static String MYSQL_SCHEMA = "spfbl";
    private static String MYSQL_USER = null;
    private static String MYSQL_PASSWORD = null;
    private static boolean MYSQL_SSL = false;
    private static short MYSQL_EXPIRES = 0;
    
    public static synchronized void setHostnameMySQL(String hostname) {
        if (hostname != null && hostname.length() > 0) {
            if (isHostname(hostname)) {
                Core.MYSQL_HOSTNAME = Domain.extractHost(hostname, false);
            } else if (isValidIP(hostname)) {
                Core.MYSQL_HOSTNAME = Subnet.normalizeIP(hostname);
            } else {
                Server.logError("invalid MySQL address '" + hostname + "'.");
            }
        }
    }
    
    public static void setPortMySQL(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortMySQL(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid MySQL port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortMySQL(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid MySQL port '" + port + "'.");
        } else {
            Core.MYSQL_PORT = (short) port;
        }
    }
    
    public static synchronized void setSchemaMySQL(String schema) {
        if (schema != null && schema.trim().length() > 0) {
            Core.MYSQL_SCHEMA = schema.trim();
        }
    }
    
    public static synchronized void setUserMySQL(String user) {
        if (user != null && user.trim().length() > 0) {
            Core.MYSQL_USER = user.trim();
        }
    }
    
    public static synchronized void setPasswordMySQL(String password) {
        if (password != null && password.trim().length() > 0) {
            Core.MYSQL_PASSWORD = password.trim();
        }
    }
    
    public static void setSSLMySQL(String ssl) {
        if (ssl != null && ssl.length() > 0) {
            try {
                setSSLMySQL(Boolean.parseBoolean(ssl));
            } catch (Exception ex) {
                Server.logError("invalid MySQL SSL '" + ssl + "'.");
            }
        }
    }
    
    public static synchronized void setSSLMySQL(boolean ssl) {
        Core.MYSQL_SSL = ssl;
    }
    
    public static void setExpiresMySQL(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setExpiresMySQL(Integer.parseInt(expires));
            } catch (Exception ex) {
                Server.logError("invalid MySQL expires days '" + expires + "'.");
            }
        }
    }
    
    public static synchronized void setExpiresMySQL(int expires) {
        if (expires < 0 || expires > Short.MAX_VALUE) {
            Server.logError("invalid MySQL expires days '" + expires + "'.");
        } else {
            Core.MYSQL_EXPIRES = (short) expires;
        }
    }
    
    public static boolean hasMySQL() {
        if (MYSQL_HOSTNAME == null) {
            return false;
        } else if (MYSQL_USER == null) {
            return false;
        } else if (MYSQL_PASSWORD == null) {
            return false;
        } else {
            return true;
        }
    }
    
    private static ConnectionPooler CONNECTION_POOLER = null;
    
    private static synchronized ConnectionPooler getConnectionPooler() {
        if (MYSQL_HOSTNAME == null) {
            return null;
        } else if (MYSQL_USER == null) {
            return null;
        } else if (MYSQL_PASSWORD == null) {
            return null;
        } else if (CONNECTION_POOLER == null) {
            return CONNECTION_POOLER = new ConnectionPooler(
                    MYSQL_HOSTNAME,
                    MYSQL_PORT,
                    MYSQL_USER,
                    MYSQL_PASSWORD,
                    MYSQL_SCHEMA,
                    MYSQL_SSL
            );
        } else {
            return CONNECTION_POOLER;
        }
    }
    
    public static synchronized boolean closeConnectionPooler() {
        if (CONNECTION_POOLER == null) {
            return false;
        } else {
            try {
                CONNECTION_POOLER.close();
                return true;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static Connection aquireConnectionMySQL() {
        ConnectionPooler pooler = getConnectionPooler();
        if (pooler == null) {
            return null;
        } else {
            try {
                return pooler.acquire();
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static boolean releaseConnectionMySQL() {
        ConnectionPooler pooler = getConnectionPooler();
        if (pooler == null) {
            return false;
        } else {
            try {
                pooler.release();
                return true;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    
    
    public static Connection newConnectionMySQL() throws Exception {
        if (MYSQL_HOSTNAME == null) {
            return null;
        } else if (MYSQL_USER == null) {
            return null;
        } else if (MYSQL_PASSWORD == null) {
            return null;
        } else {
            long begin = System.currentTimeMillis();
            Class.forName("com.mysql.jdbc.Driver");
            String url = "jdbc:mysql://" + MYSQL_HOSTNAME + ":"
                    + "" + MYSQL_PORT + "/" + MYSQL_SCHEMA + ""
                    + "?autoReconnect=true"
                    + "&useUnicode=true&characterEncoding=UTF-8"
                    + "&verifyServerCertificate=false"
                    + (MYSQL_SSL ? "&useSSL=true&requireSSL=true"
                    : "&useSSL=false&requireSSL=false");
            DriverManager.setLoginTimeout(3);
            Connection connection = DriverManager.getConnection(
                    url, MYSQL_USER, MYSQL_PASSWORD
            );
            String command = "SET NAMES 'utf8mb4'";
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(3);
                statement.executeUpdate(command);
                Server.logMySQL("connection created.");
                return connection;
            } catch (MySQLTimeoutException ex) {
                Server.logMySQL(begin, command, ex);
                connection.close();
                throw ex;
            }
        }
    }
    
    public static Short getExpiresMySQL() {
        if (MYSQL_EXPIRES > 0) {
            return MYSQL_EXPIRES;
        } else {
            return null;
        }
    }
    
    private static String PAYPAL_ACCOUNT_USER = null;
    private static String PAYPAL_ACCOUNT_PASSWORD = null;
    private static String PAYPAL_ACCOUNT_SIGNATURE = null;
    
    private static final DecimalFormat PAYPAL_PRICE_FORMAT = new DecimalFormat("0.00", new DecimalFormatSymbols(Locale.US));
    private static float PAYPAL_PRICE_DELIST_USD = 0.00f;
    private static float PAYPAL_PRICE_DELIST_EUR = 0.00f;
    private static float PAYPAL_PRICE_DELIST_JPY = 0.00f;
    private static float PAYPAL_PRICE_DELIST_BRL = 0.00f;
    
    public static synchronized void setPayPalAccount(
            String user,
            String password,
            String signature
    ) {
        if (user != null && password != null && signature != null) {
            if (user.length() > 0 && password.length() > 0 && signature.length() > 0) {
                if (Pattern.matches("^(([a-z0-9_]|[a-z0-9_][a-z0-9_+-]{0,61}[a-z0-9_])(\\.([a-z0-9_]|[a-z0-9_][a-z0-9_+-]{0,61}[a-z0-9]))*)$", user)) {
                    if (Pattern.matches("^[0-9A-Z]{16}$", password)) {
                        if (Pattern.matches("^[0-9a-zA-Z.-]{56}$", signature)) {
                            Core.PAYPAL_ACCOUNT_USER = user;
                            Core.PAYPAL_ACCOUNT_PASSWORD = password;
                            Core.PAYPAL_ACCOUNT_SIGNATURE = signature;
                        } else {
                            Server.logError("invalid PayPal signature '" + signature + "'.");
                        }
                    } else {
                        Server.logError("invalid PayPal password '" + password + "'.");
                    }
                } else {
                    Server.logError("invalid PayPal user '" + user + "'.");
                }
            }
        }
    }
    
    public static void setPayPalPriceDelistUSD(String value) {
        if (value != null && value.length() > 0) {
            try {
                setPayPalPriceDelistUSD(Float.parseFloat(value));
            } catch (Exception ex) {
                Server.logError("invalid PayPal delist USD value '" + value + "'.");
            }
        }
    }
    
    public static void setPayPalPriceDelistUSD(float value) {
        if (value < 0.01f || value > 10000.00f) {
            Server.logError("invalid PayPal delist USD value " + value + ".");
        } else {
            Core.PAYPAL_PRICE_DELIST_USD = value;
        }
    }
    
    public static void setPayPalPriceDelistJPY(String value) {
        if (value != null && value.length() > 0) {
            try {
                setPayPalPriceDelistJPY(Float.parseFloat(value));
            } catch (Exception ex) {
                Server.logError("invalid PayPal delist JPY value '" + value + "'.");
            }
        }
    }
    
    public static void setPayPalPriceDelistJPY(float value) {
        if (value < 0.01f || value > 10000.00f) {
            Server.logError("invalid PayPal delist JPY value " + value + ".");
        } else {
            Core.PAYPAL_PRICE_DELIST_JPY = value;
        }
    }
    
    public static void setPayPalPriceDelistEUR(String value) {
        if (value != null && value.length() > 0) {
            try {
                setPayPalPriceDelistEUR(Float.parseFloat(value));
            } catch (Exception ex) {
                Server.logError("invalid PayPal delist EUR value '" + value + "'.");
            }
        }
    }
    
    public static void setPayPalPriceDelistEUR(float value) {
        if (value < 0.01f || value > 10000.00f) {
            Server.logError("invalid PayPal delist EUR value " + value + ".");
        } else {
            Core.PAYPAL_PRICE_DELIST_EUR = value;
        }
    }
    
    public static void setPayPalPriceDelistBRL(String value) {
        if (value != null && value.length() > 0) {
            try {
                setPayPalPriceDelistBRL(Float.parseFloat(value));
            } catch (Exception ex) {
                Server.logError("invalid PayPal delist BRL value '" + value + "'.");
            }
        }
    }
    
    public static void setPayPalPriceDelistBRL(float value) {
        if (value < 0.01f || value > 2000.0f) {
            Server.logError("invalid PayPal delist BRL value " + value + ".");
        } else {
            Core.PAYPAL_PRICE_DELIST_BRL = value;
        }
    }
    
    public static synchronized boolean hasPayPalAccount() {
        if (PAYPAL_ACCOUNT_USER == null) {
            return false;
        } else if (PAYPAL_ACCOUNT_PASSWORD == null) {
            return false;
        } else if (PAYPAL_ACCOUNT_SIGNATURE == null) {
            return false;
        } else {
            return true;
        }
    }
    
    public static String getPayPalAccountUser() {
        return PAYPAL_ACCOUNT_USER;
    }
    
    public static String getPayPalAccountPassword() {
        return PAYPAL_ACCOUNT_PASSWORD;
    }
    
    public static String getPayPalAccountSignature() {
        return PAYPAL_ACCOUNT_SIGNATURE;
    }
    
    public static String getPayPalPriceDelistUSD() {
        if (PAYPAL_PRICE_DELIST_USD == 0.0f) {
            return null;
        } else if (hasPayPalAccount()) {
            return PAYPAL_PRICE_FORMAT.format(PAYPAL_PRICE_DELIST_USD);
        } else {
            return null;
        }
    }
    
    public static String getPayPalPriceDelistJPY() {
        if (PAYPAL_PRICE_DELIST_JPY == 0.0f) {
            return null;
        } else if (hasPayPalAccount()) {
            return PAYPAL_PRICE_FORMAT.format(PAYPAL_PRICE_DELIST_JPY);
        } else {
            return null;
        }
    }
    
    public static String getPayPalPriceDelistEUR() {
        if (PAYPAL_PRICE_DELIST_EUR == 0.0f) {
            return null;
        } else if (hasPayPalAccount()) {
            return PAYPAL_PRICE_FORMAT.format(PAYPAL_PRICE_DELIST_EUR);
        } else {
            return null;
        }
    }
    
    public static String getPayPalPriceDelistBRL() {
        if (PAYPAL_PRICE_DELIST_BRL == 0.0f) {
            return null;
        } else if (hasPayPalAccount()) {
            return PAYPAL_PRICE_FORMAT.format(PAYPAL_PRICE_DELIST_BRL);
        } else {
            return null;
        }
    }
    
    private static String HOSTNAME = null;
    private static String INTERFACE = null;
    private static String ADMIN_EMAIL = null;
    private static String ABUSE_EMAIL = null;
    private static short PORT_ADMIN = 9875;
    private static short PORT_ADMINS = 0;
    private static short PORT_SPFBL = 9877;
    private static short PORT_SPFBLS = 0;
    private static short PORT_DNSBL = 0;
    private static short PORT_HTTP = 0;
    private static short PORT_HTTPS = 0;
    private static short PORT_ESMTP = 0;
    private static short PORT_ESMTPS = 0;
    private static short UDP_MAX = 512; // UDP max size packet.
    
    public static String getTicketSender(String sender) {
        if (sender == null) {
            return null;
        } else {
            int index = sender.indexOf('@');
            String ticket = sender.substring(0, index).toUpperCase();
            String hostname = sender.substring(index + 1);
            return isMyHostname(hostname) ? ticket : null;
        }
    }
    
    public static boolean isAdminEmail(String email, String result) {
        if (email == null) {
            return false;
        } else if (Objects.equals(result, "PASS")) {
            return email.equals(ADMIN_EMAIL);
        } else {
            return false;
        }
    }
    
    public static boolean isAdminEmail(String email) {
        if (email == null) {
            return false;
        } else {
            return email.equals(ADMIN_EMAIL);
        }
    }
    
    public static boolean hasAdminEmail() {
        return ADMIN_EMAIL != null;
    }
    
    public static boolean isAbuseEmail(String email) {
        if (email == null) {
            return false;
        } else {
            return email.equals(ABUSE_EMAIL);
        }
    }
    
    public static boolean hasAbuseEmail() {
        return ABUSE_EMAIL != null;
    }
    
    public static InternetAddress getAdminInternetAddress() {
        if (ADMIN_EMAIL == null) {
            return null;
        } else {
            User user = User.get(ADMIN_EMAIL);
            if (user == null) {
                try {
                    return new InternetAddress(ADMIN_EMAIL, "SPFBL Admin");
                } catch (UnsupportedEncodingException ex) {
                    return null;
                }
            } else {
                try {
                    return user.getInternetAddress();
                } catch (UnsupportedEncodingException ex) {
                    return null;
                }
            }
        }
    }
    
    public static String getAdminEmail() {
        return ADMIN_EMAIL;
    }
    
    public static User getAdminUser() {
        return User.getUserFor(ADMIN_EMAIL);
    }
    
    public static String getAbuseEmail() {
        return ABUSE_EMAIL;
    }
    
    public static short getPortADMIN() {
        return PORT_ADMIN;
    }
    
    public static boolean hasADMINS() {
        return PORT_ADMINS > 0;
    }
    
    public static short getPortADMINS() {
        return PORT_ADMINS;
    }
    
    public static short getPortSPFBL() {
        return PORT_SPFBL;
    }
    
    public static boolean hasSPFBL() {
        return PORT_SPFBL > 0;
    }
    
    public static short getPortSPFBLS() {
        return PORT_SPFBLS;
    }
    
    public static boolean hasSPFBLS() {
        return PORT_SPFBLS > 0;
    }
    
    public static short getPortDNSBL() {
        return PORT_DNSBL;
    }
    
    public static boolean hasPortDNSBL() {
        return PORT_DNSBL > 0;
    }
    
    public static short getPortHTTP() {
        return PORT_HTTP;
    }
    
    public static boolean hasPortHTTP() {
        return PORT_HTTP > 0;
    }
    
    public static short getPortHTTPS() {
        return PORT_HTTPS;
    }
    
    public static short getPortESMTP() {
        return PORT_ESMTP;
    }
    
    public static short getPortESMTPS() {
        return PORT_ESMTPS;
    }
    
    public static boolean hasPortHTTPS() {
        return PORT_HTTPS > 0;
    }
    
    public static boolean hasPortESMTP() {
        return PORT_ESMTP > 0;
    }
    
    public static boolean hasPortESMTPS() {
        return PORT_ESMTPS > 0;
    }
    
    public static boolean hasInterface() {
        return INTERFACE != null;
    }
    
    public static String getInterface() {
        return INTERFACE;
    }
    
    public static String getHostname() {
        return HOSTNAME;
    }
    
    public static boolean isMatrixDefence() {
        if (HOSTNAME == null) {
            return TESTING;
        } else if (HOSTNAME.equals("matrix.spfbl.net")) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isMyHostname(String hostname) {
        if ((hostname = Domain.normalizeHostname(hostname, false)) == null) {
            return false;
        } else {
            return hostname.equals(HOSTNAME);
        }
    }
    
    public static boolean hasHostname() {
        return HOSTNAME != null;
    }
    
    private static boolean isRouteable(String hostame) {
        try {
            Attributes attributesA = Server.getAttributesDNS(hostame, "A");
            Attribute attributeA = attributesA.get("A");
            if (attributeA == null) {
                Attributes attributesAAAA = Server.getAttributesDNS(hostame, "AAAA");
                Attribute attributeAAAA = attributesAAAA.get("AAAA");
                if (attributeAAAA != null) {
                    for (int i = 0; i < attributeAAAA.size(); i++) {
                        String host6Address = (String) attributeAAAA.get(i);
                        if (isValidIPv6(host6Address)) {
                            try {
                                InetAddress address = InetAddress.getByName(host6Address);
                                if (address.isLinkLocalAddress()) {
                                    return false;
                                } else if (address.isLoopbackAddress()) {
                                    return false;
                                }
                            } catch (UnknownHostException ex) {
                            }
                        } else {
                            return false;
                        }
                    }
                }
            } else {
                for (int i = 0; i < attributeA.size(); i++) {
                    String host4Address = (String) attributeA.get(i);
                    host4Address = host4Address.trim();
                    if (isValidIPv4(host4Address)) {
                        try {
                            InetAddress address = InetAddress.getByName(host4Address);
                            if (address.isLinkLocalAddress()) {
                                return false;
                            } else if (address.isLoopbackAddress()) {
                                return false;
                            }
                        } catch (UnknownHostException ex) {
                        }
                    } else {
                        return false;
                    }
                }
            }
            return true;
        } catch (NamingException ex) {
            return false;
        }
    }
    
    private static boolean ADVERTISEMENT_SHOW = true;
    
    public static void setShowAdvertisement(String show) {
        if (show != null && show.length() > 0) {
            try {
                setShowAdvertisement(Boolean.parseBoolean(show));
            } catch (Exception ex) {
                Server.logError("advertisement_show parameter '" + show + "' is invalid.");
            }
        }
    }
    
    public static void setShowAdvertisement(boolean show) {
        Core.ADVERTISEMENT_SHOW = show;
    }
    
    public static boolean showAdvertisement() {
        return ADVERTISEMENT_SHOW;
    }
    
    public static synchronized void setHostname(String hostame) {
        if (hostame != null && hostame.length() > 0) {
            if (!isHostname(hostame)) {
                Server.logError("invalid hostname '" + hostame + "'.");
            } else if (!Core.TESTING && !hostame.equals("localhost") && !isRouteable(hostame)) {
                Server.logError("unrouteable hostname '" + hostame + "'.");
            } else {
                Core.HOSTNAME = Domain.extractHost(hostame, false);
            }
        }
    }
    
    private static URI ACME_PROVIDER = null;
    private static String ACME_ORGANIZATION = null;
    private static String ACME_STATE = null;
    private static String ACME_COUNTRY = null;
    
    public static synchronized void setProviderACME(String provider) {
        if (provider != null) {
            provider = provider.trim();
            if (provider.length() > 0) {
                try {
                    Core.ACME_PROVIDER = new URI(provider);
                } catch (URISyntaxException ex) {
                    Server.logError("ACME provider URL '" + provider + "' is invalid.");
                }
            }
        }
    }
    
    public static synchronized void setOrganizationACME(String organization) {
        if (organization != null) {
            organization = organization.trim();
            while (organization.contains("  ")) {
                organization = organization.replace("  ", " ");
            }
            if (organization.length() > 0) {
                Core.ACME_ORGANIZATION = organization;
            }
        }
    }
    
    public static synchronized void setStateACME(String state) {
        if (state != null) {
            state = state.toUpperCase().trim();
            while (state.contains("  ")) {
                state = state.replace("  ", " ");
            }
            if (state.length() > 0) {
                Core.ACME_STATE = state;
            }
        }
    }
    
    public static synchronized void setCountryACME(String country) {
        if (country != null) {
            country = country.toUpperCase().trim();
            while (country.contains("  ")) {
                country = country.replace("  ", " ");
            }
            if (country.length() > 0) {
                if (country.length() == 2 && Character.isLetter(country.charAt(0)) && Character.isLetter(country.charAt(1))) {
                    Core.ACME_COUNTRY = country;
                } else {
                    Server.logError("ACME country '" + country + "' is invalid.");
                }
            }
        }
    }
    
    public static URI getProviderACME() {
        return ACME_PROVIDER;
    }
    
    public static boolean hasProviderACME() {
        return ACME_PROVIDER != null;
    }
    
    public static String getOrganizationACME() {
        return ACME_ORGANIZATION;
    }
    
    public static String getStateACME() {
        return ACME_STATE;
    }
    
    public static String getCountryACME() {
        return ACME_COUNTRY;
    }
    
    private static boolean hasInterface(String netInterface) {
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)) {
                if (netInterface.equals(netint.getName())) {
                    return true;
                }
            }
            return false;
        } catch (SocketException ex) {
            return false;
        }
    }
    
    public static synchronized void setInterface(String netInterface) {
        if (netInterface != null && netInterface.length() > 0) {
            if (hasInterface(netInterface)) {
                Core.INTERFACE = netInterface;
            } else {
                Server.logError("network interface '" + netInterface + "' not found.");
            }
        }
    }
    
    public static synchronized void setAdminEmail(String email) {
        if (email != null && email.length() > 0) {
            if (isValidEmail(email)) {
                Core.ADMIN_EMAIL = Domain.normalizeEmail(email);
            } else {
                Server.logError("invalid admin e-mail '" + email + "'.");
            }
        }
    }
    
    public static synchronized void setAbuseEmail(String email) {
        if (email != null && email.length() > 0) {
            if (isValidEmail(email)) {
                Core.ABUSE_EMAIL = email.toLowerCase();
            } else {
                Server.logError("invalid abuse e-mail '" + email + "'.");
            }
        }
    }
    
    public static void setPortADMIN(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortADMIN(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid ADMIN port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortADMIN(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid ADMIN port '" + port + "'.");
        } else {
            Core.PORT_ADMIN = (short) port;
        }
    }
    
    public static void setPortADMINS(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortADMINS(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid ADMINS port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortADMINS(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid ADMINS port '" + port + "'.");
        } else {
            Core.PORT_ADMINS = (short) port;
        }
    }
    
    public static void setPortSPFBL(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortSPFBL(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid SPFBL port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortSPFBL(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid SPFBL port '" + port + "'.");
        } else {
            Core.PORT_SPFBL = (short) port;
        }
    }
    
    public static void setPortSPFBLS(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortSPFBLS(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid SPFBLS port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortSPFBLS(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid SPFBLS port '" + port + "'.");
        } else {
            Core.PORT_SPFBLS = (short) port;
        }
    }
    
    public static void setPortDNSBL(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortDNSBL(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid DNSBL port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortDNSBL(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid DNSBL port '" + port + "'.");
        } else {
            Core.PORT_DNSBL = (short) port;
        }
    }
    
    public static void setPortHTTP(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortHTTP(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid HTTP port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortHTTP(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid HTTP port '" + port + "'.");
        } else {
            Core.PORT_HTTP = (short) port;
        }
    }
    
    public static void setPortHTTPS(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortHTTPS(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid HTTPS port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortHTTPS(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid HTTPS port '" + port + "'.");
        } else {
            Core.PORT_HTTPS = (short) port;
        }
    }
    
    public static void setPortESMTP(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortESMTP(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid ESMTP port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortESMTP(int port) {
        if (port != 25) {
            Server.logError("invalid ESMTP port '" + port + "'.");
        } else {
            Core.PORT_ESMTP = (short) port;
        }
    }
    
    public static void setPortESMTPS(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortESMTPS(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid ESMTPS port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortESMTPS(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid ESMTPS port '" + port + "'.");
        } else {
            Core.PORT_ESMTPS = (short) port;
        }
    }
    
    public static void setMaxUDP(String max) {
        if (max != null && max.length() > 0) {
            try {
                setMaxUDP(Integer.parseInt(max));
            } catch (Exception ex) {
                Server.logError("invalid UDP max size '" + max + "'.");
            }
        }
    }
    
    public static synchronized void setMaxUDP(int max) {
        if (max < 128 || max > Short.MAX_VALUE) {
            Server.logError("invalid UDP max size '" + max + "'.");
        } else {
            Core.UDP_MAX = (short) max;
        }
    }
    
    public static void setLevelLOG(String level) {
        if (level != null && level.length() > 0) {
            try {
                Core.LOG_LEVEL = Core.Level.valueOf(level);
            } catch (Exception ex) {
                Server.logError("invalid LOG level '" + level + "'.");
            }
        }
    }
    
    public static boolean setLevelLOG(Level level) {
        if (level == null) {
            return false;
        } else if (level == Core.LOG_LEVEL) {
            return false;
        } else {
            Core.LOG_LEVEL = level;
            return true;
        }
    }
    
    private static class ApplicationMessageHandler implements MessageHandler {
        @Override
        public synchronized String handle(String message) {
            if (message.equals("register")) {
                Server.logInfo("another instance of this application tried to start.");
            }
            return null;
        }
    }
    
    private static byte DEFER_TIME_SOFTFAIL = 1;
    
    public static byte getDeferTimeSOFTFAIL() {
        return DEFER_TIME_SOFTFAIL;
    }
    
    public static void setDeferTimeSOFTFAIL(String time) {
        if (time != null && time.length() > 0) {
            try {
                setDeferTimeSOFTFAIL(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid DEFER time for SOFTFAIL '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setDeferTimeSOFTFAIL(int time) {
        if (time < 0 || time > Byte.MAX_VALUE) {
            Server.logError("invalid DEFER time for SOFTFAIL '" + time + "'.");
        } else {
            Core.DEFER_TIME_SOFTFAIL = (byte) time;
        }
    }
    
    private static byte DEFER_TIME_YELLOW = 25;
    
    public static byte getDeferTimeYELLOW() {
        return DEFER_TIME_YELLOW;
    }
    
    public static void setDeferTimeYELLOW(String time) {
        if (time != null && time.length() > 0) {
            try {
                setDeferTimeYELLOW(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid DEFER time for YELLOW '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setDeferTimeYELLOW(int time) {
        if (time < 0 || time > Byte.MAX_VALUE) {
            Server.logError("invalid DEFER time for YELLOW '" + time + "'.");
        } else {
            Core.DEFER_TIME_YELLOW = (byte) time;
        }
    }
    
    private static short DEFER_TIME_RED = 1435;
    
    public static short getDeferTimeRED() {
        return DEFER_TIME_RED;
    }
    
    public static void setDeferTimeRED(String time) {
        if (time != null && time.length() > 0) {
            try {
                setDeferTimeRED(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid DEFER time for RED '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setDeferTimeRED(int time) {
        if (time < 0 || time > Short.MAX_VALUE) {
            Server.logError("invalid DEFER time for RED '" + time + "'.");
        } else {
            Core.DEFER_TIME_RED = (short) time;
        }
    }
    
    private static short DEFER_TIME_HOLD = 7175;
    
    public static short getDeferTimeHOLD() {
        return DEFER_TIME_HOLD;
    }
    
    public static void setDeferTimeHOLD(String time) {
        if (time != null && time.length() > 0) {
            try {
                setDeferTimeHOLD(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid DEFER time for HOLD '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setDeferTimeHOLD(int time) {
        if (time < 0 || time > Short.MAX_VALUE) {
            Server.logError("invalid DEFER time for HOLD '" + time + "'.");
        } else {
            Core.DEFER_TIME_HOLD = (short) time;
        }
    }
    
    private static String RECAPTCHA_KEY_SITE = null;
    private static String RECAPTCHA_KEY_SECRET = null;
    
    public static boolean hasRecaptchaKeys() {
        return RECAPTCHA_KEY_SITE != null && RECAPTCHA_KEY_SECRET != null;
    }
    
    public static String getRecaptchaKeySite() {
        return RECAPTCHA_KEY_SITE;
    }
    
    public static void setRecaptchaKeySite(String key) {
        if (key != null && key.length() > 0) {
            if (key.matches("^[0-9a-zA-Z_-]+$")) {
                RECAPTCHA_KEY_SITE = key;
            } else {
                Server.logError("invalid reCAPTCHA key site '" + key + "'.");
            }
        }
    }
    
    public static String getRecaptchaKeySecret() {
        return RECAPTCHA_KEY_SECRET;
    }
    
    public static void setRecaptchaKeySecret(String key) {
        if (key != null && key.length() > 0) {
            if (key.matches("^[0-9a-zA-Z_-]+$")) {
                RECAPTCHA_KEY_SECRET = key;
            } else {
                Server.logError("invalid reCAPTCHA key secret '" + key + "'.");
            }
        }
    }
    
    private static String DKIM_SELECTOR = null;
    private static PrivateKey DKIM_PRIVATE = null;
    
    public static synchronized void setSelectorDKIM(String selector) {
        if (selector != null && selector.length() > 0) {
            if (isHostname(selector)) {
                Core.DKIM_SELECTOR = Domain.normalizeHostname(selector, false);
            } else {
                Server.logError("invalid DKIM selector '" + selector + "'.");
            }
        }
    }
    
    public static synchronized void setPrivateDKIM(String privateKey) {
        if (privateKey != null && privateKey.length() > 0) {
            try {
                byte[] privateKeyBytes = BASE64STANDARD.decode(privateKey);
                PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                Core.DKIM_PRIVATE = kf.generatePrivate(encodedKeySpec);
            } catch (Exception ex) {
                Server.logError("invalid DKIM private key '" + privateKey + "'.");
            }
        }
    }
    
    private static short INEXISTENT_EXPIRES = 180;
    
    public static synchronized void setInexistentExpires(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setInexistentExpires(Integer.parseInt(expires));
            } catch (Exception ex) {
                Server.logError("invalid inexistent expires integer value '" + expires + "'.");
            }
        }
    }
    
    public static synchronized void setInexistentExpires(int expires) {
        if (expires < 1 || expires > Short.MAX_VALUE) {
            Server.logError("invalid inexistent expires integer value '" + expires + "'.");
        } else {
            Core.INEXISTENT_EXPIRES = (short) expires;
        }
    }
    
    public static long getInexistentExpiresMillis() {
        return Core.INEXISTENT_EXPIRES * Server.DAY_TIME;
    }
    
    private static boolean SMTP_IS_AUTH = true;
    private static boolean SMTP_STARTTLS = true;
    private static String SMTP_HOST = null;
    private static short SMTP_PORT = 465;
    private static String SMTP_USER = null;
    private static String SMTP_PASSWORD = null;
    
    public static void setPortSMTP(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortSMTP(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid SMTP port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortSMTP(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid SMTP port '" + port + "'.");
        } else {
            Core.SMTP_PORT = (short) port;
        }
    }
    
    public static void setIsAuthSMTP(String auth) {
        if (auth != null && auth.length() > 0) {
            try {
                setIsAuthSMTP(Boolean.parseBoolean(auth));
            } catch (Exception ex) {
                Server.logError("invalid SMTP is auth '" + auth + "'.");
            }
        }
    }
    
    public static synchronized void setIsAuthSMTP(boolean auth) {
        Core.SMTP_IS_AUTH = auth;
    }
    
    public static void setStartTLSSMTP(String startTLS) {
        if (startTLS != null && startTLS.length() > 0) {
            try {
                setStartTLSSMTP(Boolean.parseBoolean(startTLS));
            } catch (Exception ex) {
                Server.logError("invalid SMTP start TLS '" + startTLS + "'.");
            }
        }
    }
    
    public static synchronized void setStartTLSSMTP(boolean startTLS) {
        Core.SMTP_STARTTLS = startTLS;
    }
    
    public static synchronized void setHostSMTP(String host) {
        if (host != null && host.length() > 0) {
            if (isValidIP(host)) {
                Core.SMTP_HOST = Subnet.normalizeIP(host);
            } else if (isHostname(host)) {
                Core.SMTP_HOST = Domain.normalizeHostname(host, false);
            } else {
                Server.logError("invalid SMTP hostname '" + host + "'.");
            }
        }
    }
    
    public static synchronized void setUserSMTP(String user) {
        if (user != null && user.length() > 0) {
            if (isValidEmail(user) || isHostname(user)) {
                Core.SMTP_USER = user;
            } else {
                Server.logError("invalid SMTP user '" + user + "'.");
            }
        }
    }
    
    public static synchronized void setPasswordSMTP(String password) {
        if (password != null && password.length() > 0) {
            if (password.contains(" ")) {
                Server.logError("invalid SMTP password '" + password + "'.");
            } else {
                Core.SMTP_PASSWORD = password;
            }
        }
    }
    
    private static final short REPUTATION_LIMIT = 256;
    
    public static short getReputationLimit() {
        return REPUTATION_LIMIT;
    }
    
    private static final DecimalFormat CENTENA_FORMAT = new DecimalFormat("000");
    
    public static final NumberFormat DECIMAL_FORMAT = NumberFormat.getNumberInstance();
    
    public static final NumberFormat PERCENT_FORMAT = NumberFormat.getPercentInstance();
    
    public static final SimpleDateFormat SQL_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    
    public static synchronized String formatCentena(Number value) {
        if (value == null) {
            return null;
        } else {
            return CENTENA_FORMAT.format(value);
        }
    }
    
    /**
     * Constante para formatar datas com hora no padrão de e-mail.
     */
    private static final SimpleDateFormat DATE_EMAIL_FULL_FORMATTER = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US);
    
    public static synchronized String getEmailDate() {
        return DATE_EMAIL_FULL_FORMATTER.format(new Date());
    }
    
    public static String getEmailDate(long timeMillis) {
        if (timeMillis == 0) {
            return null;
        } else {
            return getEmailDate(new Date(timeMillis));
        }
    }
    
    public static synchronized String getEmailDate(Date date) {
        if (date == null) {
            return null;
        } else {
            return DATE_EMAIL_FULL_FORMATTER.format(date);
        }
    }
    
    /**
     * Constante para formatar datas com hora no padrão de e-mail.
     */
    private static final SimpleDateFormat DATE_EMAIL_FULL_PARSER = new SimpleDateFormat("EEE, dd MMM yy HH:mm:ss Z", Locale.US);
    private static final SimpleDateFormat DATE_EMAIL_SHORT_PARSER = new SimpleDateFormat("dd MMM yy HH:mm:ss Z", Locale.US);
    
    public static synchronized String formatEmailDate(long time) {
        return DATE_EMAIL_FULL_PARSER.format(new Date(time));
    }
    
    public static synchronized String formatEmailDate(Date date) {
        if (date == null) {
            return null;
        } else {
            return DATE_EMAIL_FULL_PARSER.format(date);
        }
    }
    
    public static synchronized Date parseEmailDate(String date) throws ParseException {
        if (date == null) {
            return null;
        } else {
            return DATE_EMAIL_FULL_PARSER.parse(date);
        }
    }
    
    public static synchronized Date parseEmailShortDate(String date) throws ParseException {
        if (date == null) {
            return null;
        } else {
            return DATE_EMAIL_SHORT_PARSER.parse(date);
        }
    }
    
    public static long parseEmailDateLong(String date) {
        Date dateObj = parseEmailDateSafe(date);
        if (dateObj == null) {
            return 0;
        } else {
            return dateObj.getTime();
        }
    }
    
    public static Date parseEmailDateSafe(String date) {
        if (date == null) {
            return null;
        } else {
            try {
                return parseEmailDate(date);
            } catch (ParseException ex) {
                try {
                    int index = date.indexOf(',') + 1;
                    date = date.substring(index).trim();
                    return parseEmailShortDate(date);
                } catch (ParseException ex2) {
                    return null;
                }
            }
        }
    }
    
    public static boolean hasOutputSMTP() {
        if (isDirectSMTP()) {
            return true;
        } else if (hasRelaySMTP()) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDirectSMTP() {
        if (SMTP_HOST == null) {
            return false;
        } else {
            return SMTP_HOST.equals(HOSTNAME);
        }
    }
    
    public static boolean hasRelaySMTP() {
        if (SMTP_HOST == null) {
            return false;
        } else if (SMTP_IS_AUTH && SMTP_USER == null) {
            return false;
        } else if (SMTP_IS_AUTH && SMTP_PASSWORD == null) {
            return false;
        } else {
            return true;
        }
    }
    
    public static DKIMSigner getDKIMSigner() {
        if (ADMIN_EMAIL == null) {
            return null;
        } else if (DKIM_SELECTOR == null) {
            return null;
        } else if (DKIM_PRIVATE == null) {
            return null;
        } else {
            try {
                final String DKIM_DOMAIN = Domain.extractHost(ADMIN_EMAIL, false);
                DKIMSigner dkimSigner = new DKIMSigner(DKIM_DOMAIN, DKIM_SELECTOR, DKIM_PRIVATE);
                dkimSigner.setIdentity(ADMIN_EMAIL);
                dkimSigner.setHeaderCanonicalization(Canonicalization.SIMPLE);
                dkimSigner.setBodyCanonicalization(Canonicalization.RELAXED);
                dkimSigner.setLengthParam(true);
                dkimSigner.setSigningAlgorithm(SigningAlgorithm.SHA1withRSA);
//                dkimSigner.setZParam(true); // Debug
                dkimSigner.addHeaderToSign("List-Unsubscribe");
                dkimSigner.addHeaderToSign("Reply-To");
                dkimSigner.addHeaderToSign("Date");
                return dkimSigner;
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static MimeMessage newMessage(boolean invitation) throws Exception {
        Properties props = new Properties();
        props.putAll(System.getProperties());
        Session session = Session.getInstance(props);
        DKIMSigner dkimSigner;
        MimeMessage message;
        if (!isDirectSMTP()) {
            message = new SPFBLMimeMessage(session);
        } else if ((dkimSigner = getDKIMSigner()) == null) {
            message = new SPFBLMimeMessage(session);
        } else {
            message = new DKIMMimeMessage(session, dkimSigner);
        }
        InternetAddress adminAddress = Core.getAdminInternetAddress();
        message.setFrom(adminAddress);
        if (invitation) {
            User user = User.getUserFor(adminAddress);
            InternetAddress[] replyTo = User.getInvitationArray(user, adminAddress);
            if (replyTo != null) {
                message.setReplyTo(replyTo);
            }
        }
        message.setHeader("Date", Core.getEmailDate());
        return message;
    }
    
    public static Object getLastResponse(
            Locale locale, Message message, int timeout
    ) throws Exception {
        if (message == null) {
            return null;
        } else if (isDirectSMTP()) {
            Server.logSendSMTP("authenticate: false.");
            Server.logSendSMTP("start TLS: true.");
            Properties props = new Properties();
            props.putAll(System.getProperties());
            props.put("mail.smtp.auth", "false");
            props.put("mail.smtp.port", "25");
            props.put("mail.smtp.timeout", Integer.toString(timeout));   
            props.put("mail.smtp.connectiontimeout", "3000");
            
            ArrayList<InternetAddress> recipientList = new ArrayList<>();
            for (Address address : message.getAllRecipients()) {
                if (address instanceof InternetAddress) {
                    recipientList.add((InternetAddress) address);
                }
            }
            InternetAddress[] recipients = recipientList.toArray(new InternetAddress[recipientList.size()]);
            Exception lastException = null;
            MailConnectException mailConnectException = null;
            SendFailedException sendFailedException = null;
            MessagingException messagingException = null;
            for (InternetAddress recipient : recipients) {
                String email = recipient.getAddress();
                if (NoReply.isUnsubscribed(email)) {
                    Server.logSendSMTP("the recipient '" + email +  "' is unsubscribed.");
                    return false;
                } else {
                    Server.logSendSMTP("sending message to " + recipient + ".");
                    String domain = Domain.normalizeHostname(email, false);
                    String url = Core.getListUnsubscribeURL(locale, recipient);
                    if (url != null) {
                        message.setHeader("List-Unsubscribe", "<" + url + ">");
                    }
                    message.saveChanges();
                    try {
                        for (String mx : Reverse.getMXSet(domain, false)) {
                            props.put("mail.smtp.starttls.enable", "true");
                            props.put("mail.smtp.host", mx);
                            props.put("mail.smtp.ssl.trust", mx);
                            InternetAddress[] recipientAlone = new InternetAddress[1];
                            recipientAlone[0] = (InternetAddress) recipient;
                            Session session = Session.getInstance(props);
                            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
                            try {
                                transport.setLocalHost(HOSTNAME);
                                Server.logSendSMTP("connecting to " + mx + ":25.");
                                transport.connect(mx, 25, null, null);
                                Server.logSendSMTP("sending '" + message.getSubject() + "' to " + recipient + ".");
                                transport.sendMessage(message, recipientAlone);
                                Server.logSendSMTP("message '" + message.getSubject() + "' sent to " + recipient + ".");
                                Server.logSendSMTP("last response: " + transport.getLastServerResponse());
                                String response = transport.getLastServerResponse();
                                return mx + ": " + response;
                            } catch (MailConnectException ex) {
                                Server.logSendSMTP("connection failed.");
                                mailConnectException = ex;
                            } catch (SendFailedException ex) {
                                Server.logSendSMTP("send failed.");
                                Server.logSendSMTP("last response: " + transport.getLastServerResponse());
                                sendFailedException = ex;
                            } catch (MessagingException ex) {
                                Server.logSendSMTP("last response: " + transport.getLastServerResponse());
                                if (transport.isConnected()) {
                                    transport.close();
                                    Server.logSendSMTP("connection closed.");
                                }
                                messagingException = ex;
                                Server.logInfo("sending e-mail message without TLS.");
                                props.put("mail.smtp.starttls.enable", "false");
                                session = Session.getInstance(props);
                                transport = (SMTPTransport) session.getTransport("smtp");
                                try {
                                    transport.setLocalHost(HOSTNAME);
                                    Server.logSendSMTP("connecting to " + mx + ":25.");
                                    transport.connect(mx, 25, null, null);
                                    Server.logSendSMTP("sending '" + message.getSubject() + "' to " + recipient + ".");
                                    transport.sendMessage(message, recipientAlone);
                                    Server.logSendSMTP("message '" + message.getSubject() + "' sent to " + recipient + ".");
                                    Server.logSendSMTP("last response: " + transport.getLastServerResponse());
                                    String response = transport.getLastServerResponse();
                                    return mx + ": " + response;
                                } catch (SendFailedException ex2) {
                                    Server.logSendSMTP("send failed.");
                                    Server.logSendSMTP("last response: " + transport.getLastServerResponse());
                                    sendFailedException = ex2;
                                } catch (MessagingException ex2) {
                                    messagingException = ex2;
                                } catch (Exception ex2) {
                                    lastException = ex2;
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                                lastException = ex;
                            } finally {
                                if (transport.isConnected()) {
                                    transport.close();
                                    Server.logSendSMTP("connection closed.");
                                }
                            }
                        }
                    } catch (NamingException ex) {
                        lastException = ex;
                    }
                }
            }
            if (messagingException != null) {
                throw messagingException;
            } else if (sendFailedException != null) {
                throw sendFailedException;
            } else if (mailConnectException!= null) {
                throw mailConnectException;
            } else if (lastException != null) {
                throw lastException;
            } else {
                return false;
            }
        } else if (hasRelaySMTP()) {
            Address[] recipients = message.getAllRecipients();
            TreeSet<String> recipientSet = new TreeSet<>();
            for (Address recipient : recipients) {
                recipientSet.add(recipient.toString());
            }
            Server.logSendSMTP("sending message to " + recipientSet + ".");
            Server.logSendSMTP("authenticate: " + Boolean.toString(SMTP_IS_AUTH) + ".");
            Server.logSendSMTP("start TLS: " + Boolean.toString(SMTP_STARTTLS) + ".");
            Properties props = new Properties();
            props.putAll(System.getProperties());
            props.put("mail.smtp.auth", Boolean.toString(SMTP_IS_AUTH));
            props.put("mail.smtp.starttls.enable", Boolean.toString(SMTP_STARTTLS));
            props.put("mail.smtp.host", SMTP_HOST);
            props.put("mail.smtp.port", Short.toString(SMTP_PORT));
            props.put("mail.smtp.timeout", Integer.toString(timeout));   
            props.put("mail.smtp.connectiontimeout", "3000");
            props.put("mail.smtp.ssl.trust", SMTP_HOST);
            
            Session session = Session.getInstance(props);
            try (SMTPTransport transport = (SMTPTransport) session.getTransport("smtp")) {
                if (HOSTNAME != null) {
                    transport.setLocalHost(HOSTNAME);
                }
                Server.logSendSMTP("connecting to " + SMTP_HOST + ":" + SMTP_PORT + ".");
                transport.connect(SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD);
                Server.logSendSMTP("sending '" + message.getSubject() + "' to " + recipientSet + ".");
                transport.sendMessage(message, recipients);
                Server.logSendSMTP("message '" + message.getSubject() + "' sent to " + recipientSet + ".");
                return transport.getLastServerResponse();
            } catch (SendFailedException ex) {
                Server.logSendSMTP("send failed.");
                throw ex;
            } catch (AuthenticationFailedException ex) {
                Server.logSendSMTP("authentication failed.");
                return false;
            } catch (MailConnectException ex) {
                Server.logSendSMTP("connection failed.");
                return false;
            } catch (MessagingException ex) {
                Server.logSendSMTP("messaging failed.");
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            } finally {
                Server.logSendSMTP("connection closed.");
            }
        } else {
            return false;
        }
    }
    
    public static Properties[] getRelaySessionProperties() {
        if (hasRelaySMTP()) {
            Properties props = new Properties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.auth", Boolean.toString(SMTP_IS_AUTH));
            props.put("mail.smtp.starttls.enable", Boolean.toString(SMTP_STARTTLS));
            props.put("mail.smtp.host", SMTP_HOST);
            props.put("mail.smtp.port", Short.toString(SMTP_PORT));
            props.put("mail.smtp.timeout", "60000");   
            props.put("mail.smtp.connectiontimeout", "5000");
            props.put("mail.smtp.ssl.trust", SMTP_HOST);
            Properties[] propsArray = {props};
            return propsArray;
        } else {
            return null;
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Thread.currentThread().setName("SYSTEMCOR");
        try {
            String appId = Server.class.getCanonicalName();
            ApplicationMessageHandler messageHandler = new ApplicationMessageHandler();
            boolean alreadyRunning;
            try {
                JUnique.acquireLock(appId, messageHandler);
                alreadyRunning = false;
            } catch (AlreadyLockedException ex) {
                alreadyRunning = true;
            }
            if (alreadyRunning) {
                JUnique.sendMessage(appId, "register");
                System.exit(1);
            } else {
                loadConfiguration();
                Server.logInfo("starting server...");
                User.startIndex();
                Server.loadCache();
                try {
                    administrationTCP = new AdministrationTCP(PORT_ADMIN, PORT_ADMINS, HOSTNAME);
                    administrationTCP.start();
                } catch (BindException ex) {
                    Server.logError("system could not start because ADMIN port " + PORT_ADMIN + " is already in use.");
                    System.exit(1);
                }
                if (PORT_DNSBL > 0) {
                    if (HOSTNAME == null) {
                        Server.logInfo("DNSBL socket was not binded because no hostname was defined.");
                    } else {
                        try {
                            queryDNSBL = new ServerDNS(HOSTNAME, PORT_DNSBL);
                            queryDNSBL.start();
                        } catch (TextParseException ex) {
                            queryDNSBL = null;
                            Server.logError("DNSBL socket was not binded because the hostname '" + HOSTNAME + "' is not valid for DNS.");
                        } catch (BindException ex) {
                            queryDNSBL = null;
                            Server.logError("DNSBL socket was not binded because UDP port " + PORT_DNSBL + " is already in use.");
                        }
                    }
                }
                if (PORT_HTTP > 0) {
                    if (HOSTNAME == null) {
                        Server.logInfo("HTTP socket was not binded because no hostname was defined.");
                    } else {
                        try {
                            serviceHTTP = new ServerHTTP(HOSTNAME, PORT_HTTP, PORT_HTTPS);
                            serviceHTTP.start();
                        } catch (BindException ex) {
                            serviceHTTP = null;
                            Server.logError("HTTP socket was not binded because TCP port " + PORT_HTTP + " is already in use.");
                        }
                    }
                }
                if (PORT_ESMTP > 0) {
                    if (Core.isTestingVersion()) {
                        File deliveryFolder = new File("./delivery/");
                        File incomingFolder = new File("./incoming/");
                        if (!deliveryFolder.exists()) {
                            Server.logInfo("ESMTP socket was not binded because the delivery folder not exists.");
                        } else if (!deliveryFolder.isDirectory()) {
                            Server.logInfo("ESMTP socket was not binded because the delivery folder not exists.");
                        } else if (!incomingFolder.exists()) {
                            Server.logInfo("ESMTP socket was not binded because the incoming folder not exists.");
                        } else if (!incomingFolder.isDirectory()) {
                            Server.logInfo("ESMTP socket was not binded because the incoming folder not exists.");
                        } else if (HOSTNAME == null) {
                            Server.logInfo("ESMTP socket was not binded because no hostname was defined.");
                        } else if (ADMIN_EMAIL == null) {
                            Server.logInfo("ESMTP socket was not binded because no admin email was defined.");
                        } else {
                            try {
                                serviceESMTP = new ServerSMTP(HOSTNAME, PORT_ESMTPS, ADMIN_EMAIL);
                                serviceESMTP.start();
                            } catch (BindException ex) {
                                serviceESMTP = null;
                                Server.logError("ESMTP socket was not binded because TCP port " + PORT_ESMTP + " is already in use.");
                            }
                        }
                    } else {
                        Server.logInfo("ESMTP socket was not binded because it's an experimental implementation.");
                    }
                }
                if (PORT_SPFBL > 0) {
                    try {
                        querySPF = new ServerSPFBL(PORT_SPFBL, PORT_SPFBLS, HOSTNAME);
                        querySPF.start();
                    } catch (BindException ex) {
                        querySPF = null;
                        Server.logError("SPFBL socket was not binded because TCP port " + PORT_SPFBL + " is already in use.");
                    }
                    if (HOSTNAME == null) {
                        Server.logInfo("P2P socket was not binded because no hostname was defined.");
                    } else if (isRouteable(HOSTNAME)) {
                        try {
                            peerUDP = new ServerP2P(HOSTNAME, PORT_SPFBL, PORT_SPFBLS, UDP_MAX);
                            peerUDP.start();
                        } catch (BindException ex) {
                            peerUDP = null;
                            Server.logError("P2P socket was not binded because UDP port " + PORT_SPFBL + " is already in use.");
                        }
                    } else {
                        Server.logError("P2P socket was not binded because '" + HOSTNAME + "' is not a routeable hostname.");
                    }
                }
//                Core.startTimer();
                User.startThread();
                FQDN.startThread();
                CIDR.startThread();
                net.spfbl.data.SPF.startThread();
                DKIM.startThread();
                Dictionary.startThread();
                Block.startThread();
                Generic.startThread();
                Abuse.startThread();
                Analise.initProcess();
                net.spfbl.data.URI.startThread();
                Recipient.startThread();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
        }
    }
    
    /**
     * Timer que controla os processos em background.
     */
//    private static Timer TIMER = null;
    private static boolean running = true;

    public static void cancelTimer() {
        running = false;
//        if (TIMER != null) {
//            TIMER.cancel();
//        }
    }
    
    public static boolean isRunning() {
        return running;
    }
    
    public static String removerAcentuacao(String text) {
        if (text == null) {
            return null;
        } else {
            StringBuilder builder = new StringBuilder();
            for (char character : text.toCharArray()) {
                switch (character) {
                    case 'Á':
                    case 'À':
                    case 'Ã':
                    case 'Â':
                        character = 'A';
                        break;
                    case 'É':
                    case 'Ê':
                        character = 'E';
                        break;
                    case 'Í':
                        character = 'I';
                        break;
                    case 'Ó':
                    case 'Õ':
                    case 'Ô':
                        character = 'O';
                        break;
                    case 'Ú':
                        character = 'U';
                        break;
                    case 'Ç':
                        character = 'C';
                        break;
                    case 'á':
                    case 'à':
                    case 'ã':
                    case 'â':
                    case 'ª':
                        character = 'a';
                        break;
                    case 'é':
                    case 'ê':
                        character = 'e';
                        break;
                    case 'í':
                        character = 'i';
                        break;
                    case 'ó':
                    case 'õ':
                    case 'ô':
                    case 'º':
                        character = 'o';
                        break;
                    case 'ú':
                        character = 'u';
                        break;
                    case 'ç':
                        character = 'c';
                        break;
                }
                builder.append(character);
            }
            return builder.toString();
        }
    }
    
    public static boolean isValidOTP(String secret, int code) {
        if (secret == null) {
            return false;
        } else {
            byte[] buffer = new Base32().decode(secret);
            long index = getTimeIndexOTP();
            if (code == getCodeOTP(buffer, index - 2)) {
                return true;
            } else if (code == getCodeOTP(buffer, index - 1)) {
                return true;
            } else if (code == getCodeOTP(buffer, index)) {
                return true;
            } else if (code == getCodeOTP(buffer, index + 1)) {
                return true;
            } else if (code == getCodeOTP(buffer, index + 2)) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static String generateSecretOTP() {
        byte[] buffer = new byte[10];
        new SecureRandom().nextBytes(buffer);
        return new String(new Base32().encode(buffer));
    }
 
    private static long getTimeIndexOTP() {
        return System.currentTimeMillis() / 1000 / 30;
    }

    private static long getCodeOTP(byte[] secret, long timeIndex) {
        try {
            SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(timeIndex);
            byte[] timeBytes = buffer.array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(timeBytes);
            int offset = hash[19] & 0xf;
            long truncatedHash = hash[offset] & 0x7f;
            for (int i = 1; i < 4; i++) {
                truncatedHash <<= 8;
                truncatedHash |= hash[offset + i] & 0xff;
            }
            return (truncatedHash %= 1000000);
        } catch (Exception ex) {
            return 0;
        }
    }
    
    public static Integer getInteger(String text) {
        if (text == null) {
            return null;
        } else {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ex) {
                return null;
            }
        }
    }
    
    public static boolean equals(String text1, String text2) {
        if (text1 == null) {
            return text2 == null;
        } else {
            return text1.equals(text2);
        }
    }
    
    public static boolean equals(PublicKey key1, PublicKey key2) {
        if (key1 == null) {
            return key2 == null;
        } else if (key2 == null) {
            return false;
        } else {
            return equals(key1.getEncoded(), key2.getEncoded());
        }
    }
    
    public static boolean equals(SecretKey key1, SecretKey key2) {
        if (key1 == null) {
            return key2 == null;
        } else if (key2 == null) {
            return false;
        } else {
            return equals(key1.getEncoded(), key2.getEncoded());
        }
    }
    
    public static boolean equals(byte[] array1, byte[] array2) {
        if (array1 == null) {
            return array2 == null;
        } else if (array2 == null) {
            return false;
        } else if (array1.length == array2.length) {
            for (int i = 0; i < array1.length; i++) {
                if (array1[i] != array2[i]) {
                    return false;
                }
            }
            return true;
        } else {
            return false;
        }
    }
    
    private static final Runtime RUNTIME = Runtime.getRuntime();
    
    public static float relativeFreeMemory() {
        return (float) RUNTIME.freeMemory() / (float) RUNTIME.maxMemory();
    }
    
    public static boolean hasLowMemory() {
        return relativeFreeMemory() < 0.0625f;
    }
    
    private static final QRCodeWriter qrCodeWriter = new QRCodeWriter();

    public static File getQRCodeTempFile(String codigo) {
        try {
            File file = File.createTempFile(Long.toString(Server.getNewUniqueTime()), ".png");
            Server.logTrace("QRCode temp file created at " + file.getAbsolutePath() + ".");
            BitMatrix matrix = qrCodeWriter.encode(codigo, BarcodeFormat.QR_CODE, 256, 256);
            Server.logTrace("QRCode matrix created.");
            int width = matrix.getWidth();
            int height = matrix.getHeight();
            BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    if (!matrix.get(x, y)) {
                        image.setRGB(x, y, Color.WHITE.getRGB());
                    }
                }
            }
            Server.logTrace("writing image at QRCode temp file.");
            ImageIO.write(image, "PNG", file);
            file.deleteOnExit();
            return file;
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
//    public static Number getPositiveInteger(String text) {
//        if (hasOnlyDigits(text)) {
//            try {
//                return Byte.parseByte(text);
//            } catch (NumberFormatException ex1) {
//                try {
//                    return Short.parseShort(text);
//                } catch (NumberFormatException ex2) {
//                    try {
//                        return Integer.parseInt(text);
//                    } catch (NumberFormatException ex3) {
//                        try {
//                            return Long.parseLong(text);
//                        } catch (NumberFormatException ex4) {
//                            return new BigInteger(text);
//                        }
//                    }
//                }
//            }
//        } else {
//            return null;
//        }
//    }
//    
//    public static Number getPositiveInteger(byte[] byteArray) {
//        if (byteArray == null) {
//            return null;
//        } else if (byteArray.length == 0) {
//            return null;
//        } else if (byteArray.length < 4) {
//            int value = (byteArray[0] & 0xFF);
//            for (int i = 1; i < byteArray.length; i++) {
//                value <<= 8;
//                value += (byteArray[i] & 0xFF);
//            }
//            if (value > Short.MAX_VALUE) {
//                return value;
//            } else if (value > Byte.MAX_VALUE) {
//                return (short) value;
//            } else {
//                return (byte) value;
//            }
//        } else if (byteArray.length < 8) {
//            long value = (byteArray[0] & 0xFF);
//            for (int i = 1; i < byteArray.length; i++) {
//                value <<= 8;
//                value += (byteArray[i] & 0xFF);
//            }
//            if (value > Integer.MAX_VALUE) {
//                return value;
//            } else {
//                return (int) value;
//            }
//        } else {
//            BigInteger value = new BigInteger(1, byteArray);
//            try {
//                return value.longValueExact();
//            } catch (ArithmeticException ex) {
//                return value;
//            }
//        }
//    }
//    
//    public static byte[] getByteArray(Number value) {
//        if (value instanceof Byte) {
//            byte[] array = {(byte) value};
//            return array;
//        } else if (value instanceof Short) {
//            ByteBuffer buffer = ByteBuffer.allocate(2);
//            buffer.putShort((short) value);
//            return buffer.array();
//        } else if (value instanceof Integer) {
//            ByteBuffer buffer = ByteBuffer.allocate(4);
//            buffer.putInt((int) value);
//            return buffer.array();
//        } else if (value instanceof Long) {
//            ByteBuffer buffer = ByteBuffer.allocate(8);
//            buffer.putLong((long) value);
//            return buffer.array();
//        } else if (value instanceof BigInteger) {
//            return ((BigInteger)value).toByteArray();
//        } else {
//            return null;
//        }
//    }
    
    public static boolean isInteger(String text) {
        try {
            Integer.parseInt(text);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
    
    public static boolean isLong(String text) {
        try {
            Long.parseLong(text);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
    
    public static Long parseLong(String code, int radix) {
        if (code == null) {
            return null;
        } else {
            try {
                return Long.parseLong(code, radix);
            } catch (NumberFormatException ex) {
                return null;
            }
        }
    }
    
    public static boolean hasOnlyDigits(String text) {
        if (text == null) {
            return false;
        } else if (text.length() == 0) {
            return false;
        } else {
            for (char character : text.toCharArray()) {
                if (!Character.isDigit(character)) {
                    return false;
                }
            }
            return true;
        }
    }
    
    public static TreeSet<String> getTreeSet(String text, String demiliter) {
        if (text == null) {
            return null;
        } else if (demiliter == null) {
            return null;
        } else {
            TreeSet<String> resultSet = new TreeSet<>();
            StringTokenizer tokenizer = new StringTokenizer(
                    text, demiliter
            );
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                resultSet.add(token);
            }
            return resultSet;
        }
    }
    
    public static TreeMap<String,Boolean> getTreeMapBoolean(
            String text, String demiliter
    ) {
        if (text == null) {
            return null;
        } else if (demiliter == null) {
            return null;
        } else {
            TreeMap<String,Boolean> resultMap = new TreeMap<>();
            StringTokenizer tokenizer = new StringTokenizer(
                    text, demiliter
            );
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                int index = token.indexOf('=');
                if (index != -1) {
                    boolean value = Boolean.parseBoolean(token.substring(index + 1));
                    String key = token.substring(0, index);
                    resultMap.put(key, value);
                }
            }
            return resultMap;
        }
    }
    
    public static String getSequence(TreeSet<String> set, String demiliter) {
        if (set == null) {
            return null;
        } else if (demiliter == null) {
            return null;
        } else if (set.isEmpty()) {
            return null;
        } else {
            StringBuilder builder = new StringBuilder();
            for (String token : set) {
                if (builder.length() > 0) {
                    builder.append(demiliter);
                }
                builder.append(token);
            }
            return builder.toString();
        }
    }
    
    public static String getSequence(InternetAddress[] addresses, String demiliter) {
        if (addresses == null) {
            return null;
        } else if (demiliter == null) {
            return null;
        } else if (addresses.length == 0) {
            return null;
        } else {
            StringBuilder builder = new StringBuilder();
            for (InternetAddress address : addresses) {
                if (builder.length() > 0) {
                    builder.append(demiliter);
                }
                builder.append(address.getAddress());
            }
            return builder.toString();
        }
    }
    
    public static String getSequence(
            TreeMap<String,Boolean> map,
            String demiliter,
            int limit
    ) {
        if (map == null) {
            return null;
        } else if (demiliter == null) {
            return null;
        } else if (map.isEmpty()) {
            return null;
        } else {
            StringBuilder builder = new StringBuilder();
            for (String key : map.keySet()) {
                boolean value = map.get(key);
                String register = key + "=" + value;
                if (builder.length() > 0) {
                    register = demiliter + register;
                }
                if (builder.length() + register.length() > limit) {
                    break;
                } else {
                    builder.append(register);
                }
            }
            return builder.toString();
        }
    }
    
    public static boolean hasUnicodeBlock(String text, Character.UnicodeBlock block) {
        if (text == null) {
            return false;
        } else {
            for (char character : text.toCharArray()) {
                if (Character.UnicodeBlock.of(character) == block) {
                    return true;
                }
            }
            return false;
        }
    }
    
    private static final Locale LOCALE_BRAZIL = new Locale("pt", "BR");
    private static final Locale LOCALE_PORTUGAL = new Locale("pt", "PT");
    
    public static Locale getDefaultLocale(String address) {
        if (address == null) {
            return null;
        } else if (address.endsWith(".br")) {
            return LOCALE_BRAZIL;
        } else if (address.endsWith(".pt")) {
            return LOCALE_PORTUGAL;
        } else if (address.endsWith(".uk")) {
            return Locale.US;
        } else {
            return Locale.getDefault();
        }
    }
    
    public static TimeZone getDefaultTimeZone(String address) {
        if (address == null) {
            return null;
        } else if (address.endsWith(".br")) {
            return TimeZone.getTimeZone("America/Sao_Paulo");
        } else if (address.endsWith(".pt")) {
            return TimeZone.getTimeZone("Europe/Lisboa");
        } else if (address.endsWith(".uk")) {
            return TimeZone.getTimeZone("Europe/London");
        } else {
            return TimeZone.getDefault();
        }
    }
    
    public static URL getURL(String url) {
        if (url == null) {
            return null;
        } else {
            try {
                return new URL(url);
            } catch (MalformedURLException ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private static KeyPair SERVER_KEY_PAIR = null;
    
    public static KeyPair getServerKeyPair() {
        if (SERVER_KEY_PAIR == null) {
            File keypairFile = new File("./data/keypair.pem");
            try (FileReader fr = new FileReader(keypairFile)) {
                SERVER_KEY_PAIR = KeyPairUtils.readKeyPair(fr);
            } catch (FileNotFoundException ex) {
                SERVER_KEY_PAIR = KeyPairUtils.createKeyPair(2048);
                try (FileWriter fw = new FileWriter(keypairFile)) {
                    KeyPairUtils.writeKeyPair(SERVER_KEY_PAIR, fw);
                } catch (IOException ex2) {
                    SERVER_KEY_PAIR = null;
                    Server.logError(ex2);
                }
            } catch (IOException ex) {
                SERVER_KEY_PAIR = null;
                Server.logError(ex);
            }
        }
        return SERVER_KEY_PAIR;
    }
    
    private static KeyPair DOMAIN_KEY_PAIR = null;
    
    public static KeyPair getDomainKeyPair(String hostname) {
        if (DOMAIN_KEY_PAIR == null && hostname != null) {
            File keypairFile = new File("./data/" + hostname + ".pem");
            try (FileReader fr = new FileReader(keypairFile)) {
                DOMAIN_KEY_PAIR = KeyPairUtils.readKeyPair(fr);
            } catch (FileNotFoundException ex) {
                DOMAIN_KEY_PAIR = KeyPairUtils.createKeyPair(2048);
                try (FileWriter fw = new FileWriter(keypairFile)) {
                    KeyPairUtils.writeKeyPair(DOMAIN_KEY_PAIR, fw);
                } catch (IOException ex2) {
                    DOMAIN_KEY_PAIR = null;
                    Server.logError(ex2);
                }
            } catch (IOException ex) {
                DOMAIN_KEY_PAIR = null;
                Server.logError(ex);
            }
        }
        return DOMAIN_KEY_PAIR;
    }
    
    public static boolean storeKeyStore(KeyStore keyStore, String hostname) {
        try {
            long time = System.currentTimeMillis();
            File fileJKS = new File("./data/" + hostname + ".jks");
            try (FileOutputStream fos = new FileOutputStream(fileJKS)) {
                keyStore.store(fos, hostname.toCharArray());
            }
            Server.logStore(time, fileJKS);
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static final HashMap<String,KeyStore> KEYSTORE_MAP = new HashMap<>();
    
    public static synchronized void storeKeystoreMap() {
        for (String hostname : KEYSTORE_MAP.keySet()) {
            KeyStore keyStore = KEYSTORE_MAP.get(hostname);
            if (Core.validCertificate(keyStore, hostname)) {
                Core.storeKeyStore(keyStore, hostname);
            }
        }
    }
    
    public static synchronized KeyStore getKeyStore(String hostname) {
        if (hostname == null) {
            return null;
        } else {
            return KEYSTORE_MAP.get(hostname);
        }
    }
    
    public static synchronized KeyStore loadKeyStore(String hostname) {
        if (hostname == null) {
            return null;
        } else {
            try {
                KeyStore keyStore = KEYSTORE_MAP.get(hostname);
                if (keyStore == null) {
                    File fileJKS = new File("./data/" + hostname + ".jks");
                    if (fileJKS.exists()) {
                        keyStore = KeyStore.getInstance("JKS");
                        try (FileInputStream fis = new FileInputStream(fileJKS)) {
                            keyStore.load(fis, hostname.toCharArray());
                        }
                        if (validCertificate(keyStore, hostname)) {
                            KEYSTORE_MAP.put(hostname, keyStore);
                        } else {
                            keyStore = null;
                        }
                    }
                }
                if (keyStore == null) {
                    keyStore = KeyStore.getInstance("JKS");
                    File cacerts = new File(System.getProperty("java.home") + "/lib/security/cacerts");
                    try (FileInputStream localCertIn = new FileInputStream(cacerts)) {
                        keyStore.load(localCertIn, "changeit".toCharArray());
                    }
                    if (updateCertificate(keyStore, hostname)) {
                        storeKeyStore(keyStore, hostname);
                        KEYSTORE_MAP.put(hostname, keyStore);
                    } else {
                        keyStore = null;
                    }
                }
                return keyStore;
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private static boolean updateCertificate(KeyStore keyStore, String hostname) {
        if (requestCertificate(keyStore, hostname)) {
            removeExpiringCertificate(hostname);
            return true;
        } else {
            // TODO: manual certificate update.
            // TODO: load key pair and certificate chain.
            
//            KeyPair domainKeyPair = Core.getDomainKeyPair(hostname);
//            
//            X509Certificate[] chain = new X509Certificate[2];
//            chain[0] = certificate.download();
//            chain[1] = certificate.downloadChain()[0];
//
//            keyStore.setKeyEntry(hostname,
//                    domainKeyPair.getPrivate(),
//                    hostname.toCharArray(),
//                    chain
//            );
            return false;
        }
    }
    
    public static void waitStartHTTP() {
        if (serviceHTTP != null) {
            serviceHTTP.waitStart();
        }
    }
    
    public static boolean requestCertificate(KeyStore keyStore, String hostname) {
        String adminEmail = Core.getAdminEmail();
        URI provider = Core.getProviderACME();
        KeyPair serverKeyPair = Core.getServerKeyPair();
        if (keyStore == null) {
            return false;
        } else if (provider == null) {
            return false;
        } else if (hostname == null) {
            Server.logInfo("cannot request a certificate without a hostname.");
            return false;
        } else if (hostname.equals("localhost")) {
            Server.logInfo("cannot request a certificate for localhost.");
            return false;
        } else if (adminEmail == null) {
            Server.logInfo("cannot request a certificate without an admin e-mail.");
            return false;
        } else if (serverKeyPair == null) {
            Server.logInfo("cannot request a certificate without a server key pair.");
            return false;
        } else if (serviceHTTP == null) {
            Server.logInfo("cannot request a certificate without HTTP service.");
            return false;
        } else if (serviceHTTP.getPort() != 80) {
            Server.logInfo("cannot request a certificate because HTTP service is not binded at port 80.");
            return false;
        } else {
            try {
                Server.logAcme("requesting new certificate.");
                org.shredzone.acme4j.Session session =
                        new org.shredzone.acme4j.Session(
//                                "acme://letsencrypt.org/staging"
                                provider
                        );
                AccountBuilder accountBuilder = new AccountBuilder();
                accountBuilder.addContact("mailto:" + adminEmail);
                accountBuilder = accountBuilder.agreeToTermsOfService();
                accountBuilder = accountBuilder.useKeyPair(serverKeyPair);
                Account account = accountBuilder.create(session);
                Server.logAcme("registred as " + account.getLocation());
                
                OrderBuilder orderBuilder = account.newOrder();
                orderBuilder = orderBuilder.domain(hostname);
                Order order = orderBuilder.create();

                for (Authorization auth : order.getAuthorizations()) {
                    Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
                    if (challenge == null) {
                        Server.logAcme("no HTTP challenge option.");
                        return false;
                    } else {
                        serviceHTTP.setChallenge(challenge);
                        challenge.trigger(); // HTTP challenge trigger.
                        org.shredzone.acme4j.Status status;
                        do {
                            Thread.sleep(1000L);
                            challenge.update();
                        } while ((status = challenge.getStatus()) == org.shredzone.acme4j.Status.PROCESSING);
                        if (status == org.shredzone.acme4j.Status.VALID) {
                            auth.update();
                            Server.logAcme("autorization " + auth.getLocation());
                            KeyPair domainKeyPair = Core.getDomainKeyPair(hostname);
                            CSRBuilder csrb = new CSRBuilder();
                            csrb.addDomain(hostname);
                            csrb.setOrganization(Core.getOrganizationACME());
                            csrb.setState(Core.getStateACME());
                            csrb.setCountry(Core.getCountryACME());
                            csrb.sign(domainKeyPair);
                            byte[] csr = csrb.getEncoded();
                            order.execute(csr);
                            do {
                                Thread.sleep(1000);
                                order.update();
                            } while ((status = order.getStatus()) == org.shredzone.acme4j.Status.PROCESSING);
                            if (status == org.shredzone.acme4j.Status.VALID) {
                                Certificate certificate = order.getCertificate();
                                Server.logAcme("certification " + certificate.getLocation());

                                ArrayList<X509Certificate> certificateList = new ArrayList<>();
                                certificateList.add(certificate.getCertificate());
                                certificateList.addAll(certificate.getCertificateChain());

                                X509Certificate[] chain = new X509Certificate[certificateList.size()];
                                chain = certificateList.toArray(chain);

                                keyStore.setKeyEntry(
                                        hostname,
                                        domainKeyPair.getPrivate(),
                                        hostname.toCharArray(),
                                        chain
                                );
                                return true;
                            } else if (status == org.shredzone.acme4j.Status.INVALID) {
                                Server.logAcme("order invalid.");
                                return false;
                            } else {
                                Server.logAcme("order timeout.");
                                return false;
                            }
                        } else if (status == org.shredzone.acme4j.Status.INVALID) {
                            Server.logAcme("invalid challenge.");
                            return false;
                        } else if (status == org.shredzone.acme4j.Status.PENDING) {
                            Server.logAcme("pending challenge.");
                            Thread.sleep(3000L);
                            return requestCertificate(keyStore, hostname);
                        } else {
                            Server.logAcme("error to process challenge.");
                            return false;
                        }
                    }
                }
                Server.logAcme("no authorizations found.");
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    private static final HashSet<String> EXPIRING_SET = new HashSet<>();
    
    private static synchronized boolean removeExpiringCertificate(String token) {
        return EXPIRING_SET.remove(token);
    }
    
    private static synchronized boolean addExpiringCertificate(String token) {
        return EXPIRING_SET.add(token);
    }
    
    public static synchronized boolean isExpiringCertificate(String token) {
        return EXPIRING_SET.contains(token);
    }
    
    public static boolean validCertificate(KeyStore keyStore, String hostname) {
        if (keyStore == null) {
            return false;
        } else {
            try {
                java.security.cert.Certificate cert = keyStore.getCertificate(hostname);
                if (cert == null) {
                    Server.logInfo("no " + hostname + " certificate at keystore.");
                    return updateCertificate(keyStore, hostname);
                } else if (cert instanceof X509Certificate) {
                    X509Certificate X509cert = (X509Certificate) cert;
                    try {
                        GregorianCalendar calendar = new GregorianCalendar();
                        calendar.add(Calendar.DAY_OF_YEAR, 30);
                        X509cert.checkValidity(calendar.getTime());
                        Server.logInfo(hostname + " certificate is valid.");
                        removeExpiringCertificate(hostname);
                        return true;
                    } catch (CertificateExpiredException ex) {
                        try {
                            if (updateCertificate(keyStore, hostname)) {
                                return true;
                            } else {
                                X509cert.checkValidity();
                                if (ServerHTTP.sendCertificateExpirationAlert(hostname)) {
                                    Server.logInfo("certificate expiration alert for " + hostname + " sent by e-mail.");
                                } else {
                                    Server.logInfo(hostname + " certificate is valid but will expire soon.");
                                }
                                addExpiringCertificate(hostname);
                                return true;
                            }
                        } catch (CertificateExpiredException ex2) {
                            Server.logInfo("expired " + hostname + " certificate at keystore.");
                            return updateCertificate(keyStore, hostname);
                        } catch (CertificateNotYetValidException ex2) {
                            Server.logInfo("invalid " + hostname + " certificate at keystore.");
                            return updateCertificate(keyStore, hostname);
                        }
                    } catch (CertificateNotYetValidException ex) {
                        Server.logInfo("invalid " + hostname + " certificate at keystore.");
                        return updateCertificate(keyStore, hostname);
                    }
                } else {
                    Server.logInfo("invalid " + hostname + " certificate at keystore.");
                    return updateCertificate(keyStore, hostname);
                }
            } catch (KeyStoreException ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static byte[] compress(byte[] data) throws IOException {
        Deflater deflater = new Deflater();
        deflater.setLevel(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {
            deflater.finish();
            byte[] buffer = new byte[1024];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            return outputStream.toByteArray();
        }
    }
    
    public static String compressAsString(String data) throws IOException {
        if (data == null) {
            return null;
        } else {
            return compressAsString(data.getBytes());
        }
    }
    
    public static String compressAsString(byte[] data) throws IOException {
        return BASE64URLSAFE.encodeAsString(compress(data));
    }
    
    public static byte[] decompress(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {
            byte[] buffer = new byte[1024];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            return outputStream.toByteArray();
        }
    }
    
    public static String decompressAsStringSafe(String data) {
        try {
            return decompressAsString(data);
        } catch (Exception ex) {
            return null;
        }
    }
    
    public static String decompressAsString(String data) throws IOException, DataFormatException {
        return new String(decompress(data));
    }
    
    public static byte[] decompress(String data) throws IOException, DataFormatException {
        return decompress(BASE64URLSAFE.decode(data));
    }
    
    private static final Regex EXECUTABLE_SIGNATURE_PATTERN = new Regex("^"
            + "[0-9a-f]{32}\\.[0-9]+\\."
            + "(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|"
            + "hta|jar|ace|js|msi|sh|zip|7z|rar|gz|z|lzh|r13|doc|xls|"
            + "docx|docm|xlsx|xlsm|xlsb|html|pdf)"
            + "$"
    );
    
    public static boolean isExecutableSignature(String token) {
        if (token == null) {
            return false;
        } else {
            return EXECUTABLE_SIGNATURE_PATTERN.matches(token);
        }
    }
    
    public static final Regex URL_SIGNATURE_PATTERN = new Regex("^"
            + "([0-9a-f]{32}((\\.[a-z0-9_-]+)+)\\.([0-9]+)\\.(https?))"
            + "$"
    );
    
    public static boolean isSignatureURL(String token) {
        if (token == null) {
            return false;
        } else {
            return URL_SIGNATURE_PATTERN.matches(token);
        }
    }
    
    public static String getSignatureHostURL(String token) {
        if (token == null) {
            return null;
        } else {
            Matcher matcher = URL_SIGNATURE_PATTERN.createMatcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                if (isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                return host;
            } else {
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                return null;
            }
        }
    }
    
    public static String tryGetSignatureRootURL(String token) {
        String url = getSignatureRootURL(token);
        if (url == null) {
            return token;
        } else {
            return url;
        }
    }
    
    public static String getSignatureRootURL(String token) {
        if (token == null) {
            return null;
        } else {
            Matcher matcher = URL_SIGNATURE_PATTERN.createMatcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                if (isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                String port = matcher.group(4);
                String protocol = matcher.group(5);
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                if (protocol.equals("http") && port.equals("80")) {
                    port = "";
                } else if (protocol.equals("https") && port.equals("443")) {
                    port = "";
                } else {
                    port = ":" + port;
                }
                return protocol + "://" + host + port + "/";
            } else {
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                return null;
            }
        }
    }
    
    public static String getSignatureHostnameURL(String token) {
        if (token == null) {
            return null;
        } else {
            Matcher matcher = URL_SIGNATURE_PATTERN.createMatcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                if (isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                return host;
            } else {
                URL_SIGNATURE_PATTERN.offerMatcher(matcher);
                return null;
            }
        }
    }
    
    private static final Regex URL_SIG_PATTERN = new Regex("^"
            + "(https?)\\:\\/\\/([a-z0-9\\._-]+|\\[[a-f0-9\\:]+\\])(:([0-9]{1,6}))?"
            + "(\\/|\\?|#|$)"
    );
    
    private static final Regex URL_IPV6_PATTERN = new Regex(""
            + "^\\[([a-f0-9\\:]+)\\]"
            + "$"
    );
    
    public static boolean isValidURL(String url) {
        if (url == null) {
            return false;
        } else if (URL_SIG_PATTERN.matches(url)) {
            return true;
        } else {
            try {
                new URL(url);
                return true;
            } catch (MalformedURLException ex) {
                return false;
            }
        }
    }
    
    public static String md5Hex(String token) {
        if (token == null) {
            return null;
        } else {
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(token.getBytes());
                return md5Hex(md.digest());
            } catch (NoSuchAlgorithmException ex) {
                return null;
            }
        }
    }
    
    public static String md5Hex(byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
    
    public static String getSignature(URL url) {
        if (url == null) {
            return null;
        } else {
            return getSignatureURL(url.toString());
        }
    }
    
    public static String getSignatureURL(String url) {
        Matcher matcher = URL_SIG_PATTERN.createMatcher(url);
        if (matcher.find()) {
            String protocol = matcher.group(1).toLowerCase();
            String host = matcher.group(2).toLowerCase();
            String port = matcher.group(4);
            URL_SIG_PATTERN.offerMatcher(matcher);
            if (port == null) {
                if (protocol.equals("http")) {
                    port = "80";
                } else {
                    port = "443";
                }
            }
            if (isValidIPv4(host)) {
                host = SubnetIPv4.reverseToIPv4(host);
            } else {
                matcher = URL_IPV6_PATTERN.createMatcher(host);
                if (matcher.find() && isValidIPv6(matcher.group(1))) {
                    host = SubnetIPv6.reverseToIPv6(matcher.group(1));
                }
                URL_IPV6_PATTERN.offerMatcher(matcher);
            }
            int index = url.indexOf('?');
            if (index > 0) {
                url = url.substring(0, index);
            }
            String signature = md5Hex(url);
            return signature + "." + host + "." + port + "." + protocol;
        } else {
            URL_SIG_PATTERN.offerMatcher(matcher);
            return null;
        }
    }
    
    public static String getHostnameURL(String url) {
        Matcher matcher = URL_SIG_PATTERN.createMatcher(url);
        if (matcher.find()) {
            return matcher.group(2).toLowerCase();
        } else {
            return null;
        }
    }
    
    private static final Regex URL_SHORTENER_PATTERN = new Regex(
            "^(https?)\\:\\/\\/(1link\\.in|1url\\.com|2big\\.at|2pl\\.us|"
                    + "2tu\\.us|2ya\\.com|4url\\.cc|6url\\.com|a\\.gg|a\\.nf|"
                    + "a2a\\.me|abbrr\\.com|adf\\.ly|adjix\\.com|alturl\\.com|"
                    + "atu\\.ca|b23\\.ru|bacn\\.me|bc\\.vc|bit\\.do|bit\\.ly|"
                    + "bitly\\.com|bkite\\.com|bloat\\.me|budurl\\.com|buk\\.me|"
                    + "burnurl\\.com|buzurl\\.com|c-o\\.in|chilp\\.it|clck\\.ru|"
                    + "cli\\.gs|clickmeter\\.com|cort\\.as|cur\\.lv|cutt\\.us|"
                    + "cuturl\\.com|db\\.tt|decenturl\\.com|dfl8\\.me|"
                    + "digbig\\.com|digg\\.com|doiop\\.com|dwarfurl\\.com|"
                    + "dy\\.fi|easyuri\\.com|easyurl\\.net|eepurl\\.com|"
                    + "esyurl\\.com|ewerl\\.com|fa\\.b|ff\\.im|fff\\.to|"
                    + "fhurl\\.com|filoops\\.info|fire\\.to|firsturl\\.de|"
                    + "flic\\.kr|fly2\\.ws|fon\\.gs|fwd4\\.me|gl\\.am|"
                    + "go\\.9nl\\.com|go2\\.me|go2cut\\.com|goo\\.gl|"
                    + "goshrink\\.com|gowat\\.ch|gri\\.ms|gurl\\.es|"
                    + "hellotxt\\.com|hex\\.io|hover\\.com|href\\.in|"
                    + "htxt\\.it|hugeurl\\.com|hurl\\.it|hurl\\.me|"
                    + "hurl\\.ws|icanhaz\\.com|idek\\.net|inreply\\.to|"
                    + "is\\.gd|iscool\\.net|iterasi\\.net|ity\\.im|"
                    + "j\\.mp|jijr\\.com|jmp2\\.net|just\\.as|kissa\\.be|"
                    + "kl\\.am|klck\\.me|korta\\.nu|krunchd\\.com|liip\\.to|"
                    + "liltext\\.com|lin\\.cr|link\\.zip\\.net|linkbee\\.com|"
                    + "linkbun\\.ch|liurl\\.cn|ln-s\\.net|ln-s\\.ru|lnk\\.gd|"
                    + "lnk\\.in|lnkd\\.in|loopt\\.us|lru\\.jp|lt\\.tl|"
                    + "lurl\\.no|metamark\\.net|migre\\.me|minilien\\.com|"
                    + "miniurl\\.com|minurl\\.fr|moourl\\.com|myurl\\.in|"
                    + "ne1\\.net|njx\\.me|nn\\.nf|notlong\\.com|nsfw\\.in|"
                    + "o-x\\.fr|om\\.ly|ow\\.ly|pd\\.am|pic\\.gd|ping\\.fm|"
                    + "piurl\\.com|pnt\\.me|po\\.st|poprl\\.com|post\\.ly|"
                    + "posted\\.at|prettylinkpro\\.com|profile\\.to|q\\.gs|"
                    + "qicute\\.com|qlnk\\.net|qr\\.ae|qr\\.net|quip-art\\.com|"
                    + "rb6\\.me|redirx\\.com|ri\\.ms|rickroll\\.it|riz\\.gd|"
                    + "rsmonkey\\.com|ru\\.ly|rubyurl\\.com|s7y\\.us|safe\\.mn|"
                    + "scrnch\\.me|sharein\\.com|sharetabs\\.com|shorl\\.com|"
                    + "short\\.ie|short\\.to|shortlinks\\.co\\.uk|shortna\\.me|"
                    + "shorturl\\.com|shoturl\\.us|shrinkify\\.com|"
                    + "shrinkster\\.com|shrt\\.st|shrten\\.com|shrunkin\\.com|"
                    + "shw\\.me|simurl\\.com|sn\\.im|snipr\\.com|snipurl\\.com|"
                    + "snurl\\.com|sp2\\.ro|spedr\\.com|sqrl\\.it|"
                    + "starturl\\.com|sturly\\.com|su\\.pr|t\\.co|tcrn\\.ch|"
                    + "thrdl\\.es|tighturl\\.com|tiny\\.cc|tiny\\.pl|"
                    + "tiny123\\.com|tinyarro\\.ws|tinyarrows\\.com|"
                    + "tinytw\\.it|tinyuri\\.ca|tinyurl\\.com|tinyvid\\.io|"
                    + "tnij\\.org|to\\.ly|togoto\\.us|tr\\.im|tr\\.my|"
                    + "traceurl\\.com|turo\\.us|tweetburner\\.com|tweez\\.me|"
                    + "twirl\\.at|twit\\.ac|twitterpan\\.com|twitthis\\.com|"
                    + "twiturl\\.de|twurl\\.cc|twurl\\.nl|u\\.bb|"
                    + "u\\.mavrev\\.com|u\\.nu|u\\.to|u6e\\.de|ub0\\.cc|"
                    + "updating\\.me|ur1\\.ca|url\\.co\\.uk|url\\.ie|"
                    + "url4\\.eu|urlao\\.com|urlbrief\\.com|urlcover\\.com|"
                    + "urlcut\\.com|urlenco\\.de|urlhawk\\.com|urlkiss\\.com|"
                    + "urlot\\.com|urlpire\\.com|urlx\\.ie|urlx\\.org|"
                    + "urlzen\\.com|v\\.gd|virl\\.com|vl\\.am|vzturl\\.com|"
                    + "w3t\\.org|wapurl\\.co\\.uk|wipi\\.es|wp\\.me|x\\.co|"
                    + "x\\.se|xaddr\\.com|xeeurl\\.com|xr\\.com|xrl\\.in|"
                    + "xrl\\.us|xurl\\.jp|xzb\\.cc|yep\\.it|yfrog\\.com|"
                    + "yourls\\.org|yweb\\.com|zi\\.ma|zi\\.pe|"
                    + "zipmyurl\\.com|zz\\.gd|back\\.ly|ouo\\.io|tini\\.to|s\\.id)\\/"
    );
    
    public static boolean isShortenerURL(String url) {
        if (url == null) {
            return false;
        } else {
            return URL_SHORTENER_PATTERN.matches(url);
        }
    }
    
    
    public static boolean isShortenerHost(String host) {
        if (host == null) {
            return false;
        } else {
            return SHORTENER_SET.contains(host);
        }
    }
    
    public static HashSet<String> getUserClientSet() {
        HashSet<String> returnSet = new HashSet<>();
        String adminEmail = getAdminEmail();
        if (adminEmail != null) {
            returnSet.add(adminEmail);
        }
        returnSet.addAll(User.getKeySet());
        returnSet.addAll(Client.getEmailSet());
        return returnSet;
    }
    
    protected static void autoClearHistory() {
        autoClearHistory(600, 100000);
    }
    
    protected static void autoClearHistory(int timeout, int limit) {
        Short expires = getExpiresMySQL();
        if (expires != null && Core.isRunning()) {
            try {
                Server.logTrace("starting history clear.");
                Connection connection = Core.newConnectionMySQL();
                if (connection != null) {
                    try {
                        int expiresInt = expires * 24 * 60 * 60;
                        String command = "DELETE FROM user_query\n"
                                + "WHERE time < ((UNIX_TIMESTAMP(CURRENT_TIMESTAMP)"
                                + " - " + expiresInt + ") * 1000)\n"
                                + "LIMIT " + limit;
                        long begin = System.currentTimeMillis();
                        try (Statement statement = connection.createStatement()) {
                            statement.setQueryTimeout(timeout);
                            statement.executeUpdate(command);
                        } catch (MySQLTimeoutException ex) {
                            Server.logMySQL(begin, command, ex);
                        }
                    } finally {
                        connection.close();
                        Server.logMySQL("connection closed.");
                    }
                }
                Server.logTrace("finished history clear.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static final HashSet<String> SHORTENER_SET = new HashSet<>();
    
    static {
        SHORTENER_SET.add("1link.in");
        SHORTENER_SET.add("1url.com");
        SHORTENER_SET.add("2big.at");
        SHORTENER_SET.add("2pl.us");
        SHORTENER_SET.add("2tu.us");
        SHORTENER_SET.add("2ya.com");
        SHORTENER_SET.add("4url.cc");
        SHORTENER_SET.add("6url.com");
        SHORTENER_SET.add("a.gg");
        SHORTENER_SET.add("a.nf");
        SHORTENER_SET.add("a2a.me");
        SHORTENER_SET.add("abbrr.com");
        SHORTENER_SET.add("adf.ly");
        SHORTENER_SET.add("adjix.com");
        SHORTENER_SET.add("alturl.com");
        SHORTENER_SET.add("atu.ca");
        SHORTENER_SET.add("b23.ru");
        SHORTENER_SET.add("back.ly");
        SHORTENER_SET.add("bacn.me");
        SHORTENER_SET.add("bc.vc");
        SHORTENER_SET.add("bit.do");
        SHORTENER_SET.add("bit.ly");
        SHORTENER_SET.add("bitly.com");
        SHORTENER_SET.add("bkite.com");
        SHORTENER_SET.add("bloat.me");
        SHORTENER_SET.add("budurl.com");
        SHORTENER_SET.add("buk.me");
        SHORTENER_SET.add("burnurl.com");
        SHORTENER_SET.add("buzurl.com");
        SHORTENER_SET.add("c-o.in");
        SHORTENER_SET.add("chilp.it");
        SHORTENER_SET.add("clck.ru");
        SHORTENER_SET.add("cli.gs");
        SHORTENER_SET.add("clickmeter.com");
        SHORTENER_SET.add("cort.as");
        SHORTENER_SET.add("cur.lv");
        SHORTENER_SET.add("cutt.us");
        SHORTENER_SET.add("cuturl.com");
        SHORTENER_SET.add("db.tt");
        SHORTENER_SET.add("decenturl.com");
        SHORTENER_SET.add("dfl8.me");
        SHORTENER_SET.add("digbig.com");
        SHORTENER_SET.add("digg.com");
        SHORTENER_SET.add("doiop.com");
        SHORTENER_SET.add("dwarfurl.com");
        SHORTENER_SET.add("dy.fi");
        SHORTENER_SET.add("easyuri.com");
        SHORTENER_SET.add("easyurl.net");
        SHORTENER_SET.add("eepurl.com");
        SHORTENER_SET.add("esyurl.com");
        SHORTENER_SET.add("ewerl.com");
        SHORTENER_SET.add("fa.b");
        SHORTENER_SET.add("ff.im");
        SHORTENER_SET.add("fff.to");
        SHORTENER_SET.add("fhurl.com");
        SHORTENER_SET.add("filoops.info");
        SHORTENER_SET.add("fire.to");
        SHORTENER_SET.add("firsturl.de");
        SHORTENER_SET.add("flic.kr");
        SHORTENER_SET.add("fly2.ws");
        SHORTENER_SET.add("fon.gs");
        SHORTENER_SET.add("fwd4.me");
        SHORTENER_SET.add("gl.am");
        SHORTENER_SET.add("go.9nl.com");
        SHORTENER_SET.add("go2.me");
        SHORTENER_SET.add("go2cut.com");
        SHORTENER_SET.add("goo.gl");
        SHORTENER_SET.add("goshrink.com");
        SHORTENER_SET.add("gowat.ch");
        SHORTENER_SET.add("gri.ms");
        SHORTENER_SET.add("gurl.es");
        SHORTENER_SET.add("hellotxt.com");
        SHORTENER_SET.add("hex.io");
        SHORTENER_SET.add("hover.com");
        SHORTENER_SET.add("href.in");
        SHORTENER_SET.add("htxt.it");
        SHORTENER_SET.add("hugeurl.com");
        SHORTENER_SET.add("hurl.it");
        SHORTENER_SET.add("hurl.me");
        SHORTENER_SET.add("hurl.ws");
        SHORTENER_SET.add("icanhaz.com");
        SHORTENER_SET.add("idek.net");
        SHORTENER_SET.add("inreply.to");
        SHORTENER_SET.add("inx.lv");
        SHORTENER_SET.add("is.gd");
        SHORTENER_SET.add("iscool.net");
        SHORTENER_SET.add("iterasi.net");
        SHORTENER_SET.add("ity.im");
        SHORTENER_SET.add("j.mp");
        SHORTENER_SET.add("jijr.com");
        SHORTENER_SET.add("jmp2.net");
        SHORTENER_SET.add("just.as");
        SHORTENER_SET.add("kissa.be");
        SHORTENER_SET.add("kl.am");
        SHORTENER_SET.add("klck.me");
        SHORTENER_SET.add("korta.nu");
        SHORTENER_SET.add("krunchd.com");
        SHORTENER_SET.add("liip.to");
        SHORTENER_SET.add("liltext.com");
        SHORTENER_SET.add("lin.cr");
        SHORTENER_SET.add("link.zip.net");
        SHORTENER_SET.add("linkbee.com");
        SHORTENER_SET.add("linkbun.ch");
        SHORTENER_SET.add("liurl.cn");
        SHORTENER_SET.add("ln-s.net");
        SHORTENER_SET.add("ln-s.ru");
        SHORTENER_SET.add("lnk.gd");
        SHORTENER_SET.add("lnk.in");
        SHORTENER_SET.add("lnkd.in");
        SHORTENER_SET.add("loopt.us");
        SHORTENER_SET.add("lru.jp");
        SHORTENER_SET.add("lt.tl");
        SHORTENER_SET.add("lurl.no");
        SHORTENER_SET.add("metamark.net");
        SHORTENER_SET.add("migre.me");
        SHORTENER_SET.add("minilien.com");
        SHORTENER_SET.add("miniurl.com");
        SHORTENER_SET.add("minurl.fr");
        SHORTENER_SET.add("moourl.com");
        SHORTENER_SET.add("myurl.in");
        SHORTENER_SET.add("ne1.net");
        SHORTENER_SET.add("njx.me");
        SHORTENER_SET.add("nn.nf");
        SHORTENER_SET.add("notlong.com");
        SHORTENER_SET.add("nsfw.in");
        SHORTENER_SET.add("o-x.fr");
        SHORTENER_SET.add("om.ly");
        SHORTENER_SET.add("ouo.io");
        SHORTENER_SET.add("ow.ly");
        SHORTENER_SET.add("pd.am");
        SHORTENER_SET.add("pic.gd");
        SHORTENER_SET.add("ping.fm");
        SHORTENER_SET.add("piurl.com");
        SHORTENER_SET.add("pnt.me");
        SHORTENER_SET.add("po.st");
        SHORTENER_SET.add("poprl.com");
        SHORTENER_SET.add("post.ly");
        SHORTENER_SET.add("posted.at");
        SHORTENER_SET.add("prettylinkpro.com");
        SHORTENER_SET.add("profile.to");
        SHORTENER_SET.add("q.gs");
        SHORTENER_SET.add("qicute.com");
        SHORTENER_SET.add("qlnk.net");
        SHORTENER_SET.add("qr.ae");
        SHORTENER_SET.add("qr.net");
        SHORTENER_SET.add("quip-art.com");
        SHORTENER_SET.add("rb6.me");
        SHORTENER_SET.add("redirx.com");
        SHORTENER_SET.add("ri.ms");
        SHORTENER_SET.add("rickroll.it");
        SHORTENER_SET.add("riz.gd");
        SHORTENER_SET.add("rsmonkey.com");
        SHORTENER_SET.add("ru.ly");
        SHORTENER_SET.add("rubyurl.com");
        SHORTENER_SET.add("s7y.us");
        SHORTENER_SET.add("safe.mn");
        SHORTENER_SET.add("scrnch.me");
        SHORTENER_SET.add("sharein.com");
        SHORTENER_SET.add("sharetabs.com");
        SHORTENER_SET.add("shorl.com");
        SHORTENER_SET.add("short.ie");
        SHORTENER_SET.add("short.to");
        SHORTENER_SET.add("shortlinks.co.uk");
        SHORTENER_SET.add("shortna.me");
        SHORTENER_SET.add("shorturl.com");
        SHORTENER_SET.add("shoturl.us");
        SHORTENER_SET.add("shrinkify.com");
        SHORTENER_SET.add("shrinkster.com");
        SHORTENER_SET.add("shrt.st");
        SHORTENER_SET.add("shrten.com");
        SHORTENER_SET.add("shrunkin.com");
        SHORTENER_SET.add("shw.me");
        SHORTENER_SET.add("simurl.com");
        SHORTENER_SET.add("sn.im");
        SHORTENER_SET.add("snipr.com");
        SHORTENER_SET.add("snipurl.com");
        SHORTENER_SET.add("snurl.com");
        SHORTENER_SET.add("sp2.ro");
        SHORTENER_SET.add("spedr.com");
        SHORTENER_SET.add("sqrl.it");
        SHORTENER_SET.add("starturl.com");
        SHORTENER_SET.add("sturly.com");
        SHORTENER_SET.add("su.pr");
        SHORTENER_SET.add("t.co");
        SHORTENER_SET.add("tcrn.ch");
        SHORTENER_SET.add("thrdl.es");
        SHORTENER_SET.add("tighturl.com");
        SHORTENER_SET.add("tiny.cc");
        SHORTENER_SET.add("tiny.pl");
        SHORTENER_SET.add("tiny123.com");
        SHORTENER_SET.add("tinyarro.ws");
        SHORTENER_SET.add("tinyarrows.com");
        SHORTENER_SET.add("tinytw.it");
        SHORTENER_SET.add("tinyuri.ca");
        SHORTENER_SET.add("tinyurl.com");
        SHORTENER_SET.add("tinyvid.io");
        SHORTENER_SET.add("tnij.org");
        SHORTENER_SET.add("to.ly");
        SHORTENER_SET.add("togoto.us");
        SHORTENER_SET.add("tr.im");
        SHORTENER_SET.add("tr.my");
        SHORTENER_SET.add("traceurl.com");
        SHORTENER_SET.add("turo.us");
        SHORTENER_SET.add("tweetburner.com");
        SHORTENER_SET.add("tweez.me");
        SHORTENER_SET.add("twirl.at");
        SHORTENER_SET.add("twit.ac");
        SHORTENER_SET.add("twitterpan.com");
        SHORTENER_SET.add("twitthis.com");
        SHORTENER_SET.add("twiturl.de");
        SHORTENER_SET.add("twurl.cc");
        SHORTENER_SET.add("twurl.nl");
        SHORTENER_SET.add("u.bb");
        SHORTENER_SET.add("u.mavrev.com");
        SHORTENER_SET.add("u.nu");
        SHORTENER_SET.add("u.to");
        SHORTENER_SET.add("u6e.de");
        SHORTENER_SET.add("ub0.cc");
        SHORTENER_SET.add("ulvis.net");
        SHORTENER_SET.add("updating.me");
        SHORTENER_SET.add("ur1.ca");
        SHORTENER_SET.add("url.co.uk");
        SHORTENER_SET.add("url.ie");
        SHORTENER_SET.add("url4.eu");
        SHORTENER_SET.add("urlao.com");
        SHORTENER_SET.add("urlbrief.com");
        SHORTENER_SET.add("urlcover.com");
        SHORTENER_SET.add("urlcut.com");
        SHORTENER_SET.add("urlenco.de");
        SHORTENER_SET.add("urlhawk.com");
        SHORTENER_SET.add("urlkiss.com");
        SHORTENER_SET.add("urlot.com");
        SHORTENER_SET.add("urlpire.com");
        SHORTENER_SET.add("urlx.ie");
        SHORTENER_SET.add("urlx.org");
        SHORTENER_SET.add("urlzen.com");
        SHORTENER_SET.add("v.gd");
        SHORTENER_SET.add("virl.com");
        SHORTENER_SET.add("vl.am");
        SHORTENER_SET.add("vzturl.com");
        SHORTENER_SET.add("w3t.org");
        SHORTENER_SET.add("wapurl.co.uk");
        SHORTENER_SET.add("we.tl");
        SHORTENER_SET.add("wipi.es");
        SHORTENER_SET.add("wp.me");
        SHORTENER_SET.add("x.co");
        SHORTENER_SET.add("x.se");
        SHORTENER_SET.add("xaddr.com");
        SHORTENER_SET.add("xeeurl.com");
        SHORTENER_SET.add("xr.com");
        SHORTENER_SET.add("xrl.in");
        SHORTENER_SET.add("xrl.us");
        SHORTENER_SET.add("xurl.es");
        SHORTENER_SET.add("xurl.jp");
        SHORTENER_SET.add("xzb.cc");
        SHORTENER_SET.add("yep.it");
        SHORTENER_SET.add("yfrog.com");
        SHORTENER_SET.add("yourls.org");
        SHORTENER_SET.add("yweb.com");
        SHORTENER_SET.add("zi.ma");
        SHORTENER_SET.add("zi.pe");
        SHORTENER_SET.add("zipmyurl.com");
        SHORTENER_SET.add("zz.gd");
        SHORTENER_SET.add("ujeb.se");
        SHORTENER_SET.add("soo.gd");
        SHORTENER_SET.add("gee.su");
        SHORTENER_SET.add("gmy.su");
        SHORTENER_SET.add("v.ht");
        SHORTENER_SET.add("tini.to");
        SHORTENER_SET.add("s.id");
    }
    
    public static final HashSet<String> EXECUTABLE_SET = new HashSet<>();
    
    static {
        EXECUTABLE_SET.add("com");
        EXECUTABLE_SET.add("vbs");
        EXECUTABLE_SET.add("vbe");
        EXECUTABLE_SET.add("bat");
        EXECUTABLE_SET.add("cmd");
        EXECUTABLE_SET.add("pif");
        EXECUTABLE_SET.add("scr");
        EXECUTABLE_SET.add("prf");
        EXECUTABLE_SET.add("lnk");
        EXECUTABLE_SET.add("exe");
        EXECUTABLE_SET.add("shs");
        EXECUTABLE_SET.add("arj");
        EXECUTABLE_SET.add("hta");
        EXECUTABLE_SET.add("jar");
        EXECUTABLE_SET.add("ace");
        EXECUTABLE_SET.add("js");
        EXECUTABLE_SET.add("msi");
        EXECUTABLE_SET.add("sh");
        EXECUTABLE_SET.add("zip");
        EXECUTABLE_SET.add("7z");
        EXECUTABLE_SET.add("rar");
        EXECUTABLE_SET.add("z");
        EXECUTABLE_SET.add("lzh");
        EXECUTABLE_SET.add("r13");
        EXECUTABLE_SET.add("doc");
        EXECUTABLE_SET.add("xls");
        EXECUTABLE_SET.add("docx");
        EXECUTABLE_SET.add("xlsx");
        EXECUTABLE_SET.add("xlsm");
        EXECUTABLE_SET.add("xlsb");
        EXECUTABLE_SET.add("html");
        EXECUTABLE_SET.add("pdf");
    }
    
    public static final HashSet<String> HARMFUL_SET = new HashSet<>();
    
    static {
        HARMFUL_SET.add("com");
        HARMFUL_SET.add("vbs");
        HARMFUL_SET.add("vbe");
        HARMFUL_SET.add("bat");
        HARMFUL_SET.add("cmd");
        HARMFUL_SET.add("pif");
        HARMFUL_SET.add("scr");
        HARMFUL_SET.add("prf");
        HARMFUL_SET.add("lnk");
        HARMFUL_SET.add("exe");
        HARMFUL_SET.add("shs");
        HARMFUL_SET.add("arj");
        HARMFUL_SET.add("hta");
        HARMFUL_SET.add("jar");
        HARMFUL_SET.add("ace");
        HARMFUL_SET.add("js");
        HARMFUL_SET.add("msi");
    }
    
    public static final HashSet<String> COMPACTED_SET = new HashSet<>();
    
    static {
        COMPACTED_SET.add("zip");
        COMPACTED_SET.add("gz");
        COMPACTED_SET.add("tar");
        COMPACTED_SET.add("rar");
        COMPACTED_SET.add("7z");
        COMPACTED_SET.add("z");
        COMPACTED_SET.add("lzh");
        COMPACTED_SET.add("r13");
    }
    
    private static String GSB_API_KEY = null;
    
    public synchronized static void setSafeBrowsingKey(String key) {
        if (key != null && key.length() > 0) {
            if (key.matches("^[0-9a-zA-Z_-]+$")) {
                GSB_API_KEY = key;
                beginTimeForGSB = 0;
            } else {
                Server.logError("invalid Safe Browsing key '" + key + "'.");
            }
        }
    }
    
    private static long beginTimeForGSB = 0;
    
    public synchronized static String getSafeBrowsingKey() {
        if (System.currentTimeMillis() > beginTimeForGSB) {
            return GSB_API_KEY;
        } else {
            return null;
        }
    }
    
    public synchronized static void pauseSafeBrowsing() {
        beginTimeForGSB = System.currentTimeMillis() + Server.HOUR_TIME;
    }
    
    public synchronized static void disableSafeBrowsing() {
        beginTimeForGSB = Long.MAX_VALUE;
    }
    
    public static String checkGoogleSafeBrowsing(Long timeKey, String user, TreeSet<String> urlSet) {
        String gsbKey = getSafeBrowsingKey();
        if (gsbKey == null) {
            return null;
        } else if (urlSet == null) {
            return null;
        } else if (urlSet.isEmpty()) {
            return null;
        } else {
            Server.logInfo("quering Google Safe Browsing.");

            JsonObjectBuilder root = Json.createObjectBuilder();

            JsonObjectBuilder client = Json.createObjectBuilder();
            client.add("clientId", "SPFBL");
            client.add("clientVersion", Core.getVersion());
            root.add("client", client);

            JsonObjectBuilder threatInfo = Json.createObjectBuilder();
            JsonArrayBuilder threatTypes = Json.createArrayBuilder();
            threatTypes.add("MALWARE");
            threatTypes.add("SOCIAL_ENGINEERING");
            threatTypes.add("UNWANTED_SOFTWARE");
            threatTypes.add("POTENTIALLY_HARMFUL_APPLICATION");
            threatInfo.add("threatTypes", threatTypes);
            JsonArrayBuilder platformTypes = Json.createArrayBuilder();
            platformTypes.add("LINUX");
            platformTypes.add("ANDROID");
            platformTypes.add("OSX");
            platformTypes.add("IOS");
            platformTypes.add("WINDOWS");
            threatInfo.add("platformTypes", platformTypes);
            JsonArrayBuilder threatEntryTypes = Json.createArrayBuilder();
            threatEntryTypes.add("URL");
            threatInfo.add("threatEntryTypes", threatEntryTypes);
            JsonArrayBuilder threatEntries = Json.createArrayBuilder();
            for (String url : urlSet) {
                JsonObjectBuilder entrie = Json.createObjectBuilder();
                entrie.add("url", url);
                threatEntries.add(entrie);
            }
            threatInfo.add("threatEntries", threatEntries);
            root.add("threatInfo", threatInfo);

            JsonObject object = root.build();
            try {
                URL gsbURL = new URL("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + gsbKey);
                HttpsURLConnection gsbConn = (HttpsURLConnection) gsbURL.openConnection();
                gsbConn.setConnectTimeout(3000);
                gsbConn.setReadTimeout(5000);
                gsbConn.setRequestMethod("POST");
                gsbConn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                gsbConn.setRequestProperty("Accept", "application/json");
                gsbConn.setDoOutput(true);
                try (JsonWriter writer = Json.createWriter(gsbConn.getOutputStream())) {
                    writer.writeObject(object);
                }
                try (JsonReader reader = Json.createReader(gsbConn.getInputStream())) {
                    object = reader.readObject();
                }
                JsonArray matches = object.getJsonArray("matches");
                if (matches == null) {
                    return null;
                } else {
                    TreeSet<String> malwareSet = new TreeSet<>();
                    for (JsonObject match : matches.getValuesAs(JsonObject.class)) {
                        JsonObject threat = match.getJsonObject("threat");
                        URL url = new URL(threat.getJsonString("url").getString());
                        String host = url.getHost().toLowerCase();
                        if (host.charAt(0) == '[') {
                            int index = host.length() - 1;
                            host = host.substring(1, index);
                            malwareSet.add("Google.SafeBrowsing.IP");
                        } else if (isValidIP(host)) {
                            malwareSet.add("Google.SafeBrowsing.IP");
                        } else {
                            malwareSet.add("Google.SafeBrowsing." + host);
                        }
                        if (SHORTENER_SET.contains(host)) {
                            String signature = Core.getSignature(url);
                            if (Block.addExact(signature)) {
                                Server.logDebug(timeKey, "new BLOCK '" + signature + "' added by 'Google.SafeBrowsing'.");
                            }
                        } else if (Block.addExact("HREF=." + host)) {
                            Server.logDebug(timeKey, "new BLOCK 'HREF=." + host + "' added by 'Google.SafeBrowsing'.");
                        }
                    }
                    if (malwareSet.isEmpty()) {
                        return null;
                    } else if (malwareSet.size() == 1) {
                        return malwareSet.first();
                    } else {
                        for (String malware : malwareSet) {
                            if (user != null && !Ignore.containsExact(user + ":MALWARE=" + malware)) {
                                return malware;
                            }
                        }
                        return malwareSet.first();
                    }
                }
            } catch (Exception ex) {
                if (ex.getMessage().startsWith("Server returned HTTP response code: 400 ")) {
                    disableSafeBrowsing();
                    Server.logError("Google Safe Browsing was disabled by invalid parameter.");
                } else if (ex.getMessage().startsWith("Server returned HTTP response code: 401 ")) {
                    disableSafeBrowsing();
                    Server.logError("Google Safe Browsing was disabled by invalid credentials.");
                } else if (ex.getMessage().startsWith("Server returned HTTP response code: 403 ")) {
                    pauseSafeBrowsing();
                    Server.logWarning("Google Safe Browsing paused for a while by quota exceeded.");
                } else if (ex.getMessage().startsWith("Server returned HTTP response code: 429 ")) {
                    pauseSafeBrowsing();
                    Server.logWarning("Google Safe Browsing paused for a while by resource exhausted.");
                } else {
                    Server.logError(ex);
                }
                return null;
            }
        }
    }
    
    private static File getTemplateFolder(User user) {
        File folder = null;
        if (user != null) {
            folder = new File("./template/" + user.getEmail() + "/");
        }
        if (folder == null || !folder.exists()) {
            folder = new File("./template/");
        }
        return folder;
    }
    
    public static Document getTemplateWarningRetentionUser(User user, Locale locale) {
        File folder = getTemplateFolder(user);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.retention.user." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.retention.user.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningRetentionRecipient(User user, Locale locale) {
        File folder = getTemplateFolder(user);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.retention.recipient." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.retention.recipient.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningRejectionRecipient(User user, Locale locale) {
        File folder = getTemplateFolder(user);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.rejection.recipient." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.rejection.recipient.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningRetentionSender(User user, Locale locale) {
        File folder = getTemplateFolder(user);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.retention.sender." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.retention.sender.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningRejectionSender(User user, Locale locale) {
        File folder = getTemplateFolder(user);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.rejection.sender." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.rejection.sender.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningHijackedSender(Locale locale) {
        File folder = getTemplateFolder(null);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.hijacked.sender." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.hijacked.sender.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Document getTemplateWarningReleasedSender(Locale locale) {
        File folder = getTemplateFolder(null);
        String language = locale == null ? "en" : locale.getLanguage();
        File file = new File(folder, "warning.released.sender." + language + ".html");
        if (!file.exists()) {
            file = new File(folder, "warning.released.sender.en.html");
        }
        try {
            return Jsoup.parse(file, "UTF-8");
        } catch (IOException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static File getLogoFile(User user) {
        if (user == null) {
            return ServerHTTP.getWebFile("logo.png");
        } else {
            File folder = null;
            if (user != null) {
                folder = new File("./template/" + user.getEmail() + "/");
            }
            if (folder == null || !folder.exists()) {
                folder = new File("./template/");
            }
            
            
            
            File file = new File("./template/" + user.getEmail() + "/logo.png");
            if (file.exists()) {
                return file;
            } else {
                return ServerHTTP.getWebFile("logo.png");
            }
        }
    }
    
    private static final Regex PATTERN_BITCOIN = new Regex(
            "\\b[13][a-km-zA-HJ-NP-Z1-9]{26,34}\\b"
    );
    
    public static boolean hasBitcoinPattern(String text) {
        if (text == null) {
            return false;
        } else {
            return PATTERN_BITCOIN.matches(text);
        }
    }
    
    private static final Regex MIME_PARTS_REGEX = new Regex(
            "=\\?([^?]+)\\?([^?]+)\\?([^?]+)\\?="
    );
    
    public static String tryToDecodeRecursivelyMIME(String text) {
        if (text == null) {
            return null;
        } else {
            int count = 0;
            String decoded;
            while ((decoded = tryToDecodeMIME(text)) != null && !decoded.equals(text) && count < 4) {
                text = decoded;
                count++;
            }
            return text;
        }
    }
    
    public static String tryToDecodeMIME(String mimeText) {
        if (mimeText == null) {
            return null;
        } else {
            try {
                String decoded = MimeUtility.decodeText(mimeText);
                if (!Objects.equals(mimeText, decoded)) {
                    mimeText = Dictionary.normalizeCharset(decoded);
                }
                mimeText = mimeText.replace("?= =?", "?==?");
                Matcher matcher = MIME_PARTS_REGEX.createMatcher(mimeText);
                if (matcher.find()) {
                    do {
                        String mime = matcher.group(0);
                        String enconding = matcher.group(2);
                        if (enconding.equals("B")) {
                            // Fix space character encoding.
                            decoded = MimeUtility.decodeText(mime.replace(" ", ""));
                        } else if (enconding.equals("Q")) {
                            // Fix space character encoding.
                            decoded = MimeUtility.decodeText(mime.replace(' ', '_'));
                        } else if (enconding.equals("q")) {
                            // Fix space character encoding.
                            decoded = MimeUtility.decodeText(mime.replace(' ', '_'));
                        } else {
                            decoded = MimeUtility.decodeText(mime);
                        }
                        mimeText = mimeText.replace(mime, decoded);
                    } while (matcher.find());
                }
                MIME_PARTS_REGEX.offerMatcher(matcher);
                return MimeUtility.decodeText(mimeText);
            } catch (UnsupportedEncodingException ex) {
                return mimeText;
            }
        }
    }
    
    public static boolean isAutoExecutableOfficeFile(
            String extension,
            InputStream inputStream,
            MessageDigest messageDigest
    ) throws IOException {
        if (extension == null) {
            return false;
        } else if (inputStream == null) {
            return false;
//        } else if (extension.equals("xlsx")) {
//            ZipInputStream zis = new ZipInputStream(inputStream);
//            ZipEntry entry;
//            while ((entry = zis.getNextEntry()) != null) {
//                System.out.println(entry.getName());
//                int code;
//                while ((code = zis.read()) != -1) {
//                    if (Character.isLetterOrDigit((char) code)) {
//                        System.out.print((char) code);
//                    }
//                }
//                System.out.println();
//                System.out.println();
//            }
//            return false;
        } else if (extension.equals("doc")) {
            int i1 = 0;
            int i2 = 0;
            int i3 = 0;
            char[] state1 = {'a','u','t','o','o','p','e','n'};
            char[] state2 = {'d','o','c','u','m','e','n','t','o','p','e','n'};
            char[] state3 = {'w','o','r','d','v','b','a','p','r','o','j','e','c','t','b','i','n'};
            boolean executable = false;
            int code;
            while ((code = inputStream.read()) != -1) {
                if (messageDigest != null) {
                    messageDigest.update((byte) code);
                }
                if (!executable) {
                    char character = Character.toLowerCase((char) code);
//                    if (Character.isLetterOrDigit(character)) {
//                        System.out.print(character);
//                    }
                    if (character == 'a') {
                        i1 = 1;
                    } else if (state1[i1] == character) {
                        if (++i1 == 8) {
                            i1 = 0;
                            executable = true;
                        }
                    } else if (Character.isLetter(character)) {
                        i1 = 0;
                    }
                    if (character == 'd') {
                        i2 = 1;
                    } else if (state2[i2] == character) {
                        if (++i2 == 12) {
                            i2 = 0;
                            executable = true;
                        }
                    } else if (Character.isLetter(character)) {
                        i2 = 0;
                    }
                    if (character == 'w') {
                        i3 = 1;
                    } else if (state3[i3] == character) {
                        if (++i3 == 17) {
                            i3 = 0;
                            executable = true;
                        }
                    } else if (Character.isLetter(character)) {
                        i3 = 0;
                    }
                } else if (messageDigest == null) {
                    break;
                }
            }
            return executable;
        } else if (extension.equals("xls")) {
            int i1 = 0;
            char[] state1 = {'w','o','r','k','b','o','o','k','o','p','e','n'};
            boolean executable = false;
            int code;
            while ((code = inputStream.read()) != -1) {
                if (messageDigest != null) {
                    messageDigest.update((byte) code);
                }
                if (!executable) {
                    char character = Character.toLowerCase((char) code);
//                    if (Character.isLetterOrDigit(character)) {
//                        System.out.print(character);
//                    }
                    if (character == 'a') {
                        i1 = 1;
                    } else if (state1[i1] == character) {
                        if (++i1 == 12) {
                            i1 = 0;
                            executable = true;
                        }
                    } else if (Character.isLetter(character)) {
                        i1 = 0;
                    }
                } else if (messageDigest == null) {
                    break;
                }
            }
            return executable;
        } else {
            return false;
        }
    }
    
    public static boolean isSupportedCharset(String charset) {
        if (charset == null) {
            return false;
        } else {
            try {
                return Charset.isSupported(charset);
            } catch (Exception ex) {
                return false;
            }
        }
    }
    
    public static boolean writeUTF(DataOutput dos, String text) throws Exception {
        if (dos == null) {
            return false;
        } else if (text == null) {
            dos.writeShort(-1);
            return false;
        } else {
            byte[] data = text.getBytes(UTF_8);
            if (data.length > Short.MAX_VALUE) {
                throw new Exception("encoded string too long: " + data.length + " bytes");
            } else {
                dos.writeShort(data.length);
                dos.write(data);
            }
            return true;
        }
    }
    
    public static boolean writeURL(DataOutput dos, URL url) throws Exception {
        if (dos == null) {
            return false;
        } else if (url == null) {
            writeUTF(dos, (String) null);
            return false;
        } else {
            writeUTF(dos, url.toString());
            return true;
        }
    }
    
    public static boolean writeQualifier(DataOutput dos, Qualifier qualifier) throws Exception {
        if (dos == null) {
            return false;
        } else if (qualifier == null) {
            dos.writeByte(-1);
            return false;
        } else {
            switch (qualifier) {
                case PASS:
                    dos.writeByte(0);
                    return true;
                case FAIL:
                    dos.writeByte(1);
                    return true;
                case SOFTFAIL:
                    dos.writeByte(2);
                    return true;
                case NEUTRAL:
                    dos.writeByte(3);
                    return true;
                default:
                    dos.writeByte(-1);
                    return false;
            }
        }
    }

    
    public static boolean writeEnum(DataOutput dos, Enum enumeration) throws Exception {
        if (dos == null) {
            return false;
        } else if (enumeration == null) {
            dos.writeByte(-1);
            return false;
        } else {
            dos.writeByte(enumeration.ordinal());
            return false;
        }
    }
    
    public static boolean writeTinySubset(DataOutput dos, Set<String> set, Set<String> subset) throws Exception {
        if (dos == null) {
            return false;
        } else if (set == null) {
            return false;
        } else if (subset == null) {
            dos.writeByte(0);
            return true;
        } else {
            int size = subset.size();
            if (size > 255) {
                throw new Exception("set size too big: " + size + " elements");
            } else {
                dos.writeByte(size);
                for (String key : subset) {
                    dos.writeByte(Core.getElementIndex(set, key));
                }
                return true;
            }
        }
    }
    
    public static boolean writeSmallUTF(DataOutput dos, Set<String> set) throws Exception {
        if (dos == null) {
            return false;
        } else if (set == null) {
            dos.writeShort(-1);
            return false;
        } else {
            int size = set.size();
            if (size > Short.MAX_VALUE) {
                throw new Exception("set size too big: " + size + " elements");
            } else {
                dos.writeShort(size);
                for (String text : set) {
                    dos.writeUTF(text);
                }
                return true;
            }
        }
    }
    
    public static boolean writeTinyUTF(DataOutput dos, Set<String> set) throws Exception {
        if (dos == null) {
            return false;
        } else if (set == null) {
            dos.writeByte(0);
            return false;
        } else {
            int size = set.size();
            if (size > 256) {
                throw new Exception("set size too big: " + size + " elements");
            } else {
                dos.writeByte(size);
                for (String text : set) {
                    dos.writeUTF(text);
                }
                return true;
            }
        }
    }
    
    private static short getElementIndex(Set<String> set, String element) {
        if (set == null) {
            return -1;
        } else if (element == null) {
            return -1;
        } else {
            short index = 0;
            for (String key : set) {
                if (key.equals(element)) {
                    return index;
                }
                index++;
            }
            return -1;
        }
    }
    
    public static boolean writeTinyElement(DataOutput dos, Set<String> set, String element) throws Exception {
        if (dos == null) {
            return false;
        } else if (set == null) {
            return false;
        } else if (set.size() > 256) {
            throw new Exception("set size too big: " + set.size() + " elements");
        } else {
            dos.writeByte(getElementIndex(set, element));
            return true;
        }
    }
    
    public static boolean writeBooleanArray(
            DataOutput dos,
            boolean b0, boolean b1, boolean b2, boolean b3,
            boolean b4, boolean b5, boolean b6, boolean b7
    ) throws Exception {
        if (dos == null) {
            return false;
        } else {
            byte value = 0;
            if (b7) value++; value <<= 1;
            if (b6) value++; value <<= 1;
            if (b5) value++; value <<= 1;
            if (b4) value++; value <<= 1;
            if (b3) value++; value <<= 1;
            if (b2) value++; value <<= 1;
            if (b1) value++; value <<= 1;
            if (b0) value++;
            dos.writeByte(value);
            return true;
        }
    }
    
    public static boolean[] readBooleanArray(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            byte value = dis.readByte();
            boolean[] b = new boolean[8];
            b[0] = (value & 0x01) == 1; value >>>= 1;
            b[1] = (value & 0x01) == 1; value >>>= 1;
            b[2] = (value & 0x01) == 1; value >>>= 1;
            b[3] = (value & 0x01) == 1; value >>>= 1;
            b[4] = (value & 0x01) == 1; value >>>= 1;
            b[5] = (value & 0x01) == 1; value >>>= 1;
            b[6] = (value & 0x01) == 1; value >>>= 1;
            b[7] = (value & 0x01) == 1;
            return b;
        }
    }
    
    public static boolean writeBoolean(DataOutput dos, Boolean value) throws Exception {
        if (dos == null) {
            return false;
        } else if (value == null) {
            dos.writeByte(-1);
            return false;
        } else if (value) {
            dos.writeByte(1);
            return true;
        } else {
            dos.writeByte(0);
            return true;
        }
    }
    
    public static boolean writeUTF(DataOutput dos, Map<String,Boolean> map) throws Exception {
        if (dos == null) {
            return false;
        } else if (map == null) {
            dos.writeShort(-1);
            return false;
        } else {
            int size = map.size();
            if (size > Short.MAX_VALUE) {
                throw new Exception("map size too big: " + size + " elements");
            } else {
                dos.writeShort(size);
                for (String key : map.keySet()) {
                    Boolean value = map.get(key);
                    writeUTF(dos, key);
                    writeBoolean(dos, value);
                }
                return true;
            }
        }
    }

    
    public static boolean writeTimestamp(DataOutput dos, Timestamp date) throws Exception {
        if (dos == null) {
            return false;
        } else if (date == null) {
            dos.writeLong(-1);
            return false;
        } else {
            dos.writeLong(date.getTime());
            return true;
        }
    }
    
    public static boolean writeDate(DataOutput dos, Date date) throws Exception {
        if (dos == null) {
            return false;
        } else if (date == null) {
            dos.writeLong(-1);
            return false;
        } else {
            dos.writeLong(date.getTime());
            return true;
        }
    }
    
    public static String readIP(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            byte version = dis.readByte();
            switch (version) {
                case 4:
                    return SubnetIPv4.getAddressIP(dis.readInt());
                case 6:
                    byte[] buffer = new byte[16];
                    dis.readFully(buffer);
                    return SubnetIPv6.getAddressIP(buffer);
                default:
                    throw new Exception("undefined IP version: " + version);
            }
        }
    }
    
    public static boolean writeIP(DataOutput dos, String ip) throws Exception {
        if (dos == null) {
            return false;
        } else if (isValidIPv4(ip)) {
            dos.writeByte(4);
            dos.writeInt(SubnetIPv4.getAddressIP(ip));
            return true;
        } else if (isValidIPv6(ip)) {
            dos.writeByte(6);
            dos.write(SubnetIPv6.getAddressIP(ip));
            return true;
        } else {
            dos.writeByte(-1);
            return false;
        }
    }
    
    public static String readElement(DataInput dis, TreeSet<String> set) throws Exception {
        if (dis == null) {
            return null;
        } else if (set == null) {
            return null;
        } else {
            int index = dis.readUnsignedByte();
            for (String element : set) {
                if (index-- == 0) {
                    return element;
                }
            }
            return null;
        }
    }
    
    public static String readUTF(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            short length = dis.readShort();
            if (length < 0) {
                return null;
            } else {
                byte[] data = new byte[length];
                dis.readFully(data);
                return new String(data, UTF_8);
            }
        }
    }
    
    public static Qualifier readQualifier(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            switch (dis.readByte()) {
                case 0:
                    return Qualifier.PASS;
                case 1:
                    return Qualifier.FAIL;
                case 2:
                    return Qualifier.SOFTFAIL;
                case 3:
                    return Qualifier.NEUTRAL;
                default:
                    return null;
            }
        }
    }
    
    public static Enum readEnum(DataInput dis, Class classObj) throws Exception {
        if (dis == null) {
            return null;
        } else {
            int index = dis.readByte();
            if (index < 0) {
                return null;
            } else if (classObj == null) {
                return null;
            } else if (classObj.isEnum()) {
                try {
                    return (Enum) classObj.getEnumConstants()[index];
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            } else {
                return null;
            }
        }
    }
    
    public static Date readDate(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            long time = dis.readLong();
            if (time < 0) {
                return null;
            } else {
                return new Date(time);
            }
        }
    }
    
    public static Timestamp readTimestamp(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            long time = dis.readLong();
            if (time < 0) {
                return null;
            } else {
                return new Timestamp(time);
            }
        }
    }
    
    public static URL readURL(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            String url = readUTF(dis);
            if (url == null) {
                return null;
            } else {
                try {
                    return new URL(url);
                } catch (MalformedURLException ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        }
    }
    
    public static Boolean readBoolean(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            switch (dis.readByte()) {
                case 0:
                    return false;
                case 1:
                    return true;
                default:
                    return null;
            }
        }
    }
    
    public static TreeSet<String> readTinySetUTF(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            int size = dis.readUnsignedByte();
            if (size == 0) {
                return null;
            } else {
                TreeSet<String> set = new TreeSet<>();
                while (size-- > 0) {
                    set.add(dis.readUTF());
                }
                return set;
            }
        }
    }
    
    public static TreeSet<String> readTinySetUTF(
            DataInput dis, TreeSet<String> set
    ) throws Exception {
        if (dis == null) {
            return null;
        } else if (set == null) {
            return null;
        } else {
            int size = dis.readUnsignedByte();
            if (size == 0) {
                return null;
            } else {
                TreeSet<String> resultSet = new TreeSet<>();
                while (size-- > 0) {
                    String element = readElement(dis, set);
                    if (element != null) {
                        resultSet.add(element);
                    }
                }
                return resultSet;
            }
        }
    }
    
    public static TreeSet<String> readSmallSetUTF(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            short size = dis.readShort();
            if (size < 0) {
                return null;
            } else {
                TreeSet<String> set = new TreeSet<>();
                while (size-- > 0) {
                    set.add(dis.readUTF());
                }
                return set;
            }
        }
    }
    
    public static TreeMap<String,Boolean> readMapBooleanUTF(DataInput dis) throws Exception {
        if (dis == null) {
            return null;
        } else {
            short size = dis.readShort();
            if (size < 0) {
                return null;
            } else {
                TreeMap<String,Boolean> map = new TreeMap<>();
                while (size-- > 0) {
                    String key = readUTF(dis);
                    Boolean value = readBoolean(dis);
                    map.put(key, value);
                }
                return map;
            }
        }
    }
    
    public static boolean deleteFully(File file) {
        if (file == null) {
            return false;
        } else if (file.isDirectory()) {
            for (File child : file.listFiles()) {
                deleteFully(child);
            }
            return file.delete();
        } else {
            return file.delete();
        }
    }
    
    public static Boolean getBooleanObject(String value) {
        if (value == null) {
            return null;
        } else {
            switch (value.toLowerCase()) {
                case "true":
                    return true;
                case "false":
                    return false;
                default:
                    return null;
            }
        }
    }
}
