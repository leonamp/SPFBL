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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.mysql.jdbc.exceptions.MySQLTimeoutException;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import de.agitos.dkim.Canonicalization;
import de.agitos.dkim.DKIMSigner;
import de.agitos.dkim.SMTPDKIMMessage;
import de.agitos.dkim.SigningAlgorithm;
import it.sauronsoftware.junique.AlreadyLockedException;
import it.sauronsoftware.junique.JUnique;
import it.sauronsoftware.junique.MessageHandler;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
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
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import net.spfbl.whois.QueryTCP;
import net.spfbl.spf.QuerySPF;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.mail.Address;
import javax.mail.AuthenticationFailedException;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.data.Block;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.dns.QueryDNS;
import net.spfbl.http.ServerHTTP;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.OrderBuilder;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Core {
    
    private static final byte VERSION = 2;
    private static final byte SUBVERSION = 11;
    private static final byte RELEASE = 0;
    private static final boolean TESTING = false;
    
    public static String getAplication() {
        return "SPFBL-" + getVersion() + (TESTING ? "-TESTING" : "");
    }
    
    public static String getVersion() {
        return VERSION + "." + SUBVERSION + "." + RELEASE;
    }
    
    public static String getSubVersion() {
        return VERSION + "." + SUBVERSION;
    }
    
    private static final Pattern VERSION_PATTERN = Pattern.compile("^"
            + "[0-9]+\\.[0-9]+(\\.[0-9]+)?"
            + "$"
    );
    
    public static boolean isValidVersion(String version) {
        if (version == null) {
            return false;
        } else {
//            return Pattern.matches("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$", version);
            return VERSION_PATTERN.matcher(version).matches();
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
    
    public static byte[] encodeHuffmanPlus(String text, int deslocamento) throws ProcessException {
        if (text == null) {
            return null;
        } else {
            return HUFFMANPLUS.encodeByteArray(text.toLowerCase(), deslocamento);
        }
    }
    
    public static String decodeHuffmanPlus(byte[] byteArray, int deslocamento) {
        return Core.HUFFMANPLUS.decode(byteArray, deslocamento);
    }
    
    public static String decodeHuffman(byte[] byteArray, int deslocamento) {
        String query = Core.HUFFMANPLUS.decode(byteArray, deslocamento);
        if (query == null) {
            return Core.HUFFMAN.decode(byteArray, deslocamento);
        } else if (query.startsWith("block ")) {
            return query;
        } else if (query.startsWith("holding ")) {
            return query;
        } else if (query.startsWith("release ")) {
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
        } else if (query.startsWith("unsubscribe ")) {
            return query;
        } else if (query.startsWith("white ")) {
            return query;
        } else if (query.startsWith("delist ")) {
            return query;
        } else {
            return Core.HUFFMAN.decode(byteArray, deslocamento);
        }
    }
    
    public static final Base64 BASE64 = new Base64(0, new byte[0], true);
    
    public static String getReleaseURL(User user, String id) throws ProcessException {
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
                try {
                    long time = System.currentTimeMillis();
                    String ticket = "release " + id;
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
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
            ) throws ProcessException {
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
            ) throws ProcessException {
        if (userEmail == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (sender == null) {
            return null;
        } else if (recipient == null) {
            return null;
        } else if (!Domain.isValidEmail(sender)) {
            return null;
        } else if (!Domain.isValidEmail(recipient)) {
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
                try {
                    long time = System.currentTimeMillis();
                    String ticket = "unblock";
                    ticket += ' ' + userEmail;
                    ticket += ' ' + ip;
                    ticket += ' ' + sender;
                    ticket += ' ' + recipient;
                    ticket += hostname == null ? "" : ' ' + hostname;
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
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
            ) throws ProcessException {
        if (client == null) {
            return null;
        } else if (!Domain.isValidEmail(client)) {
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
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    Server.logError("compress fail: " + ticket);
                    throw new ProcessException("FATAL", ex);
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
            ) throws ProcessException {
        if (user == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (!Domain.isValidEmail(user)) {
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
                ticket += ' ' + user;
                ticket += ' ' + ip;
                ticket += ' ' + token;
                ticket += ' ' + playerid;
                ticket += ' ' + price;
                ticket += ' ' + currency;
                try {
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    Server.logError("compress fail: " + ticket);
                    throw new ProcessException("FATAL", ex);
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getHoldingURL(
            User user,
            long time
    ) throws ProcessException {
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
                try {
                    String ticket = "holding";
                    ticket += ' ' + user.getEmail();
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getUnholdURL(
            User user,
            long time
    ) throws ProcessException {
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
                try {
                    String ticket = "unhold";
                    ticket += ' ' + user.getEmail();
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getUnholdURL(
            long time,
            String user
    ) throws ProcessException {
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
                try {
                    String ticket = "unhold";
                    ticket += ' ' + user;
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
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
        } else if (Core.hasRecaptchaKeys()) {
            String url = serviceHTTP.getSecuredURL(locale);
            if (url == null) {
                return null;
            } else {
                try {
                    long time = Server.getNewUniqueTime();
                    String ticket = "unsubscribe";
                    ticket += ' ' + recipient.getAddress();
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    Server.logError(ex);
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
                try {
                    String ticket = "block";
                    ticket += ' ' + user.getEmail();
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    Server.logError(ex);
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
                try {
                    String ticket = "block";
                    ticket += ' ' + user;
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    Server.logError(ex);
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
            ) throws ProcessException {
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
                try {
                    long time = System.currentTimeMillis();
                    String ticket = "white";
                    ticket += ' ' + white;
                    ticket += ' ' + client;
                    ticket += ' ' + ip;
                    ticket += ' ' + sender;
                    ticket += ' ' + recipient;
                    ticket += hostname == null ? "" : ' ' + hostname;
                    byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
                    byteArray[0] = (byte) (time & 0xFF);
                    byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
                    byteArray[7] = (byte) ((time >>> 8) & 0xFF);
                    return url + Server.encryptURLSafe(byteArray);
                } catch (Exception ex) {
                    throw new ProcessException("FATAL", ex);
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
    private static QuerySPF querySPF = null;
    private static QueryDNS queryDNSBL = null;
    private static PeerUDP peerUDP = null;
    
    public static void interruptTimeout() {
        if (querySPF != null) {
            querySPF.interruptTimeout();
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
                    Server.setProviderDNS(properties.getProperty("dns_provider"));
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
                    Core.setPortWHOIS(properties.getProperty("whois_port"));
                    Core.setPortSPFBL(properties.getProperty("spfbl_port"));
                    Core.setPortSPFBLS(properties.getProperty("spfbls_port"));
                    Core.setPortDNSBL(properties.getProperty("dnsbl_port"));
                    Core.setPortHTTP(properties.getProperty("http_port"));
                    Core.setPortHTTPS(properties.getProperty("https_port"));
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
                    Core.setFloodTimeIP(properties.getProperty("flood_time_ip"));
                    Core.setFloodTimeHELO(properties.getProperty("flood_time_helo"));
                    Core.setFloodTimeSender(properties.getProperty("flood_time_sender"));
                    Core.setFloodMaxRetry(properties.getProperty("flood_max_retry"));
                    Core.setDeferTimeFLOOD(properties.getProperty("defer_time_flood"));
                    Core.setDeferTimeSOFTFAIL(properties.getProperty("defer_time_softfail"));
                    Core.setDeferTimeYELLOW(properties.getProperty("defer_time_gray")); // Obsolete.
                    Core.setDeferTimeYELLOW(properties.getProperty("defer_time_yellow"));
                    Core.setDeferTimeRED(properties.getProperty("defer_time_black")); // Obsolete.
                    Core.setDeferTimeRED(properties.getProperty("defer_time_red"));
                    Core.setDeferTimeHOLD(properties.getProperty("defer_time_hold"));
                    Core.setReverseRequired(properties.getProperty("reverse_required"));
                    Core.setLevelLOG(properties.getProperty("log_level"));
                    Core.setRecaptchaKeySite(properties.getProperty("recaptcha_key_site"));
                    Core.setRecaptchaKeySecret(properties.getProperty("recaptcha_key_secret"));
                    Core.setCacheTimeStore(properties.getProperty("cache_time_store"));
                    Core.setHostnameMySQL(properties.getProperty("mysql_hostname"));
                    Core.setPortMySQL(properties.getProperty("mysql_port"));
                    Core.setSchemaMySQL(properties.getProperty("mysql_schema"));
                    Core.setUserMySQL(properties.getProperty("mysql_user"));
                    Core.setPasswordMySQL(properties.getProperty("mysql_password"));
                    Core.setSSLMySQL(properties.getProperty("mysql_ssl"));
                    PeerUDP.setConnectionLimit(properties.getProperty("peer_limit"));
                    QueryDNS.setConnectionLimit(properties.getProperty("dnsbl_limit"));
                    QuerySPF.setConnectionLimit(properties.getProperty("spfbl_limit"));
                    ServerHTTP.setConnectionLimit(properties.getProperty("http_limit"));
                    Analise.setAnaliseExpires(properties.getProperty("analise_expires"));
                    Analise.setAnaliseIP(properties.getProperty("analise_ip"));
                    Analise.setAnaliseMX(properties.getProperty("analise_mx"));
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
    
    public static synchronized void setHostnameMySQL(String hostname) {
        if (hostname != null && hostname.length() > 0) {
            if (Domain.isHostname(hostname)) {
                Core.MYSQL_HOSTNAME = Domain.extractHost(hostname, false);
            } else if (Subnet.isValidIP(hostname)) {
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
                    + (MYSQL_SSL ? "&verifyServerCertificate=false"
                    + "&useSSL=true&requireSSL=true" : "");
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
    private static short PORT_WHOIS = 0;
    private static short PORT_SPFBL = 9877;
    private static short PORT_SPFBLS = 0;
    private static short PORT_DNSBL = 0;
    private static short PORT_HTTP = 0;
    private static short PORT_HTTPS = 0;
    private static short UDP_MAX = 512; // UDP max size packet.
    
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
    
    public static short getPortWHOIS() {
        return PORT_WHOIS;
    }
    
    public static boolean hasPortWHOIS() {
        return PORT_WHOIS > 0;
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
    
    public static boolean hasPortHTTPS() {
        return PORT_HTTPS > 0;
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
    
    public static boolean isHostname(String hostname) {
        if (hostname == null) {
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
                        if (SubnetIPv6.isValidIPv6(host6Address)) {
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
                    if (SubnetIPv4.isValidIPv4(host4Address)) {
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
            if (!Domain.isHostname(hostame)) {
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
            if (Domain.isValidEmail(email)) {
                Core.ADMIN_EMAIL = email.toLowerCase();
            } else {
                Server.logError("invalid admin e-mail '" + email + "'.");
            }
        }
    }
    
    public static synchronized void setAbuseEmail(String email) {
        if (email != null && email.length() > 0) {
            if (Domain.isValidEmail(email)) {
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
    
    public static void setPortWHOIS(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortWHOIS(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid WHOIS port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortWHOIS(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid WHOIS port '" + port + "'.");
        } else {
            Core.PORT_WHOIS = (short) port;
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
    
    private static float FLOOD_TIME_IP = 1.0f;
    
    public static float getFloodTimeIP() {
        return FLOOD_TIME_IP;
    }
    
    public static void setFloodTimeIP(String time) {
        if (time != null && time.length() > 0) {
            try {
                setFloodTimeIP(Float.parseFloat(time));
            } catch (Exception ex) {
                Server.logError("invalid FLOOD IP time '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setFloodTimeIP(float time) {
        if (time < 0.0f || time > Byte.MAX_VALUE) {
            Server.logError("invalid FLOOD IP time '" + time + "s'.");
        } else {
            Core.FLOOD_TIME_IP = time;
        }
    }
    
    private static float FLOOD_TIME_HELO = 10.0f;
    
    public static float getFloodTimeHELO() {
        return FLOOD_TIME_HELO;
    }
    
    public static void setFloodTimeHELO(String time) {
        if (time != null && time.length() > 0) {
            try {
                setFloodTimeHELO(Float.parseFloat(time));
            } catch (Exception ex) {
                Server.logError("invalid FLOOD HELO time '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setFloodTimeHELO(float time) {
        if (time < 0.0f || time > Byte.MAX_VALUE) {
            Server.logError("invalid FLOOD HELO time '" + time + "s'.");
        } else {
            Core.FLOOD_TIME_HELO = time;
        }
    }
    
    private static float FLOOD_TIME_SENDER = 30.0f;
    
    public static float getFloodTimeSender() {
        return FLOOD_TIME_SENDER;
    }
    
    public static void setFloodTimeSender(String time) {
        if (time != null && time.length() > 0) {
            try {
                setFloodTimeSender(Float.parseFloat(time));
            } catch (Exception ex) {
                Server.logError("invalid FLOOD SENDER time '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setFloodTimeSender(float time) {
        if (time < 0.0f || time > Byte.MAX_VALUE) {
            Server.logError("invalid FLOOD SENDER time '" + time + "s'.");
        } else {
            Core.FLOOD_TIME_SENDER = time;
        }
    }
    
    private static byte FLOOD_MAX_RETRY = 32;
    
    public static float getFloodMaxRetry() {
        return FLOOD_MAX_RETRY;
    }
    
    public static void setFloodMaxRetry(String max) {
        if (max != null && max.length() > 0) {
            try {
                setFloodMaxRetry(Integer.parseInt(max));
            } catch (Exception ex) {
                Server.logError("invalid FLOOD max retry '" + max + "'.");
            }
        }
    }
    
    public static synchronized void setFloodMaxRetry(int max) {
        if (max < 0 || max > Byte.MAX_VALUE) {
            Server.logError("invalid FLOOD max retry '" + max + "'.");
        } else {
            Core.FLOOD_MAX_RETRY = (byte) max;
        }
    }
    
    private static class ApplicationMessageHandler implements MessageHandler {
        @Override
        public synchronized String handle(String message) {
            if (message.equals("register")) {
                Server.logDebug("another instance of this application tried to start.");
            }
            return null;
        }
    }
    
    private static byte DEFER_TIME_FLOOD = 0;
    
    public static byte getDeferTimeFLOOD() {
        return DEFER_TIME_FLOOD;
    }
    
    public static void setDeferTimeFLOOD(String time) {
        if (time != null && time.length() > 0) {
            try {
                setDeferTimeFLOOD(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid DEFER time for FLOOD '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setDeferTimeFLOOD(int time) {
        if (time < 0 || time > Byte.MAX_VALUE) {
            Server.logError("invalid DEFER time for FLOOD '" + time + "'.");
        } else {
            Core.DEFER_TIME_FLOOD = (byte) time;
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

    private static boolean REVERSE_REQUIRED = false;
    
    public static boolean isReverseRequired() {
        return REVERSE_REQUIRED;
    }
    
    public static void setReverseRequired(String required) {
        if (required != null && required.length() > 0) {
            try {
                setReverseRequired(Boolean.parseBoolean(required));
            } catch (Exception ex) {
                Server.logError("invalid required reverse flag '" + required + "'.");
            }
        }
    }
    
    public static synchronized void setReverseRequired(boolean required) {
        Core.REVERSE_REQUIRED = required;
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
            RECAPTCHA_KEY_SITE = key;
        }
    }
    
    public static String getRecaptchaKeySecret() {
        return RECAPTCHA_KEY_SECRET;
    }
    
    public static void setRecaptchaKeySecret(String key) {
        if (key != null && key.length() > 0) {
            RECAPTCHA_KEY_SECRET = key;
        }
    }
    
    private static String DKIM_SELECTOR = null;
    private static PrivateKey DKIM_PRIVATE = null;
    
    public static synchronized void setSelectorDKIM(String selector) {
        if (selector != null && selector.length() > 0) {
            if (Domain.isHostname(selector)) {
                Core.DKIM_SELECTOR = Domain.normalizeHostname(selector, false);
            } else {
                Server.logError("invalid DKIM selector '" + selector + "'.");
            }
        }
    }
    
    public static synchronized void setPrivateDKIM(String privateKey) {
        if (privateKey != null && privateKey.length() > 0) {
            try {
                byte[] privateKeyBytes = BASE64.decode(privateKey);
                PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                Core.DKIM_PRIVATE = kf.generatePrivate(encodedKeySpec);
            } catch (Exception ex) {
                Server.logError("invalid DKIM private key '" + privateKey + "'.");
            }
        }
    }
    
    private static short INEXISTENT_EXPIRES = 365;
    
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
            if (Subnet.isValidIP(host)) {
                Core.SMTP_HOST = Subnet.normalizeIP(host);
            } else if (Domain.isHostname(host)) {
                Core.SMTP_HOST = Domain.normalizeHostname(host, false);
            } else {
                Server.logError("invalid SMTP hostname '" + host + "'.");
            }
        }
    }
    
    public static synchronized void setUserSMTP(String user) {
        if (user != null && user.length() > 0) {
            if (Domain.isValidEmail(user) || Domain.isHostname(user)) {
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
    
    private static final short REPUTATION_LIMIT = 512;
    
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
    
    public static synchronized Date parseEmailDate(String date) throws ParseException {
        return DATE_EMAIL_FULL_PARSER.parse(date);
    }
    
    public static synchronized Date parseEmailShortDate(String date) throws ParseException {
        return DATE_EMAIL_SHORT_PARSER.parse(date);
    }
    
    public static Date parseEmailDateSafe(String date) throws ParseException {
        if (date == null) {
            return null;
        } else {
            try {
                return parseEmailDate(date);
            } catch (ParseException ex) {
                int index = date.indexOf(',') + 1;
                date = date.substring(index).trim();
                return parseEmailShortDate(date);
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
    
    private static DKIMSigner getDKIMSigner() {
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
                return dkimSigner;
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static MimeMessage newMessage() throws Exception {
        Properties props = System.getProperties();
        javax.mail.Session session = javax.mail.Session.getDefaultInstance(props);
        DKIMSigner dkimSigner;
        MimeMessage message;
        if (!isDirectSMTP()) {
            message = new MimeMessage(session);
        } else if ((dkimSigner = getDKIMSigner()) == null) {
            message = new MimeMessage(session);
        } else {
            message = new SMTPDKIMMessage(session, dkimSigner);
        }
        message.setHeader("Date", Core.getEmailDate());
        message.setFrom(Core.getAdminInternetAddress());
        return message;
    }
    
    public static boolean sendMessage(
            Locale locale, Message message, int timeout
    ) throws Exception {
        Object response = getLastResponse(
                locale, message, timeout
        );
        if (response instanceof String) {
            return true;
        } else if (response instanceof Boolean) {
            return (Boolean) response;
        } else {
            return false;
        }
    }
    
    public static Object getLastResponse(
            Locale locale, Message message, int timeout
    ) throws Exception {
        if (message == null) {
            return null;
        } else if (isDirectSMTP()) {
            Server.logInfo("sending e-mail message.");
            Server.logSendMTP("authenticate: false.");
            Server.logSendMTP("start TLS: true.");
            Properties props = System.getProperties();
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
                if (NoReply.contains(email, true)) {
                    Server.logDebug("the recipient '" + email +  "' is in no-reply list.");
                    return false;
                } else {
                    String domain = Domain.normalizeHostname(email, false);
                    String url = Core.getListUnsubscribeURL(locale, recipient);
                    if (url != null) {
                        message.setHeader("List-Unsubscribe", "<" + url + ">");
                    }
                    message.saveChanges();
                    try {
                        for (String mx : Reverse.getMXSet(domain)) {
                            mx = mx.substring(1);
                            props.put("mail.smtp.starttls.enable", "true");
                            props.put("mail.smtp.host", mx);
                            props.put("mail.smtp.ssl.trust", mx);
                            InternetAddress[] recipientAlone = new InternetAddress[1];
                            recipientAlone[0] = (InternetAddress) recipient;
                            javax.mail.Session session = javax.mail.Session.getDefaultInstance(props);
                            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
                            try {
                                transport.setLocalHost(HOSTNAME);
                                Server.logSendMTP("connecting to " + mx + ":25.");
                                transport.connect(mx, 25, null, null);
                                Server.logSendMTP("sending '" + message.getSubject() + "' to " + recipient + ".");
                                transport.sendMessage(message, recipientAlone);
                                Server.logSendMTP("message '" + message.getSubject() + "' sent to " + recipient + ".");
                                Server.logSendMTP("last response: " + transport.getLastServerResponse());
                                return mx + ": " + transport.getLastServerResponse();
                            } catch (MailConnectException ex) {
                                Server.logSendMTP("connection failed.");
                                mailConnectException = ex;
                            } catch (SendFailedException ex) {
                                Server.logSendMTP("send failed.");
                                Server.logSendMTP("last response: " + transport.getLastServerResponse());
                                sendFailedException = ex;
                            } catch (MessagingException ex) {
    //                            if (ex.getMessage().contains(" TLS ")) {
    //                            Server.logSendMTP("cannot establish TLS connection.");
                                Server.logSendMTP("last response: " + transport.getLastServerResponse());
                                if (transport.isConnected()) {
                                    transport.close();
                                    Server.logSendMTP("connection closed.");
                                }
                                messagingException = ex;
                                Server.logInfo("sending e-mail message without TLS.");
                                props.put("mail.smtp.starttls.enable", "false");
                                session = javax.mail.Session.getDefaultInstance(props);
                                transport = (SMTPTransport) session.getTransport("smtp");
                                try {
                                    transport.setLocalHost(HOSTNAME);
                                    Server.logSendMTP("connecting to " + mx + ":25.");
                                    transport.connect(mx, 25, null, null);
                                    Server.logSendMTP("sending '" + message.getSubject() + "' to " + recipient + ".");
                                    transport.sendMessage(message, recipientAlone);
                                    Server.logSendMTP("message '" + message.getSubject() + "' sent to " + recipient + ".");
                                    Server.logSendMTP("last response: " + transport.getLastServerResponse());
                                    return mx + ": " + transport.getLastServerResponse();
                                } catch (SendFailedException ex2) {
                                    Server.logSendMTP("send failed.");
                                    Server.logSendMTP("last response: " + transport.getLastServerResponse());
                                    sendFailedException = ex2;
                                } catch (MessagingException ex2) {
                                    messagingException = ex;
                                } catch (Exception ex2) {
                                    lastException = ex;
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                                lastException = ex;
                            } finally {
                                if (transport.isConnected()) {
                                    transport.close();
                                    Server.logSendMTP("connection closed.");
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
            Server.logInfo("sending e-mail message.");
            Server.logSendMTP("authenticate: " + Boolean.toString(SMTP_IS_AUTH) + ".");
            Server.logSendMTP("start TLS: " + Boolean.toString(SMTP_STARTTLS) + ".");
            Properties props = System.getProperties();
            props.put("mail.smtp.auth", Boolean.toString(SMTP_IS_AUTH));
            props.put("mail.smtp.starttls.enable", Boolean.toString(SMTP_STARTTLS));
            props.put("mail.smtp.host", SMTP_HOST);
            props.put("mail.smtp.port", Short.toString(SMTP_PORT));
            props.put("mail.smtp.timeout", Integer.toString(timeout));   
            props.put("mail.smtp.connectiontimeout", "3000");
            props.put("mail.smtp.ssl.trust", SMTP_HOST);
            Address[] recipients = message.getAllRecipients();
            TreeSet<String> recipientSet = new TreeSet<>();
            for (Address recipient : recipients) {
                recipientSet.add(recipient.toString());
            }
            javax.mail.Session session = javax.mail.Session.getDefaultInstance(props);
            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
            try {
                if (HOSTNAME != null) {
                    transport.setLocalHost(HOSTNAME);
                }
                Server.logSendMTP("connecting to " + SMTP_HOST + ":" + SMTP_PORT + ".");
                transport.connect(SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD);
                Server.logSendMTP("sending '" + message.getSubject() + "' to " + recipientSet + ".");
                transport.sendMessage(message, recipients);
                Server.logSendMTP("message '" + message.getSubject() + "' sent to " + recipientSet + ".");
                return transport.getLastServerResponse();
            } catch (SendFailedException ex) {
                Server.logSendMTP("send failed.");
                throw ex;
            } catch (AuthenticationFailedException ex) {
                Server.logSendMTP("authentication failed.");
                return false;
            } catch (MailConnectException ex) {
                Server.logSendMTP("connection failed.");
                return false;
            } catch (MessagingException ex) {
                Server.logSendMTP("messaging failed.");
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            } finally {
                if (transport.isConnected()) {
                    transport.close();
                    Server.logSendMTP("connection closed.");
                }
            }
        } else {
            return false;
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
                Server.loadCache();
                try {
                    administrationTCP = new AdministrationTCP(PORT_ADMIN, PORT_ADMINS, HOSTNAME);
                    administrationTCP.start();
                } catch (BindException ex) {
                    Server.logError("system could not start because ADMIN port " + PORT_ADMIN + " is already in use.");
                    System.exit(1);
                }
                if (PORT_WHOIS > 0) {
                    try {
                        new QueryTCP(PORT_WHOIS).start();
                    } catch (BindException ex) {
                        Server.logError("WHOIS socket was not binded because TCP port " + PORT_WHOIS + " is already in use.");
                    }
                }
                if (PORT_DNSBL > 0) {
                    try {
                        queryDNSBL = new QueryDNS(PORT_DNSBL);
                        queryDNSBL.start();
                    } catch (BindException ex) {
                        queryDNSBL = null;
                        Server.logError("DNSBL socket was not binded because UDP port " + PORT_DNSBL + " is already in use.");
                    }
                }
                if (PORT_HTTP > 0) {
                    if (HOSTNAME == null) {
                        Server.logInfo("HTTP socket was not binded because no hostname defined.");
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
                if (PORT_SPFBL > 0) {
                    try {
                        querySPF = new QuerySPF(PORT_SPFBL, PORT_SPFBLS, HOSTNAME);
                        querySPF.start();
                    } catch (BindException ex) {
                        querySPF = null;
                        Server.logError("SPFBL socket was not binded because TCP port " + PORT_SPFBL + " is already in use.");
                    }
                    if (HOSTNAME == null) {
                        Server.logInfo("P2P socket was not binded because no hostname defined.");
                    } else if (isRouteable(HOSTNAME)) {
                        try {
                            peerUDP = new PeerUDP(HOSTNAME, PORT_SPFBL, PORT_SPFBLS, UDP_MAX);
                            peerUDP.start();
                        } catch (BindException ex) {
                            peerUDP = null;
                            Server.logError("P2P socket was not binded because UDP port " + PORT_SPFBL + " is already in use.");
                        }
                    } else {
                        Server.logError("P2P socket was not binded because '" + HOSTNAME + "' is not a routeable hostname.");
                    }
                }
                Core.startTimer();
                Analise.initProcess();
                Peer.sendHeloToAll();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
        }
    }
    
    /**
     * Timer que controla os processos em background.
     */
    private static final Timer TIMER = new Timer("BCKGROUND");
    private static boolean running = true;

    public static void cancelTimer() {
        running = false;
        TIMER.cancel();
    }
    
    public static boolean isRunning() {
        return running;
    }
    
    private static class TimerInterruptTimeout extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Interromper conexões vencidas.
                Core.interruptTimeout();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerRefreshSPF extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Atualiza registro SPF mais consultado.
                SPF.refreshSPF();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerRefreshHELO extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Atualiza registro HELO mais consultado.
                SPF.refreshHELO();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerRefreshReverse extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Atualiza registro de IP reverso mais consultado.
                Reverse.refreshLast();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerRefreshWHOIS extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerRefreshWHOIS started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Atualiza registros WHOIS expirando.
                Server.tryRefreshWHOIS();
                Server.logTrace("TimerRefreshWHOIS finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredSPF extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredSPF started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Remoção de registros SPF expirados. 
                SPF.dropExpiredSPF();
                Server.logTrace("TimerDropExpiredSPF finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerCheckAccessSMTP extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerCheckAccessSMTP started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                Analise.checkAccessSMTP();
                Server.logTrace("TimerCheckAccessSMTP finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerSendHoldingWarningMessages extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerSendHoldingWarningMessages started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                User.sendHoldingWarning();
                Server.logTrace("TimerSendHoldingWarningMessages finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerSendWarningMessages extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerSendWarningMessages started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                User.sendWarningMessages();
                User.storeAndDropFinished();
                Server.logTrace("TimerSendWarningMessages finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredPeer extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredPeer started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Remoção de registros de reputação expirados. 
                Peer.dropExpired();
                Peer.sendHeloToAll();
                Server.logTrace("TimerDropExpiredPeer finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredHELO extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredHELO started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de DNS de HELO vencidos.
                SPF.dropExpiredHELO();
                Server.logTrace("TimerDropExpiredHELO finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredReverse extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredReverse started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de IP reverso vencidos.
                Reverse.dropExpired();
                Server.logTrace("TimerDropExpiredReverse finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredDistribution extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredDistribution started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas as distribuições e consultas vencidas.
                User.dropAllExpiredQuery();
//                SPF.dropExpiredDistribution();
//                Block.dropExpired();
                Server.logTrace("TimerDropExpiredDistribution finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredDefer extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDropExpiredDefer started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de atrazo programado vencidos.
                Defer.dropExpired();
                Server.logTrace("TimerDropExpiredDefer finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerStoreCache extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerStoreCache started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Armazena todos os registros atualizados durante a consulta.
                Server.tryStoreCache();
                Server.logTrace("TimerStoreCache finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDeleteLogExpired extends TimerTask {
        @Override
        public void run() {
            try {
                Server.logTrace("TimerDeleteLogExpired started.");
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apaga todos os arquivos de LOG vencidos.
                Server.deleteLogExpired();
                // Apaga todos as listas de analise vencidas.
                Analise.dropExpired();
                Server.logTrace("TimerDeleteLogExpired finished.");
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static long CACHE_TIME_STORE = 3600000; // Frequência de 1 hora.
    
    public static void setCacheTimeStore(String time) {
        if (time != null && time.length() > 0) {
            try {
                setCacheTimeStore(Integer.parseInt(time));
            } catch (Exception ex) {
                Server.logError("invalid cache time store '" + time + "'.");
            }
        }
    }
    
    public static synchronized void setCacheTimeStore(int time) {
        if (time < 0 || time > 1440) {
            Server.logError("invalid cache time store '" + time + "'.");
        } else {
            Core.CACHE_TIME_STORE = time * 60000;
        }
    }
    
    public static void startTimer() {
        TIMER.schedule(new TimerInterruptTimeout(), 10000, 10000); // Frequência de 10 segundos.
        TIMER.schedule(new TimerRefreshSPF(), 30000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshHELO(), 60000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshReverse(), 60000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshWHOIS(), 600000, 600000); // Frequência de 10 minutos.
        TIMER.schedule(new TimerSendHoldingWarningMessages(), 600000, 600000); // Frequência de 10 minutos.
        TIMER.schedule(new TimerDropExpiredPeer(), 900000, 1800000); // Frequência de 30 minutos.
        TIMER.schedule(new TimerDropExpiredSPF(), 600000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredHELO(), 1200000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredReverse(), 1200000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredDistribution(), 1800000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredDefer(), 2400000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerSendWarningMessages(), 3600000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDeleteLogExpired(), 3600000, 3600000); // Frequência de 1 hora.
        if (CACHE_TIME_STORE > 0) {
            TIMER.schedule(new TimerStoreCache(), CACHE_TIME_STORE, CACHE_TIME_STORE);
        }
        TIMER.schedule(new TimerCheckAccessSMTP(), 0, 86400000); // Frequência de 24 horas.
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

    public static File getQRCodeTempFile(String codigo) throws Exception {
        BitMatrix matrix = qrCodeWriter.encode(codigo, BarcodeFormat.QR_CODE, 256, 256);
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
        File file = File.createTempFile(Long.toString(Server.getNewUniqueTime()), ".png");
        ImageIO.write(image, "PNG", file);
        Server.logTrace("QRCode temp file created at " + file.getAbsolutePath() + ".");
        file.deleteOnExit();
        return file;
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
    
    public static boolean isLong(String text) {
        try {
            Long.parseLong(text);
            return true;
        } catch (Exception ex) {
            return false;
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
    
    public static boolean hasMiscellaneousSymbols(String text) {
        if (text == null) {
            return false;
        } else {
            for (char character : text.toCharArray()) {
                Character.UnicodeBlock block = Character.UnicodeBlock.of(character);
                if (block == Character.UnicodeBlock.MISCELLANEOUS_MATHEMATICAL_SYMBOLS_A) {
                    return true;
                } else if (block == Character.UnicodeBlock.MISCELLANEOUS_MATHEMATICAL_SYMBOLS_B) {
                    return true;
                } else if (block == Character.UnicodeBlock.MISCELLANEOUS_SYMBOLS) {
                    return true;
                } else if (block == Character.UnicodeBlock.MISCELLANEOUS_SYMBOLS_AND_ARROWS) {
                    return true;
                } else if (block == Character.UnicodeBlock.MISCELLANEOUS_SYMBOLS_AND_PICTOGRAPHS) {
                    return true;
                } else if (block == Character.UnicodeBlock.MISCELLANEOUS_TECHNICAL) {
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
    
    private static HashMap<String,KeyStore> KEYSTORE_MAP = new HashMap<>();
    
    public static synchronized void storeKeystoreMap() {
        for (String hostname : KEYSTORE_MAP.keySet()) {
            KeyStore keyStore = KEYSTORE_MAP.get(hostname);
            if (Core.validCertificate(keyStore, hostname)) {
                Core.storeKeyStore(keyStore, hostname);
            }
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
            removeExpiring(hostname);
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
            Server.logDebug("cannot request a certificate without a hostname.");
            return false;
        } else if (hostname.equals("localhost")) {
            Server.logDebug("cannot request a certificate for localhost.");
            return false;
        } else if (adminEmail == null) {
            Server.logDebug("cannot request a certificate without an admin e-mail.");
            return false;
        } else if (serverKeyPair == null) {
            Server.logDebug("cannot request a certificate without a server key pair.");
            return false;
        } else if (serviceHTTP == null) {
            Server.logDebug("cannot request a certificate without HTTP service.");
            return false;
        } else if (serviceHTTP.getPort() != 80) {
            Server.logDebug("cannot request a certificate because HTTP service is not binded at port 80.");
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
    
    private static synchronized boolean removeExpiring(String token) {
        return EXPIRING_SET.remove(token);
    }
    
    private static synchronized boolean addExpiring(String token) {
        return EXPIRING_SET.add(token);
    }
    
    public static synchronized boolean isExpiring(String token) {
        return EXPIRING_SET.contains(token);
    }
    
    public static boolean validCertificate(KeyStore keyStore, String hostname) {
        if (keyStore == null) {
            return false;
        } else {
            try {
                java.security.cert.Certificate cert = keyStore.getCertificate(hostname);
                if (cert == null) {
                    Server.logDebug("no " + hostname + " certificate at keystore.");
                    return updateCertificate(keyStore, hostname);
                } else if (cert instanceof X509Certificate) {
                    X509Certificate X509cert = (X509Certificate) cert;
                    try {
                        GregorianCalendar calendar = new GregorianCalendar();
                        calendar.add(Calendar.DAY_OF_YEAR, 30);
                        X509cert.checkValidity(calendar.getTime());
                        Server.logDebug(hostname + " certificate is valid.");
                        removeExpiring(hostname);
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
                                addExpiring(hostname);
                                return true;
                            }
                        } catch (CertificateExpiredException ex2) {
                            Server.logDebug("expired " + hostname + " certificate at keystore.");
                            return updateCertificate(keyStore, hostname);
                        } catch (CertificateNotYetValidException ex2) {
                            Server.logDebug("invalid " + hostname + " certificate at keystore.");
                            return updateCertificate(keyStore, hostname);
                        }
                    } catch (CertificateNotYetValidException ex) {
                        Server.logDebug("invalid " + hostname + " certificate at keystore.");
                        return updateCertificate(keyStore, hostname);
                    }
                } else {
                    Server.logDebug("invalid " + hostname + " certificate at keystore.");
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
        return BASE64.encodeAsString(compress(data));
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
        return decompress(BASE64.decode(data));
    }
    
    private static final Pattern EXECUTABLE_SIGNATURE_PATTERN = Pattern.compile("^"
            + "[0-9a-f]{32}\\.[0-9]+\\."
            + "(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh|zip|7z|rar)"
            + "$"
    );
    
    public static boolean isExecutableSignature(String token) {
        if (token == null) {
            return false;
        } else {
//            return Pattern.matches("^[0-9a-f]{32}\\.[0-9]+\\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh|zip|7z|rar)$", token);
            return EXECUTABLE_SIGNATURE_PATTERN.matcher(token).matches();
        }
    }
    
    private static final Pattern URL_SIGNATURE_PATTERN = Pattern.compile("^"
            + "[0-9a-f]{32}(\\.[a-z0-9_-]+)+\\.[0-9]+\\.https?"
            + "$"
    );
    
    public static boolean isSignatureURL(String token) {
        if (token == null) {
            return false;
        } else {
//            return Pattern.matches("^[0-9a-f]{32}(\\.[a-z0-9_-]+)+\\.[0-9]+\\.https?$", token);
            return URL_SIGNATURE_PATTERN.matcher(token).matches();
        }
    }
    
    public static String getSignatureHostURL(String token) {
        if (token == null) {
            return null;
        } else {
            Pattern pattern = Pattern.compile("^([0-9a-f]{32}((\\.[a-z0-9_-]+)+)\\.[0-9]+\\.https?)$");
            Matcher matcher = pattern.matcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                if (SubnetIPv4.isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (SubnetIPv6.isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                return host;
            } else {
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
            Pattern pattern = Pattern.compile("^([0-9a-f]{32}((\\.[a-z0-9_-]+)+)\\.([0-9]+)\\.(https?))$");
            Matcher matcher = pattern.matcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                if (SubnetIPv4.isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (SubnetIPv6.isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                String port = matcher.group(4);
                String protocol = matcher.group(5);
                if (protocol.equals("http") && port.equals("80")) {
                    port = "";
                } else if (protocol.equals("https") && port.equals("443")) {
                    port = "";
                } else {
                    port = ":" + port;
                }
                return protocol + "://" + host + port + "/";
            } else {
                return null;
            }
        }
    }
    
    public static String getSignatureHostnameURL(String token) {
        if (token == null) {
            return null;
        } else {
            Pattern pattern = Pattern.compile("^([0-9a-f]{32}((\\.[a-z0-9_-]+)+)\\.([0-9]+)\\.(https?))$");
            Matcher matcher = pattern.matcher(token);
            if (matcher.find()) {
                String host = matcher.group(2).substring(1);
                if (SubnetIPv4.isValidIPv4(host)) {
                    host = SubnetIPv4.reverseToIPv4(host);
                } else if (SubnetIPv6.isReverseIPv6(host)) {
                    host = SubnetIPv6.reverseToIPv6(host);
                    host = SubnetIPv6.tryTransformToIPv4(host);
                }
                return host;
            } else {
                return null;
            }
        }
    }
    
    private static final Pattern URL_SIG_PATTERN = Pattern.compile("^(https?)\\:\\/\\/([a-z0-9\\._-]+|\\[[a-f0-9\\:]+\\])(:([0-9]{1,6}))?(\\/|\\?|#|$)");
    private static final Pattern URL_IPV6_PATTERN = Pattern.compile("^\\[([a-f0-9\\:]+)\\]$");
    
    public static boolean isValidURL(String url) {
        if (url == null) {
            return false;
        } else {
            return URL_SIG_PATTERN.matcher(url).find();
        }
    }
    
    public static String md2Hex(String token) {
        if (token == null) {
            return null;
        } else {
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(token.getBytes());
                byte[] digest = md.digest();
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b & 0xff));
                }
                return sb.toString();
            } catch (NoSuchAlgorithmException ex) {
                return null;
            }
        }
    }
    
    public static String getSignatureURL(String url) {
        Matcher matcher = URL_SIG_PATTERN.matcher(url);
        if (matcher.find()) {
            String protocol = matcher.group(1).toLowerCase();
            String host = matcher.group(2).toLowerCase();
            String port = matcher.group(4);
            if (port == null) {
                if (protocol.equals("http")) {
                    port = "80";
                } else {
                    port = "443";
                }
            }
            if (SubnetIPv4.isValidIPv4(host)) {
                host = SubnetIPv4.reverseToIPv4(host);
            } else if ((matcher = URL_IPV6_PATTERN.matcher(host)).find() && SubnetIPv6.isValidIPv6(matcher.group(1))) {
                host = SubnetIPv6.reverseToIPv6(matcher.group(1));
            }
            String signature = md2Hex(url);
            return signature + "." + host + "." + port + "." + protocol;
        } else {
            return null;
        }
    }
    
    private static final Pattern URL_SHORTENER_PATTERN = Pattern.compile(
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
                    + "zipmyurl\\.com|zz\\.gd|back\\.ly|ouo\\.io)\\/"
    );
    
    public static boolean isShortenerURL(String url) {
        if (url == null) {
            return false;
        } else {
            return URL_SHORTENER_PATTERN.matcher(url).find();
        }
    }
}
