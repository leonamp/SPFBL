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

import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.MailConnectException;
import it.sauronsoftware.junique.AlreadyLockedException;
import it.sauronsoftware.junique.JUnique;
import it.sauronsoftware.junique.MessageHandler;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import net.spfbl.whois.QueryTCP;
import net.spfbl.spf.QuerySPF;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.mail.Address;
import javax.mail.AuthenticationFailedException;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.data.NoReply;
import net.spfbl.dns.QueryDNS;
import net.spfbl.http.ServerHTTP;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Core {
    
    private static final byte VERSION = 2;
    private static final byte SUBVERSION = 5;
    private static final byte RELEASE = 0;
    private static final boolean TESTING = false;
    
    public static String getAplication() {
        return "SPFBL-" + getVersion() + (TESTING ? "-TESTING" : "");
    }
    
    public static String getVersion() {
        return VERSION + "." + SUBVERSION + "." + RELEASE;
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
    
    public static String sendCommandToPeer(
            String command,
            String address,
            int port
            ) {
        if (peerUDP == null) {
            return "DISABLED";
        } else {
            return peerUDP.send(command, address, port);
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
    
    private static ServerHTTP complainHTTP = null;
    
    public static final Huffman HUFFMAN = Huffman.load();
    
    public static final Base64 BASE64 = new Base64(0, new byte[0], true);
    
    public static String getReleaseURL(String id) throws ProcessException {
        if (complainHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            Defer defer = Defer.getDefer(id);
            String url = complainHTTP.getURL();
            if (defer == null) {
                return null;
            } else if (url == null) {
                return null;
            } else {
                try {
                    long time = System.currentTimeMillis();
                    String ticket = "release " + id;
                    byte[] byteArray = Core.HUFFMAN.encodeByteArray(ticket, 8);
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
    
    public static String getDNSBLURL(String token) throws ProcessException {
        if (complainHTTP == null) {
            return null;
        } else if (token == null) {
            return null;
        } else {
            String url = complainHTTP.getDNSBLURL();
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
            String result,
            String recipient
            ) throws ProcessException {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail == null) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (sender == null) {
            return null;
        } else if (!Domain.isValidEmail(sender)) {
            return null;
        } else if (recipient == null) {
            return null;
        } else if (!Domain.isValidEmail(recipient)) {
            return null;
        } else if (complainHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = complainHTTP.getURL();
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
                    byte[] byteArray = Core.HUFFMAN.encodeByteArray(ticket, 8);
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
    
    public static String getUnblockURL(
            String client,
            String ip
            ) throws ProcessException {
        if (client == null) {
            return null;
        } else if (!Domain.isEmail(client)) {
            return null;
        } else if (ip == null) {
            return null;
        } else if (complainHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = complainHTTP.getURL();
            if (url == null) {
                return null;
            } else {
                try {
                    long time = System.currentTimeMillis();
                    String ticket = "unblock";
                    ticket += ' ' + client;
                    ticket += ' ' + ip;
                    byte[] byteArray = Core.HUFFMAN.encodeByteArray(ticket, 8);
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
    
    public static String getWhiteURL(
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
        } else if (complainHTTP == null) {
            return null;
        } else if (Core.hasRecaptchaKeys()) {
            String url = complainHTTP.getURL();
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
                    byte[] byteArray = Core.HUFFMAN.encodeByteArray(ticket, 8);
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
//                try {
//                    String ticket = Server.getNewTicketDate();
//                    ticket += ' ' + white;
//                    ticket += ' ' + client;
//                    ticket += ' ' + ip;
//                    ticket += ' ' + sender;
//                    ticket += ' ' + recipient;
//                    ticket += hostname == null ? "" : ' ' + hostname;
//                    ticket = Server.encrypt(ticket);
//                    ticket = URLEncoder.encode(ticket, "UTF-8");
//                    return url + ticket;
//                } catch (Exception ex) {
//                    throw new ProcessException("FATAL", ex);
//                }
            }
        } else {
            return null;
        }
    }
    
    public static String getURL() {
        if (complainHTTP == null) {
            return null;
        } else {
            return complainHTTP.getURL();
        }
    }
    
//    public static String getSpamURL(String recipient) {
//        if (complainHTTP == null) {
//            return null;
//        } else if (recipient == null) {
//            return complainHTTP.getSpamURL();
//        } else {
//            int index = recipient.lastIndexOf('@');
//            String domain = recipient.substring(index + 1).toLowerCase();
//            return complainHTTP.getSpamURL(domain);
//        }
//    }
    
    public static String dropURL(String domain) {
        if (complainHTTP == null) {
            return null;
        } else {
            return complainHTTP.drop(domain);
        }
    }
    
    public static boolean addURL(String domain, String url) {
        if (complainHTTP == null) {
            return false;
        } else {
            return complainHTTP.put(domain, url);
        }
    }
    
    public static void loadURL() {
        if (complainHTTP != null) {
            complainHTTP.load();
        }
    }
    
    public static void storeURL() {
        if (complainHTTP != null) {
            complainHTTP.store();
        }
    }
    
    public static HashMap<String,String> getMapURL() {
        if (complainHTTP == null) {
            return new HashMap<String,String>();
        } else {
            return complainHTTP.getMap();
        }
    }
    
    private static AdministrationTCP administrationTCP = null;
    private static QuerySPF querySPF = null;
    private static QueryDNS queryDNSBL = null;
    private static PeerUDP peerUDP = null;
    
    public static void interruptTimeout() {
        if (administrationTCP != null) {
            administrationTCP.interruptTimeout();
        }
        if (querySPF != null) {
            querySPF.interruptTimeout();
        }
        if (queryDNSBL != null) {
            queryDNSBL.interruptTimeout();
        }
        if (peerUDP != null) {
            peerUDP.interruptTimeout();
        }
    }
    
    public static boolean loadConfiguration() {
        File confFile = new File("spfbl.conf");
        if (confFile.exists()) {
            try {
                Properties properties = new Properties();
                FileInputStream confIS = new FileInputStream(confFile);
                try {
                    properties.load(confIS);
                    Server.setLogFolder(properties.getProperty("log_folder"));
                    Server.setLogExpires(properties.getProperty("log_expires"));
                    Server.setProviderDNS(properties.getProperty("dns_provider"));
                    Core.setHostname(properties.getProperty("hostname"));
                    Core.setInterface(properties.getProperty("interface"));
                    Core.setAdminEmail(properties.getProperty("admin_email"));
                    Core.setIsAuthSMTP(properties.getProperty("smtp_auth"));
                    Core.setStartTLSSMTP(properties.getProperty("smtp_starttls"));
                    Core.setHostSMTP(properties.getProperty("smtp_host"));
                    Core.setPortSMTP(properties.getProperty("smpt_port")); // Version: 2.4
                    Core.setPortSMTP(properties.getProperty("smtp_port"));
                    Core.setUserSMTP(properties.getProperty("smtp_user"));
                    Core.setPasswordSMTP(properties.getProperty("smtp_password"));
                    Core.setPortAdmin(properties.getProperty("admin_port"));
                    Core.setPortWHOIS(properties.getProperty("whois_port"));
                    Core.setPortSPFBL(properties.getProperty("spfbl_port"));
                    Core.setPortDNSBL(properties.getProperty("dnsbl_port"));
                    Core.setPortHTTP(properties.getProperty("http_port"));
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
                    Core.setReverseRequired(properties.getProperty("reverse_required"));
                    Core.setLevelLOG(properties.getProperty("log_level"));
                    Core.setRecaptchaKeySite(properties.getProperty("recaptcha_key_site"));
                    Core.setRecaptchaKeySecret(properties.getProperty("recaptcha_key_secret"));
                    Core.setCacheTimeStore(properties.getProperty("cache_time_store"));
                    PeerUDP.setConnectionLimit(properties.getProperty("peer_limit"));
                    QueryDNS.setConnectionLimit(properties.getProperty("dnsbl_limit"));
                    QuerySPF.setConnectionLimit(properties.getProperty("spfbl_limit"));
                    Analise.setAnaliseExpires(properties.getProperty("analise_expires"));
                    Analise.setAnaliseIP(properties.getProperty("analise_ip"));
                    Analise.setAnaliseMX(properties.getProperty("analise_mx"));
                    return true;
                } finally {
                    confIS.close();
                }
            } catch (IOException ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    public static boolean hasAdminEmail() {
        return ADMIN_EMAIL != null;
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
                return user.getInternetAddress();
            }
        }
    }
    
    public static String getAdminEmail() {
        return ADMIN_EMAIL;
    }
    
    public static short getPortAdmin() {
        return PORT_ADMIN;
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
    
    public static boolean hasInterface() {
        return INTERFACE != null;
    }
    
    public static String getInterface() {
        return INTERFACE;
    }
    
    public static String getHostname() {
        return HOSTNAME;
    }
    
    public static boolean hasHostname() {
        return HOSTNAME != null;
    }
    
    private static String HOSTNAME = null;
    private static String INTERFACE = null;
    private static String ADMIN_EMAIL = null;
    private static short PORT_ADMIN = 9875;
    private static short PORT_WHOIS = 0;
    private static short PORT_SPFBL = 9877;
    private static short PORT_DNSBL = 0;
    private static short PORT_HTTP = 0;
    private static short UDP_MAX = 512; // UDP max size packet.
    
    private static boolean isRouteable(String hostame) {
        try {
            Attributes attributesA = Server.getAttributesDNS(
                    hostame, new String[]{"A"});
            Attribute attributeA = attributesA.get("A");
            if (attributeA == null) {
                Attributes attributesAAAA = Server.getAttributesDNS(
                        hostame, new String[]{"AAAA"});
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
            if (Domain.isEmail(email)) {
                Core.ADMIN_EMAIL = email.toLowerCase();
            } else {
                Server.logError("invalid admin e-mail '" + email + "'.");
            }
        }
    }
    
    public static void setPortAdmin(String port) {
        if (port != null && port.length() > 0) {
            try {
                setPortAdmin(Integer.parseInt(port));
            } catch (Exception ex) {
                Server.logError("invalid administration port '" + port + "'.");
            }
        }
    }
    
    public static synchronized void setPortAdmin(int port) {
        if (port < 1 || port > Short.MAX_VALUE) {
            Server.logError("invalid administration port '" + port + "'.");
        } else {
            Core.PORT_ADMIN = (short) port;
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
    
    private static byte FLOOD_MAX_RETRY = 16;
    
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
    
    private static byte DEFER_TIME_FLOOD = 1;
    
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
    
    private static byte DEFER_TIME_RED = 25;
    
    public static byte getDeferTimeBLACK() {
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
        if (time < 0 || time > Integer.MAX_VALUE) {
            Server.logError("invalid DEFER time for RED '" + time + "'.");
        } else {
            Core.DEFER_TIME_RED = (byte) time;
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
            if (Domain.isEmail(user) || Domain.isHostname(user)) {
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
    
    private static short REPUTATION_LIMIT = 1024;
    
    public static short getReputationLimit() {
        return REPUTATION_LIMIT;
    }
    
    public static final DecimalFormat CENTENA_FORMAT = new DecimalFormat("000");
    
    public static final NumberFormat DECIMAL_FORMAT = NumberFormat.getNumberInstance();
    
    public static final NumberFormat PERCENT_FORMAT = NumberFormat.getPercentInstance();
    
    public static final SimpleDateFormat SQL_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    
    /**
     * Constante para formatar datas com hora no padrão de e-mail.
     */
    private static final SimpleDateFormat DATE_EMAIL_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US);
    
    public static synchronized String getEmailDate() {
        return DATE_EMAIL_FORMAT.format(new Date());
    }
    
    public static boolean hasSMTP() {
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
    
    private static final LinkedList<Message> MESSAGE_QUEUE = new LinkedList<Message>();
    
    public static void sendAllMessages() {
        int count = MESSAGE_QUEUE.size();
        while (count-- > 0) {
            sendNextMessage();
        }
    }
    
    public static void sendNextMessage() {
        Message message = MESSAGE_QUEUE.poll();
        if (message != null) {
            try {
                sendMessage(message);
            } catch (ProcessException ex) {
                Throwable cause = ex.getCause(SMTPAddressFailedException.class);
                if (cause == null) {
                    MESSAGE_QUEUE.offer(message);
                    Server.logError(ex);
                } else {
                    SMTPAddressFailedException afEx = (SMTPAddressFailedException) cause;
                    Server.logDebug("SMTP " + afEx.getMessage());
                    try {
                        InternetAddress address = afEx.getAddress();
                        NoReply.add(address.getAddress());
                    } catch (ProcessException ex2) {
                        Server.logError(ex2);
                    }
                }
            } catch (Exception ex) {
                MESSAGE_QUEUE.offer(message);
                Server.logError(ex);
            }
        }
    }
    
    public static boolean offerMessage(Message message) {
        return MESSAGE_QUEUE.offer(message);
    }
    
    private static void sendMessage(Message message) throws Exception {
        if (message != null && hasSMTP()) {
            Server.logInfo("sending e-mail message.");
            Server.logSendMTP("authenticate: " + Boolean.toString(SMTP_IS_AUTH) + ".");
            Server.logSendMTP("start TLS: " + Boolean.toString(SMTP_STARTTLS) + ".");
            Properties props = System.getProperties();
            props.put("mail.smtp.auth", Boolean.toString(SMTP_IS_AUTH));
            props.put("mail.smtp.starttls.enable", Boolean.toString(SMTP_STARTTLS));
            props.put("mail.smtp.host", SMTP_HOST);
            props.put("mail.smtp.port", Short.toString(SMTP_PORT));
            props.put("mail.smtp.ssl.trust", SMTP_HOST);
            Address[] recipients = message.getRecipients(Message.RecipientType.TO);
            Session session = Session.getDefaultInstance(props);
            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
            try {
                transport.setLocalHost(HOSTNAME);
                Server.logSendMTP("connecting to " + SMTP_HOST + ":" + SMTP_PORT + ".");
                transport.connect(SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD);
                Server.logSendMTP("sending '" + message.getSubject() + "'.");
                transport.sendMessage(message, recipients);
                Server.logSendMTP("message '" + message.getSubject() + "' sent.");
            } catch (AuthenticationFailedException ex) {
                Server.logSendMTP("authentication failed.");
            } catch (MailConnectException ex) {
                Server.logSendMTP("connection failed.");
            } catch (MessagingException ex) {
                Server.logSendMTP("messaging failed.");
                throw new ProcessException("Falha de envio SMTP.", ex);
            } finally {
                if (transport.isConnected()) {
                    transport.close();
                    Server.logSendMTP("connection closed.");
                }
            }
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
                    administrationTCP = new AdministrationTCP(PORT_ADMIN);
                    administrationTCP.start();
                } catch (BindException ex) {
                    Server.logError("system could not start because TCP port " + PORT_ADMIN + " is already in use.");
                    System.exit(1);
                }
                if (PORT_WHOIS > 0) {
                    try {
                        new QueryTCP(PORT_WHOIS).start();
                    } catch (BindException ex) {
                        Server.logError("WHOIS socket was not binded because TCP port " + PORT_WHOIS + " is already in use.");
                    }
                }
                if (PORT_SPFBL > 0) {
                    try {
                        querySPF = new QuerySPF(PORT_SPFBL);
                        querySPF.start();
                    } catch (BindException ex) {
                        querySPF = null;
                        Server.logError("SPFBL socket was not binded because TCP port " + PORT_SPFBL + " is already in use.");
                    }
                    if (HOSTNAME == null) {
                        Server.logInfo("P2P socket was not binded because no hostname defined.");
                    } else if (isRouteable(HOSTNAME)) {
                        try {
                            peerUDP = new PeerUDP(HOSTNAME, PORT_SPFBL, UDP_MAX);
                            peerUDP.start();
                        } catch (BindException ex) {
                            peerUDP = null;
                            Server.logError("P2P socket was not binded because UDP port " + PORT_SPFBL + " is already in use.");
                        }
                    } else {
                        Server.logError("P2P socket was not binded because '" + HOSTNAME + "' is not a routeable hostname.");
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
                if (PORT_HTTP > 0 ) {
                    if (HOSTNAME == null) {
                        Server.logInfo("HTTP socket was not binded because no hostname defined.");
                    } else {
                        try {
                            complainHTTP = new ServerHTTP(HOSTNAME, PORT_HTTP);
                            complainHTTP.load();
                            complainHTTP.start();
                        } catch (BindException ex) {
                            complainHTTP = null;
                            Server.logError("HTTP socket was not binded because TCP port " + PORT_HTTP + " is already in use.");
                        }
                    }
                }
                Peer.sendHeloToAll();
                Core.startTimer();
                Analise.initProcess();
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

    public static void cancelTimer() {
        TIMER.cancel();
    }
    
    private static class TimerSendMessage extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Enviar próxima mensagem de e-mail.
                Core.sendAllMessages();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
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
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Atualiza registros WHOIS expirando.
                Server.tryRefreshWHOIS();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredSPF extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Remoção de registros SPF expirados. 
                SPF.dropExpiredSPF();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerSendHeloToAll extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Envio de PING para os peers cadastrados.
                Peer.sendHeloToAll();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredPeer extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Remoção de registros de reputação expirados. 
                Peer.dropExpired();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredHELO extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de DNS de HELO vencidos.
                SPF.dropExpiredHELO();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredReverse extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de IP reverso vencidos.
                Reverse.dropExpired();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredDistribution extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas as distribuições vencidas.
                SPF.dropExpiredDistribution();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDropExpiredDefer extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apagar todas os registros de atrazo programado vencidos.
                Defer.dropExpired();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerStoreCache extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Armazena todos os registros atualizados durante a consulta.
                Server.tryStoreCache(true);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static class TimerDeleteLogExpired extends TimerTask {
        @Override
        public void run() {
            try {
                Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                // Apaga todos os arquivos de LOG vencidos.
                Server.deleteLogExpired();
                // Apaga todos as listas de analise vencidas.
                Analise.dropExpired();
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
        TIMER.schedule(new TimerSendMessage(), 30000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerInterruptTimeout(), 1000, 1000); // Frequência de 1 segundo.
        TIMER.schedule(new TimerRefreshSPF(), 30000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshHELO(), 60000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshReverse(), 60000, 60000); // Frequência de 1 minuto.
        TIMER.schedule(new TimerRefreshWHOIS(), 600000, 600000); // Frequência de 10 minutos.
        TIMER.schedule(new TimerDropExpiredPeer(), 900000, 1800000); // Frequência de 30 minutos.
        TIMER.schedule(new TimerSendHeloToAll(), 1800000, 1800000); // Frequência de 30 minutos.
        TIMER.schedule(new TimerDropExpiredSPF(), 600000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredHELO(), 1200000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredReverse(), 1200000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredDistribution(), 1800000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDropExpiredDefer(), 2400000, 3600000); // Frequência de 1 hora.
        TIMER.schedule(new TimerDeleteLogExpired(), 3600000, 3600000); // Frequência de 1 hora.
        if (CACHE_TIME_STORE > 0) {
            TIMER.schedule(new TimerStoreCache(), CACHE_TIME_STORE, CACHE_TIME_STORE);
        }
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
    
    private static final Runtime RUNTIME = Runtime.getRuntime();
    
    public static float relativeFreeMemory() {
        return (float) RUNTIME.freeMemory() / (float) RUNTIME.maxMemory();
    }
    
    public static boolean hasLowMemory() {
        return relativeFreeMemory() < 0.0625f;
    }
    
    private static final QRCodeWriter qrCodeWriter = new QRCodeWriter();

    public static File getQRCodeTempFile(String codigo) throws Exception {
        BitMatrix matrix = qrCodeWriter.encode(codigo, com.google.zxing.BarcodeFormat.QR_CODE, 256, 256);
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
        ImageIO.write(image, "png", file);
        Server.logTrace("QRCode temp file created at " + file.getAbsolutePath() + ".");
        file.deleteOnExit();
        return file;
    }
    
    public static boolean isLong(String text) {
        try {
            Long.parseLong(text);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}
