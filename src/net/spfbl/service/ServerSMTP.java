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
package net.spfbl.service;

import com.github.junrar.Archive;
import com.github.junrar.exception.RarException;
import com.github.junrar.rarfile.FileHeader;
import com.sun.mail.dsn.DeliveryStatus;
import com.sun.mail.dsn.DispositionNotification;
import com.sun.mail.dsn.MultipartReport;
import com.sun.mail.iap.ConnectionException;
import com.sun.mail.imap.IMAPBodyPart;
import com.sun.mail.imap.IMAPMessage;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.smtp.SMTPSendFailedException;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.FolderClosedIOException;
import net.spfbl.spf.SPF;
import com.sun.mail.util.MailConnectException;
import com.sun.mail.util.SocketConnectException;
import de.agitos.dkim.DKIMSigner;
import net.spfbl.core.Server;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import javax.activation.DataSource;
import javax.mail.Address;
import javax.mail.AuthenticationFailedException;
import javax.mail.Authenticator;
import javax.mail.BodyPart;
import javax.mail.Flags;
import javax.mail.Folder;
import javax.mail.FolderClosedException;
import javax.mail.Header;
import javax.mail.Message;
import javax.mail.MessageRemovedException;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.PasswordAuthentication;
import javax.mail.SendFailedException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeUtility;
import javax.mail.util.SharedByteArrayInputStream;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import net.spfbl.core.Action;
import net.spfbl.core.Core;
import static net.spfbl.core.Core.Level.*;
import net.spfbl.core.DKIMMimeMessage;
import net.spfbl.core.Defer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isValidEmail;
import net.spfbl.core.Reverse;
import net.spfbl.core.SPFBLMimeMessage;
import net.spfbl.core.SimpleMimeMessage;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.CIDR;
import net.spfbl.data.DKIM;
import net.spfbl.data.Dictionary;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.FQDN;
import net.spfbl.data.Reputation;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.spf.SPF.Qualifier;
import static net.spfbl.spf.SPF.Qualifier.PASS;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.text.PDFTextStripper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * Servidor de consulta em ESMTP.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class ServerSMTP extends Server {

    private final int PORTS;
    private final String HOSTNAME;
    private final String POSTMASTER;
    private final ServerSocket SERVER;
    private SSLServerSocket SERVERS = null;
    private final QueueThread QUEUE;

    public ServerSMTP(String hostname, int ports, String postmaster) throws IOException {
        super("SERVRSMTP");
        PORTS = ports;
        HOSTNAME = hostname;
        POSTMASTER = postmaster;
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logInfo("binding SMTP socket on port 25...");
        SERVER = new ServerSocket(25);
        QUEUE = new QueueThread();
        Server.logTrace(getName() + " thread allocation.");
    }
    
    @Override
    public void run() {
        if (PORTS == 0) {
            startService();
        } else if (HOSTNAME == null) {
            Server.logInfo("SPFBLS socket was not binded because no hostname defined.");
        } else {
            KeyStore keyStore = Core.loadKeyStore(HOSTNAME);
            if (keyStore == null) {
                Server.logError("SPFBLS socket was not binded because " + HOSTNAME + " keystore not exists.");
            } else {
                try {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(keyStore, HOSTNAME.toCharArray());
                    KeyManager[] km = kmf.getKeyManagers();
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(keyStore);
                    TrustManager[] tm = tmf.getTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(km, tm, null);
                    SNIHostName serverName = new SNIHostName(HOSTNAME);
                    ArrayList<SNIServerName> serverNames = new ArrayList<>(1);
                    serverNames.add(serverName);
                    try {
                        Server.logInfo("binding SMTPS socket on port " + PORTS + "...");
                        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
                        SERVERS = (SSLServerSocket) socketFactory.createServerSocket(PORTS);
                        SSLParameters params = SERVERS.getSSLParameters();
                        params.setServerNames(serverNames);
                        SERVERS.setSSLParameters(params);
                        Thread sslService = new Thread() {
                            @Override
                            public void run() {
                                setName("SERVRSMTP");
                                startServiceSSL();
                            }
                        };
                        sslService.start();
                    } catch (BindException ex) {
                        Server.logError("SMTPS socket was not binded because TCP port " + PORTS + " is already in use.");
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            startService();
        }
    }
    
    private void startService() {
        try {
            Server.logInfo("listening ESMTP connections on port 25.");
            QUEUE.start();
            while (continueListenning()) {
                try {
                    Socket socket = SERVER.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "421 Too many concurrent SMTP connections.\r\n");
                        } else {
                            connection.process(socket, time, false);
                        }
                    } else {
                        socket.close();
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("ESMTP server closed.");
        }
    }
    
    private void startServiceSSL() {
        try {
            Server.logInfo("listening queries on SMTPS port " + PORTS + ".");
            while (continueListenning()) {
                try {
                    Socket socket = SERVERS.accept();
                    if (continueListenning()) {
                        long time = System.currentTimeMillis();
                        Connection connection = pollConnection();
                        if (connection == null) {
                            sendMessage(time, socket, "TOO MANY CONNECTIONS\n");
                        } else {
                            connection.process(socket, time, true);
                        }
                    } else {
                        socket.close();
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logInfo("querie SMTPS server closed.");
        }
    }

    private static void sendMessage(
            long timeKey,
            Socket socket, String message
            ) throws IOException {
        InetAddress address = socket.getInetAddress();
        String origin = address.getHostAddress();
        String fqdn = FQDN.getFQDN(origin, false);
        if (fqdn != null) {
            origin += ' ' + fqdn;
        }
        try {
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(message.getBytes("ISO-8859-1"));
            socket.close();
        } catch (SSLHandshakeException ex) {
            Server.logDebug(timeKey, ex.getMessage());
        } catch (SSLException ex) {
            Server.logDebug(timeKey, ex.getMessage());
        } finally {
            Server.logQuery(timeKey, "ESMTP",
                origin,
                timeKey, message, null
                );
        }
    }
    
    public static Properties newProperties(
            String host, Integer port,
            String user, String password
    ) {
        if (port == null) {
            return newProperties(host, 25, true, user, password);
        } else {
            return newProperties(host, port, true, user, password);
        }
    }
    
    public static Properties newProperties(
            String host, int port, boolean tls
    ) {
        return newProperties(host, port, tls, null, null);
    }
    
    public static Properties newProperties(
            String host, int port, boolean tls,
            String user, String password
    ) {
        if (host == null) {
            return null;
        } else if (port < 1 || port > Short.MAX_VALUE) {
            return null;
        } else if (user == null || password == null) {
            Properties props = new Properties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.auth", "false");
            props.put("mail.smtp.port", Integer.toString(port));
            props.put("mail.smtp.timeout", "60000");   
            props.put("mail.smtp.connectiontimeout", "3000");
            props.put("mail.smtp.starttls.enable", Boolean.toString(tls));
            props.put("mail.smtp.host", host);
            props.put("mail.smtp.ssl.trust", host);
            return props;
        } else {
            Properties props = new Properties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.port", Integer.toString(port));
            props.put("mail.smtp.timeout", "60000");   
            props.put("mail.smtp.connectiontimeout", "3000");
            props.put("mail.smtp.starttls.enable", Boolean.toString(tls));
            props.put("mail.smtp.host", host);
            props.put("mail.smtp.ssl.trust", host);
            props.put("mail.smtp.user", user);
            props.put("mail.smtp.password", password);
            if (isValidEmail(user)) {
                props.put("mail.smtp.from", user);
            }
            return props;
        }
    }
    
    public static boolean sendMessage(
            Locale locale,
            Message message,
            InternetAddress[] recipients,
            InternetAddress[] recipientsBCC
    ) throws Exception {
        if (locale == null) {
            return false;
        } else if (message == null) {
            return false;
        } else if (recipients == null) {
            return false;
        } else {
            boolean sent = false;
            for (InternetAddress recipient : recipients) {
                if (sendMessage(locale, message, recipient)) {
                    sent = true;
                }
            }
            if (sent && recipientsBCC != null) {
                for (InternetAddress recipient : recipientsBCC) {
                    try {
                        sendMessage(locale, message, recipient);
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
            }
            return sent;
        }
    }
    
    public static boolean sendMessage(
            Locale locale,
            Message message,
            String email,
            String emailBCC
    ) throws Exception {
        if (locale == null) {
            return false;
        } else if (message == null) {
            return false;
        } else if (email == null) {
            return false;
        } else if (emailBCC == null) {
            return sendMessage(
                    locale,
                    message,
                    InternetAddress.parse(email),
                    null
            );
        } else {
            return sendMessage(
                    locale,
                    message,
                    InternetAddress.parse(email),
                    InternetAddress.parse(emailBCC)
            );
        }
    }
    
    public static boolean sendMessage(
            Locale locale,
            Message message,
            InternetAddress recipient
    ) throws Exception {
        return sendMessage(locale, message, recipient, null, false);
    }
    
    public static boolean sendMessage(
            Locale locale,
            Message message,
            InternetAddress recipient,
            InternetHeaders status,
            boolean bounce
    ) throws Exception {
        if (locale == null) {
            return false;
        } else if (message == null) {
            return false;
        } else if (recipient == null) {
            return false;
        } else {
            String domain = null;
            try {
                Properties[] propsArray = User.getSessionProperties(recipient);
                if (propsArray == null) {
                    if (Core.isDirectSMTP()) {
                        String email = recipient.getAddress();
                        int index = email.indexOf('@') + 1;
                        domain = email.substring(index);
                        ArrayList<String> mxSet = Reverse.getMXSet(domain, false);
                        if (mxSet == null || mxSet.isEmpty()) {
                            return false;
                        } else {
                            index = 0;
                            int size = mxSet.size() * 2;
                            propsArray = new Properties[size];
                            for (String mx : mxSet) {
                                propsArray[index++] = newProperties(mx, 25, true);
                            }
                            for (String mx : mxSet) {
                                propsArray[index++] = newProperties(mx, 25, false);
                            }
                        }
                    } else {
                        propsArray = Core.getRelaySessionProperties();
                    }
                }
                if (bounce && propsArray != null) {
                    for (Properties props : propsArray) {
                        props.put("mail.smtp.from", "<>");
                    }
                }
                if (status == null) {
                    String url = Core.getListUnsubscribeURL(locale, recipient);
                    if (url != null) {
                        message.setHeader("List-Unsubscribe", "<" + url + ">");
                    }
                    message.saveChanges();
                }
                InternetAddress[] recipients = {recipient};
                return sendMessage(
                        Core.getHostname(),
                        propsArray,
                        null,
                        message,
                        recipients,
                        status
                );
            } catch (NameNotFoundException ex) {
                Server.logSendSMTP("non-existent domain: " + domain);
                setHeader(status, "Remote-MTA", null);
                setHeader(status, "Last-Attempt-Date", Core.getEmailDate());
                setHeader(status, "Action", "failed");
                setHeader(status, "Status", "1.0.1");
                setHeader(status, "Diagnostic-Code", "dns; " + ex.getMessage());
                throw ex;
            } catch (CommunicationException ex) {
                if (ex.getCause() instanceof SocketTimeoutException) {
                    Server.logSendSMTP("DNS timeout: " + domain);
                } else if (ex.getCause() instanceof IOException) {
                    Server.logSendSMTP("DNS unreachable: " + domain);
                } else {
                    Server.logError(ex);
                }
                setHeader(status, "Remote-MTA", null);
                setHeader(status, "Last-Attempt-Date", Core.getEmailDate());
                setHeader(status, "Action", "delayed");
                setHeader(status, "Status", "1.0.1");
                setHeader(status, "Diagnostic-Code", "dns; " + ex.getMessage());
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logSendSMTP("DNS unavailable: " + domain);
                setHeader(status, "Remote-MTA", null);
                setHeader(status, "Last-Attempt-Date", Core.getEmailDate());
                setHeader(status, "Action", "delayed");
                setHeader(status, "Status", "1.0.1");
                setHeader(status, "Diagnostic-Code", "dns; " + ex.getMessage());
                return false;
            } catch (NamingException ex) {
                Server.logError(ex);
                setHeader(status, "Remote-MTA", null);
                setHeader(status, "Last-Attempt-Date", Core.getEmailDate());
                setHeader(status, "Action", "failed");
                setHeader(status, "Status", "1.0.1");
                setHeader(status, "Diagnostic-Code", "dns; " + ex.getMessage());
                return false;
            }
        }
    }
    
    private static boolean sendMessage(
            String HOSTNAME,
            Properties[] propsArray,
            InternetAddress from,
            Message message,
            InternetAddress[] recipients,
            InternetHeaders status
    ) throws Exception {
        if (propsArray == null) {
            return false;
        } else {
            Exception exception = null;
            MailConnectException mailConnectException = null;
            AuthenticationFailedException authenticationFailedException = null;
            MessagingException messagingException = null;
            for (Properties props : propsArray) {
                try {
                    if (sendMessage(HOSTNAME, props, from, message, recipients, status)) {
                        return true;
                    }
                } catch (MailConnectException ex) {
                    mailConnectException = ex;
                } catch (AuthenticationFailedException ex) {
                    authenticationFailedException = ex;
                } catch (SendFailedException ex) {
                    throw ex;
                } catch (MessagingException ex) {
                    messagingException = ex;
                } catch (Exception ex) {
                    exception = ex;
                }
            }
            if (messagingException != null) {
                throw messagingException;
            } else if (authenticationFailedException != null) {
                throw authenticationFailedException;
            } else if (mailConnectException!= null) {
                throw mailConnectException;
            } else if (exception != null) {
                throw exception;
            } else {
                return false;
            }
        }
    }
    
    public static boolean sendMessage(
            Properties props,
            Message message,
            InternetAddress[] recipients
    ) throws Exception {
        return sendMessage(
                Core.getHostname(),
                props,
                null,
                message,
                recipients,
                null
        );
    }
    
    public static boolean sendMessage(
            Properties props,
            Message message,
            InternetAddress from,
            InternetAddress[] recipients
    ) throws Exception {
        return sendMessage(
                Core.getHostname(),
                props,
                from,
                message,
                recipients,
                null
        );
    }
    
    private static final Regex ENVELOPE_FROM_PATTERN = new Regex("^"
            + "from ("
            + "([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*\\.?"
            + "|"
            + "\\[("
            + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "|"
            + "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,7}:"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
            + "|"
            + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
            + "|"
            + ":((:[0-9a-fA-F]{1,4}){1,7}|:)"
            + ")\\]"
            + ") "
            + "("
            + "\\("
            + "((([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*\\.?) )?"
            + "\\[("
            + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "|"
            + "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,7}:"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
            + "|"
            + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
            + "|"
            + ":((:[0-9a-fA-F]{1,4}){1,7}|:)"
            + ")\\](:[0-9]+)?"
            + "( helo=(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*))?"
            + "\\)"
            + "|"
            + "(\\(HELO (([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)\\) )?"
            + "\\(("
            + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "|"
            + "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,7}:"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
            + "|"
            + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
            + "|"
            + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
            + "|"
            + ":((:[0-9a-fA-F]{1,4}){1,7}|:)"
            + ")\\)"
            + ")"
    );

    private static final Regex ENVELOPE_BY_PATTERN = new Regex("\\b"
            + "by (([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + "( \\([a-zA-Z0-9/.]+\\))? with "
    );

    private static final Regex QUEUE_ID_PATTERN = new Regex(
            " id ([0-9a-zA-Z.]+)\\b"
    );

    private static final Regex ENVELOPE_SENDER_PATTERN = new Regex("\\b"
            + "envelope-from <("
            + "[a-zA-Z0-9][a-zA-Z0-9._+=-]*@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*"
            + "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])"
            + ")?>"
    );

    private static final Regex ENVELOPE_FOR_PATTERN = new Regex("\\b"
            + "for ("
            + "<("
            + "[0-9a-z][0-9a-z._+=-]*@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*"
            + "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])"
            + ")>"
            + "|"
            + "("
            + "[0-9a-z][0-9a-z._+=-]*@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*"
            + "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])"
            + ");"
            + ")"
    );
    
    private static boolean isSameMX(String by, String to) {
        if (by == null) {
            return false;
        } else if (to == null) {
            return false;
        } else {
            int index = to.indexOf('@') + 1;
            ArrayList<String> mxList = Reverse.getMXSetSafe(to.substring(index), false);
            if (mxList == null) {
                return false;
            } else if (mxList.contains(by = Domain.normalizeHostname(by, false))) {
                return true;
            } else {
                TreeSet<String> bySet = Reverse.getAddressSetSafe(by);
                if (bySet == null) {
                    return false;
                } else {
                    for (String mx : mxList) {
                        TreeSet<String> mxSet = Reverse.getAddressSetSafe(mx);
                        if (mxSet != null) {
                            for (String address : mxSet) {
                                if (bySet.contains(address)) {
                                    return true;
                                }
                            }
                        }
                    }
                    return false;
                }
            }
        }
    }
    
    public static Entry<Long,User.Query> newQuery(
            User user, Message message
    ) throws Exception {
        return newQuery(user, null, message);
    }
    
    private static Entry<Long,User.Query> newQuery(
            User user,
            String rcptTo,
            Message message
    ) throws Exception {
        if (message == null) {
            return null;
        } else {
            String[] headerArray = message.getHeader("Received-SPFBL");
            Entry<Long,Query> entry = getQueryEntry(headerArray);
            Query query = entry == null ? null : entry.getValue();
            user = query == null ? user : query.getUser();
            if (user == null) {
                return null;
            } else {
                boolean internet = false;
                // Check DKIM information.
                String from = extractAddress(message.getHeader("From"), true);
                TreeSet<String> identitySet = new TreeSet<>();
                TreeSet<String> signerSet = new TreeSet<>();
                if (from == null || !from.contains("@")) {
                    from = null;
                } else {
                    identitySet.add(from);
                }
                ArrayList<DKIM.Signature> signatureList = new ArrayList<>(1);
                Enumeration<Header> headerEnum = message.getAllHeaders();
                while (headerEnum.hasMoreElements()) {
                    Header header = headerEnum.nextElement();
                    String name = header.getName();
                    String value = header.getValue();
                    String line = name + ": " + value;
                    if (name.equals("DKIM-Signature")) {
                        try {
                            DKIM.Signature signature = new DKIM.Signature(line);
                            signatureList.add(signature);
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    } else {
                        for (DKIM.Signature signature : signatureList) {
                            signature.putHeader(line);
                        }
                    }
                }
                for (DKIM.Signature signature : signatureList) {
                    try {
                        if (signature.hasIdentity()) {
                            identitySet.add(signature.getIdentity());
                        }
                        if (signature.isHeaderValid()) {
                            signerSet.add(signature.getDomain());
                        }
                    } catch (ServiceUnavailableException ex) {
                        // Do nothing.
                    } catch (NamingException ex) {
                        // Do nothing.
                    } catch (Exception ex) {
                        // Do nothing.
                    }
                }
                // Check routing information.
                String client = null;
                String queueID = null;
                Date arrival = null;
                String ip = null;
                String helo = null;
                String fqdn = null;
                String sender = null;
                String recipient = null;
                String subaddress = null;
                String to = extractAddress(message.getHeader("To"), true);
                if (to != null && !to.contains("@")) {
                    to = null;
                }
                String returnPath = extractAddress(message.getHeader("Return-Path"), false);
                if (returnPath == null) {
                    returnPath = extractAddress(message.getHeader("X-Sender"), false);
                }
                if (returnPath != null && !returnPath.contains("@")) {
                    returnPath = null;
                }
                Qualifier qualifier = null;
                TreeSet<String> forSet = new TreeSet<>();
                String[] receivedArray = message.getHeader("Received");
                if (receivedArray != null) {
                    for (String header : receivedArray) {
                        header = header.replaceAll("[\\r\\n\\t ]+", " ");
                        Matcher matcherFrom = ENVELOPE_FROM_PATTERN.createMatcher(header);
                        if (matcherFrom.find()) {
                            String newIP = matcherFrom.group(30);
                            if (newIP == null) {
                                newIP = matcherFrom.group(60);
                            }
                            if (newIP == null) {
                                Server.logError(header);
                            } else if (!Subnet.isReservedIP(newIP)) {
                                internet = true;
                                String hostname = matcherFrom.group(1);
                                String newHelo = matcherFrom.group(50);
                                if (newHelo == null) {
                                    newHelo = matcherFrom.group(26);
                                    if (newHelo == null) {
                                        newHelo = matcherFrom.group(56);
                                        if (newHelo == null) {
                                            newHelo = hostname;
                                        }
                                    }
                                }
                                String newFQDN;
                                boolean terminate = false;
                                if (FQDN.isFQDN(newIP, newHelo)) {
                                    newFQDN = Domain.normalizeHostname(newHelo, false);
                                } else if (FQDN.isFQDN(newIP, hostname)) {
                                    newFQDN = Domain.normalizeHostname(hostname, false);
                                } else {
                                    newFQDN = FQDN.discoverFQDN(newIP);
                                }
                                Matcher matcherBy = ENVELOPE_BY_PATTERN.createMatcher(header);
                                String newClient;
                                if (matcherBy.find()) {
                                    newClient = matcherBy.group(1).toLowerCase();
                                } else {
                                    newClient = null;
                                }
                                ENVELOPE_BY_PATTERN.offerMatcher(matcherBy);
                                Matcher matcherID = QUEUE_ID_PATTERN.createMatcher(header);
                                String newQueueID;
                                if (matcherID.find()) {
                                    newQueueID = matcherID.group(1);
                                } else {
                                    newQueueID = null;
                                }
                                QUEUE_ID_PATTERN.offerMatcher(matcherID);
                                Matcher matcherSender = ENVELOPE_SENDER_PATTERN.createMatcher(header);
                                String newSender;
                                if (matcherSender.find()) {
                                    newSender = matcherSender.group(1);
                                } else {
                                    newSender = returnPath;
                                }
                                ENVELOPE_SENDER_PATTERN.offerMatcher(matcherSender);
                                Matcher matcherFor = ENVELOPE_FOR_PATTERN.createMatcher(header);
                                String newRecipient;
                                if (matcherFor.find()) {
                                    newRecipient = matcherFor.group(2);
                                    if (newRecipient == null) {
                                        newRecipient = matcherFor.group(6);
                                    }
                                    newRecipient = newRecipient.toLowerCase();
                                    forSet.add(newRecipient);
                                } else if (isSameMX(newClient, to)) {
                                    newRecipient = to;
                                    terminate = true;
                                } else {
                                    newRecipient = null;
                                    for (String address : forSet) {
                                        if (isSameMX(newClient, address)) {
                                            newRecipient = address;
                                            terminate = true;
                                        }
                                    }
                                }
                                ENVELOPE_FOR_PATTERN.offerMatcher(matcherFor);
                                if (rcptTo != null && newRecipient != null) {
                                    if (rcptTo.equals(newRecipient)) {
                                        terminate = true;
                                    }
                                }
                                Qualifier newQualifier;
                                if (newSender != null) {
                                    newQualifier = SPF.getQualifier(
                                            newIP, newSender, newHelo, false
                                    );
                                    if (newQualifier == PASS) {
                                        terminate = true;
                                    }
                                } else {
                                    newQualifier = null;
                                    for (String identity : identitySet) {
                                        newQualifier = SPF.getQualifier(
                                                newIP, identity, newHelo, false
                                        );
                                        if (newQualifier == PASS && identity.contains("@")) {
                                            newSender = identity;
                                            terminate = true;
                                        }
                                    }
                                }
                                if (terminate || ip == null) {
                                    client = newClient;
                                    queueID = newQueueID;
                                    ip = newIP;
                                    helo = newHelo;
                                    fqdn = newFQDN;
                                    sender = newSender;
                                    qualifier = newQualifier;
                                    recipient = newRecipient;
                                    // Extract arrival date.
                                    int index = header.lastIndexOf(';') + 1;
                                    header = header.substring(index).trim();
                                    arrival = Core.parseEmailDateSafe(header);
                                }
                                if (terminate) {
                                    break;
                                }
                            } else if (internet) {
                                break;
                            }
                        }
                        ENVELOPE_FROM_PATTERN.offerMatcher(matcherFrom);
                    }
                }
                if (ip == null) {
                    StringBuilder builder = new StringBuilder();
                    Enumeration<Header> enumeration = message.getAllHeaders();
                    while (enumeration.hasMoreElements()) {
                        Header header = enumeration.nextElement();
                        String name = header.getName();
                        String value = header.getValue();
                        builder.append(name);
                        builder.append(": ");
                        builder.append(value);
                        builder.append('\n');
                    }
                    return null;
                } else {
                    if (rcptTo != null) {
                        recipient = rcptTo;
                    } else if (recipient == null) {
                        recipient = user.getEmail();
                    }
                    String result = "ACCEPT";
                    if (client == null) {
                        client = user.getEmail();
                        int index = client.indexOf('@') + 1;
                        client = client.substring(index);
                    }
                    TreeSet<String> tokenSet = new TreeSet<>();
                    tokenSet.add(ip);
                    tokenSet.add(user.getEmail() + ':');
                    if (recipient != null) {
                        tokenSet.add('>' + recipient);
                    }
                    if (Generic.containsGenericSoft(fqdn)) {
                        if (!Provider.containsDomain(fqdn)) {
                            fqdn = null;
                        }
                    } else if (fqdn != null) {
                        tokenSet.add('.' + fqdn);
                    }
                    if (qualifier == Qualifier.PASS || (sender != null && Provider.containsFQDN(fqdn))) {
                        String mx = Domain.extractHost(sender, true);
                        if (!Provider.containsExact(mx)) {
                            tokenSet.add(mx);
                        } else if (isValidEmail(sender)) {
                            String userEmail = null;
                            String recipientEmail = null;
                            for (String token : tokenSet) {
                                if (token.endsWith(":")) {
                                    userEmail = token;
                                } else if (token.startsWith(">")) {
                                    recipientEmail = token;
                                }
                            }
                            tokenSet.clear();
                            tokenSet.add(sender);
                            if (userEmail != null) {
                                tokenSet.add(userEmail);
                            }
                            if (recipientEmail != null) {
                                tokenSet.add(recipientEmail);
                            }
                        }
                    }
                    String replyTo = extractAddress(message.getHeader("Reply-To"), true);
                    if (replyTo != null && !replyTo.contains("@")) {
                        replyTo = null;
                    }
                    Date date = message.getReceivedDate();
                    String subject = message.getSubject();
                    if ((subject = Core.tryToDecodeMIME(subject)) != null) {
                        subject = subject.replaceAll(" +", " ");
                    }
                    URL unsubscribeURL = extractUnsubscribe(message);
                    String messageID = extractMessageID(
                            message.getHeader("Message-ID")
                    );
                    if (entry == null) {
                        long timeKey = Server.getNewUniqueTime();
                        query = user.newQuery(
                                client, ip, helo, fqdn, sender, qualifier,
                                recipient, subaddress,
                                tokenSet, result, from, replyTo, date,
                                unsubscribeURL, signerSet, subject,
                                messageID, queueID, arrival
                        );
                        entry = new AbstractMap.SimpleImmutableEntry<>(timeKey, query);
                    } else {
                        long timeKey = entry.getKey();
                        query = entry.getValue();
                        if (!query.hasHeaderInformation()) {
                            query.setHeader(
                                    timeKey, client, from, replyTo,
                                    subject, messageID, replyTo,
                                    queueID, date, unsubscribeURL, arrival
                            );
                        }
                    }
                    return entry;
                }
            }
        }
    }
        
    private static boolean setHeader(
            InternetHeaders headers,
            String name,
            String value
    ) {
        if (headers == null) {
            return false;
        } else if (name == null) {
            return false;
        } else if (value == null) {
            headers.removeHeader(name);
            return true;
        } else {
            value = value.replaceAll("[\\r\\n\\t]+", "\r\n\t");
            headers.setHeader(name, value);
            return true;
        }
    }
    
    private static final Regex STATUS_PATTERN = new Regex(
            "\\b[245]\\.[0-7]\\.[0-9]{1,2}\\b"
    );
    
    private static String extractEnhancedCode(String message) {
        if (message == null) {
            return "5.5.0";
        } else {
            int code;
            try {
                code = Integer.parseInt(message.trim().substring(0, 3));
            } catch (NumberFormatException ex) {
                code = 550;
            }
            return extractEnhancedCode(code, message);
        }
    }
    
    private static String extractEnhancedCode(int code, String message) {
        if (message != null) {
            Matcher matcher = STATUS_PATTERN.createMatcher(message);
            if (matcher.find()) {
                String group = matcher.group();
                STATUS_PATTERN.offerMatcher(matcher);
                return group;
            }
        }
        int a = code / 100;
        int b = code / 10 % 10;
        int c = code % 10;
        return a + "." + b + "." + c;
    }
    
    // Método temporário para implementação.
    private static boolean sendMessage(
            String HOSTNAME,
            Properties props,
            InternetAddress from,
            Message message,
            InternetAddress[] recipients,
            InternetHeaders status
    ) throws Exception {
        if (props == null) {
            return false;
        } else if (message == null) {
            return false;
        } else if (recipients == null) {
            return false;
        } else if (recipients.length == 0) {
            return false;
        } else {
            
            final String authenticate = props.getProperty("mail.smtp.auth", "false");
            final String user = props.getProperty("mail.smtp.user");
            final String password = props.getProperty("mail.smtp.password");
            
            Authenticator authenticator;
            if (authenticate == null) {
                authenticator = null;
            } else if (user == null) {
                authenticator = null;
            } else if (password == null) {
                authenticator = null;
            } else if (user.isEmpty()) {
                authenticator = null;
            } else if (password.isEmpty()) {
                authenticator = null;
            } else if (authenticate.equals("true")) {
                authenticator = new Authenticator() {
                    @Override
                    public PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(user, password);
                    }
                };
            } else {
                authenticator = null;
            }

            Properties props2 = new Properties();
            props2.putAll(System.getProperties());
            props2.putAll(props);
            
            Session session;
            if (authenticator == null) {
                session = Session.getInstance(props2);
            } else {
                session = Session.getInstance(props2, authenticator);
            }
            props2 = session.getProperties();
            if (from != null && !props2.containsKey("mail.smtp.from")) {
                props2.put("mail.smtp.from", from.getAddress());
            }
            
            String sender = props2.getProperty("mail.smtp.from");
            String starttls = props2.getProperty("mail.smtp.starttls.enable", "true");
            String host = props2.getProperty("mail.smtp.host");
            String port = props2.getProperty("mail.smtp.port");
            String connTimeout = props2.getProperty("mail.smtp.connectiontimeout");
            String sessionTimeout = props2.getProperty("mail.smtp.timeout");
            String sequence = Core.getSequence(recipients, " ");
            
            Server.logSendSMTP("envelope sender: " + sender);
            Server.logSendSMTP("user name: " + user);
            Server.logSendSMTP("sending message to: " + sequence);
            Server.logSendSMTP("authenticate: " + authenticate);
            Server.logSendSMTP("start TLS: " + starttls);
            Server.logSendSMTP("connection timeout: " + connTimeout);
            Server.logSendSMTP("session timeout: " + sessionTimeout);
            
            setHeader(status, "Remote-MTA", "dns; " + host);
            setHeader(status, "Last-Attempt-Date", Core.getEmailDate());
            
            try (SMTPTransport transport = (SMTPTransport) session.getTransport("smtp")) {
                try {
                    String subject = message.getSubject();
                    transport.setLocalHost(HOSTNAME);
                    Server.logSendSMTP("connecting to " + host + ":" + port);
                    transport.connect(host, Integer.parseInt(port), user, password);
                    Server.logSendSMTP("sending '" + subject + "' to " + sequence + ".");
                    transport.sendMessage(message, recipients);
                    Server.logSendSMTP("message sent: " + transport.getLastServerResponse());
                    setHeader(status, "Action", "delivered");
                    setHeader(status, "Status", "2.0.0");
                    setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                    return true;
                } catch (MailConnectException ex) {
                    Server.logSendSMTP("connection failed: " + host);
                    setHeader(status, "Action", "delayed");
                    setHeader(status, "Status", "1.0.1");
                    setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                    throw ex;
                } catch (AuthenticationFailedException ex) {
                    Server.logSendSMTP("authentication failed: " + user);
                    setHeader(status, "Action", "failed");
                    setHeader(status, "Status", "5.7.3");
                    setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                    throw ex;
                } catch (SMTPAddressFailedException ex) {
                    String lastResponse = transport.getLastServerResponse();
                    Server.logSendSMTP("address failed: " + lastResponse);
                    setHeader(status, "Action", ex.getReturnCode() / 100 == 5 ? "failed" : "delayed");
                    setHeader(status, "Status", extractEnhancedCode(ex.getReturnCode(),lastResponse));
                    setHeader(status, "Diagnostic-Code", "smtp; " + lastResponse);
                    throw ex;
                } catch (SendFailedException ex) {
                    String lastResponse = transport.getLastServerResponse();
                    if (ex.getCause() instanceof SMTPAddressFailedException) {
                        SMTPAddressFailedException afex = (SMTPAddressFailedException) ex.getCause();
                        Server.logSendSMTP("address failed: " + lastResponse);
                        String enhancedCode = extractEnhancedCode(afex.getReturnCode(), lastResponse);
                        setHeader(status, "Action", afex.getReturnCode() / 100 == 5 ? "failed" : "delayed");
                        setHeader(status, "Status", enhancedCode);
                        setHeader(status, "Diagnostic-Code", "smtp; " + lastResponse);
                        throw afex;
                    } else {
                        Server.logSendSMTP("send failed: " + lastResponse);
                        String enhancedCode = extractEnhancedCode(lastResponse);
                        setHeader(status, "Action", lastResponse.charAt(0) == '5' ? "failed" : "delayed");
                        setHeader(status, "Status", enhancedCode);
                        setHeader(status, "Diagnostic-Code", "smtp; " + lastResponse);
                        throw ex;
                    }
                } catch (MessagingException ex) {
                    if (ex.getCause() instanceof IOException) {
                        Server.logSendSMTP("writing error: " + message.getSubject());
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.6.5");
                        setHeader(status, "Diagnostic-Code", "smtp; " + ex.getMessage());
                        throw (IOException) ex.getCause();
                    } else if (ex.getCause() instanceof SocketTimeoutException) {
                        Server.logSendSMTP("messaging timeout: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.2.0");
                        setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                        throw (SocketTimeoutException) ex.getCause();
                    } else if (ex.getCause() instanceof SocketException) {
                        Server.logSendSMTP("connection closed: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.4.2");
                        setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                        int portInt = Integer.parseInt(port);
                        int timeoutInt = Integer.parseInt(connTimeout);
                        throw new MailConnectException(new SocketConnectException(ex.getMessage(), ex, host, portInt, timeoutInt));
                    } else if (ex.getCause() instanceof SSLHandshakeException) {
                        Server.logSendSMTP("TLS handshake failed: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.5");
                        setHeader(status, "Diagnostic-Code", "smtp; " + ex.getMessage());
                        throw (SSLHandshakeException) ex.getCause();
                    } else if (ex.getCause() instanceof SSLException) {
                        Server.logSendSMTP("TLS handshake failed: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.5");
                        setHeader(status, "Diagnostic-Code", "smtp; " + ex.getMessage());
                        throw (SSLException) ex.getCause();
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: -1")) {
                        Server.logSendSMTP("connection failed: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "1.1.1");
                        setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                        int portInt = Integer.parseInt(port);
                        int timeoutInt = Integer.parseInt(connTimeout);
                        throw new MailConnectException(new SocketConnectException(ex.getMessage(), ex, host, portInt, timeoutInt));
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 550")) {
                        Server.logSendSMTP("connection refused: " + host);
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.5.0");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 554")) {
                        Server.logSendSMTP("received refused: " + host);
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.5.4");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 530")) {
                        Server.logSendSMTP("autentication required: " + host);
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.7.3");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().contains(" 5.5.2 ")) {
                        Server.logSendSMTP("syntax error: " + host);
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.5.2");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 450")) {
                        Server.logSendSMTP("mailbox unavailable: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.5.0");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 451")) {
                        Server.logSendSMTP("connection delayed: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.5.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().startsWith("Could not connect to SMTP host: ") && ex.getMessage().endsWith(", response: 421")) {
                        Server.logSendSMTP("too many connections: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.2.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().contains(" 4.3.0 ")) {
                        Server.logSendSMTP("server unavailable: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.3.0");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().contains(" 4.4.5 ")) {
                        Server.logSendSMTP("server busy: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.4.5");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().contains(" 4.7.0 ")) {
                        Server.logSendSMTP("server busy: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.0");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().contains("TLS")) {
                        Server.logSendSMTP("TLS unavailable: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    } else if (ex.getMessage().equals("[EOF]")) {
                        Server.logSendSMTP("connection dropped: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.4.2");
                        setHeader(status, "Diagnostic-Code", "smtp; The connection was dropped during transmission");
                        throw ex;
                    } else if (ex.getMessage().endsWith(" response: 521")) {
                        Server.logSendSMTP("not accepting mail: " + host);
                        setHeader(status, "Action", "failed");
                        setHeader(status, "Status", "5.2.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw (IOException) ex.getCause();
                    } else {
                        Server.logError(ex);
                        Server.logSendSMTP("messaging refused: " + transport.getLastServerResponse());
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        throw ex;
                    }
                } catch (Exception ex) {
                    if (ex instanceof SocketException) {
                        Server.logSendSMTP("connection reset: " + host);
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.4.2");
                        setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                        int portInt = Integer.parseInt(port);
                        int timeoutInt = Integer.parseInt(connTimeout);
                        throw new MailConnectException(new SocketConnectException(ex.getMessage(), ex, host, portInt, timeoutInt));
                    } else {
                        Server.logSendSMTP("transport error: " + ex.getMessage());
                        setHeader(status, "Action", "delayed");
                        setHeader(status, "Status", "4.7.1");
                        setHeader(status, "Diagnostic-Code", "smtp; " + transport.getLastServerResponse());
                        Server.logError(ex);
                        throw ex;
                    }
                }
            } catch (SocketException ex) {
                Server.logSendSMTP("connection failed: " + host);
                setHeader(status, "Action", "delayed");
                setHeader(status, "Status", "1.0.1");
                setHeader(status, "Diagnostic-Code", "tcp; " + ex.getMessage());
                throw ex;
            }
        }
    }
    
    public static MimeMessage loadMimeMessage(byte[] byteArray) throws Exception {
        if (byteArray == null) {
            return null;
        } else {
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray)) {
                return new SimpleMimeMessage(null, inputStream);
            }
        }
    }
    
    public static MimeMessage loadMimeMessage(File file) throws Exception {
        if (file == null) {
            return null;
        } else if (file.exists()) {
            try (FileInputStream inputStream = new FileInputStream(file)) {
                return new SimpleMimeMessage(null, inputStream);
            }
        } else {
            return null;
        }
    }
    
    private static MimeMessage loadMessageSPFBL(MimeMessage message) throws Exception {
        DKIMSigner dkimSigner = Core.getDKIMSigner();
        if (dkimSigner == null) {
            return new SPFBLMimeMessage(message);
        } else {
            return new DKIMMimeMessage(message, dkimSigner);
        }
    }
    
    public static boolean removeDangerousObjects(Document document) throws Exception {
        if (document == null) {
            return false;
        } else {
            boolean removed = false;
            for (Element element : document.getElementsByAttribute("href")) {
                element.attr("href", "#");
                removed = true;
            }
            for (Element element : document.getElementsByTag("a")) {
                element.attr("href", "#");
                element.attr("data-saferedirecturl", "#");
                element.attr("data-mce-href", "#");
                removed = true;
            }
            for (Element element : document.getElementsByTag("img")) {
                element.attr("src", "#");
                element.attr("data-mce-src", "#");
                removed = true;
            }
            for (Element element : document.getElementsByTag("script")) {
                element.remove();
                removed = true;
            }
            for (Element element : document.getElementsByTag("style")) {
                element.remove();
                removed = true;
            }
            return removed;
        }
    }
    
    public static boolean removeDangerousObjects(MimeMessage message) throws Exception {
        if (message == null) {
            return false;
        } else if (message.getSize() == 0) {
            return false;
        } else {
            boolean removed = false;
            fixContentMetadata(message);
            LinkedList<Object> contentStack = new LinkedList<>();
            contentStack.push(message.getContent());
            while (!contentStack.isEmpty()) {
                Object content = contentStack.pop();
                if (content instanceof Multipart) {
                    Multipart multipart = (Multipart) content;
                    for (int index = multipart.getCount() - 1; index >= 0; index--) {
                        BodyPart part = multipart.getBodyPart(index);
                        String type = part.getContentType();
                        if (type.startsWith("application/")) {
                            multipart.removeBodyPart(index);
                            multipart.getParent().setContent(multipart);
                            removed = true;
                        } else if (Part.ATTACHMENT.equals(part.getDisposition())) {
                            multipart.removeBodyPart(index);
                            multipart.getParent().setContent(multipart);
                            removed = true;
                        } else if (type.startsWith("text/html")) {
                            // Disarm dangerous HTML objects.
                            String[] contentType = extractContentType(part);
                            String charset = contentType[1];
                            Document document = parseHTML(part, charset);
                            document = document.normalise();
                            if (removeDangerousObjects(document)) {
                                document = document.normalise();
                                String html = document.html();
                                part.setContent(html, "text/html; charset=UTF-8");
                                part.setHeader("Content-Type", "text/html; charset=UTF-8");
                                part.setHeader("Content-Transfer-Encoding", "7BIT");
                                multipart.getParent().setContent(multipart);
                                removed = true;
                            }
                        } else if (type.startsWith("text/plain")) {
                            contentStack.push(part);
                        } else if (part.getContent() instanceof String) {
                            multipart.removeBodyPart(index);
                            multipart.getParent().setContent(multipart);
                            removed = true;
                        } else {
                            contentStack.push(part);
                        }
                    }
                } else if (content instanceof BodyPart) {
                    BodyPart part = (BodyPart) content;
                    fixContentMetadata(part);
                    String[] contentType = extractContentType(part);
                    String type = contentType[0];
                    String charset = contentType[1];
                    if (part.getContent() instanceof Multipart) {
                        Multipart multipart = (Multipart) part.getContent();
                        contentStack.push(multipart);
                    } else if (part.getContent() instanceof MimeMessage) {
                        MimeMessage forwarded = (MimeMessage) part.getContent();
                        fixContentMetadata(forwarded);
                        if (removeDangerousObjects(forwarded)) {
                            removed = true;
                        }
                        contentStack.push(forwarded.getContent());
                    } else if (type.startsWith("text/html")) {
                        // Disarm dangerous HTML objects.
                        Document document = parseHTML(part, charset);
                        document = document.normalise();
                        if (removeDangerousObjects(document)) {
                            document = document.normalise();
                            String html = document.html();
                            part.setContent(html, "text/html; charset=UTF-8");
                            part.setHeader("Content-Type", "text/html; charset=UTF-8");
                            part.setHeader("Content-Transfer-Encoding", "7BIT");
                            Multipart multipart = part.getParent();
                            multipart.getParent().setContent(multipart);
                            removed = true;
                        }
                    }
                }
            }
            if (removed) {
                message.saveChanges();
                return true;
            } else {
                return false;
            }
        }
    }
    
    private static Document parseHTML(BodyPart part, String charset) {
        if (part == null) {
            return null;
        } else {
            try {
                Object content = part.getContent();
                String html = null;
                if (content instanceof String) {
                    html = (String) content;
                } else if (content instanceof SharedByteArrayInputStream) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    SharedByteArrayInputStream in = (SharedByteArrayInputStream) content;
                    int nread;
                    while ((nread = in.read()) >= 0) {
                        baos.write(nread);
                    }
                    html = baos.toString(charset);
                }
                if (html == null) {
                    Server.logError(
                            "Could not parse text in the class "
                                    + content.getClass()
                    );
                } else {
                    return Jsoup.parse(html);
                }
                return null;
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    public static boolean fixContentMetadata(MimeMessage message) {
        if (message == null) {
            return false;
        } else if (message instanceof IMAPMessage) {
            return false;
        } else {
            try {
                String encoding = fixEncoding(message.getHeader("Content-Transfer-Encoding"));
                message.setHeader("Content-Transfer-Encoding", encoding);
                String contentType = message.getHeader("Content-Type", null);
                contentType = fixContentType(contentType);
                message.setHeader("Content-Type", contentType);
                message.saveChanges();
                return true;
            } catch (javax.mail.internet.ParseException ex) {
                return false;
            } catch (MessagingException ex) {
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    private static boolean fixContentMetadata(Part part) {
        if (part == null) {
            return false;
        } else if (part instanceof IMAPMessage) {
            return false;
        } else if (part instanceof IMAPBodyPart) {
            return false;
        } else {
            try {
                String encoding = fixEncoding(part.getHeader("Content-Transfer-Encoding"));
                part.setHeader("Content-Transfer-Encoding", encoding);
                if (encoding.equals("BASE64") && part.getContent() instanceof MimeMessage) {
                    MimeMessage message = (MimeMessage) part.getContent();
                    if (message.getSize() == -1) {
                        // Fix BASE64 decoding.
                        InputStream inputStream = part.getInputStream();
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        int code;
                        while ((code = inputStream.read()) >= 0) {
                            outputStream.write(code);
                        }
                        byte[] decoded = Core.BASE64STANDARD.decode(outputStream.toByteArray());
                        inputStream = new ByteArrayInputStream(decoded);
                        message = new SimpleMimeMessage(null, inputStream);
                        part.setContent(message, "message/rfc822");
                        part.setHeader("Content-Type", "message/rfc822");
                        return true;
                    }
                }
                String contentType = part.getContentType();
                contentType = fixContentType(contentType);
                part.setHeader("Content-Type", contentType);
                return true;
            } catch (javax.mail.internet.ParseException ex) {
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    // Fix encoding to be compliance with RFC 1341.
    private static String fixEncoding(String[] encoding) {
        if (encoding == null || encoding.length == 0) {
            return "8BIT";
        } else {
            String upper = encoding[0].toUpperCase();
            if (upper.equals("8BITS")) {
                return "8BIT";
            } else if (upper.equals("8BIT+")) {
                return "8BIT";
            } else if (upper.equals("UNICODE-1-1-UTF-7")) {
                return "7BIT";
            } else if (upper.equals("64BIT")) {
                return "BASE64";
            } else if (upper.equals("AS-IS")) {
                return "7BIT";
            } else if (upper.equals("UTF-8")) {
                return "8BIT";
            } else if (upper.equals("8-BIT")) {
                return "8BIT";
            } else if (upper.equals("US-ASCII")) {
                return "7BIT";
            } else {
                return upper;
            }
        }
    }
    
    private static String fixContentType(String contentType) {
        if (contentType == null) {
            // Default value.
            return "text/plain; charset=us-ascii";
        } else if (contentType.equals("text/html")) {
            // Default charset for HTML.
            return "text/html; charset=UTF-8";
        } else {
            // Charset correction.
            contentType = contentType.replaceFirst("\\bcharset='utf-8'\\B", "charset=UTF-8");
            contentType = contentType.replaceFirst("\\bcharset=\"UTF8\"\\B", "charset=UTF-8");
            contentType = contentType.replaceFirst("\\bcharset=8859-1\\b", "charset=ISO-8859-1");
            contentType = contentType.replaceFirst("\\bcharset=cp-850\\b", "charset=CP850");
            contentType = contentType.replaceFirst("\\bcharset=ansi_x3\\.110-1983\\b", "charset=US-ASCII");
            contentType = contentType.replaceFirst("\\bcharset=_iso-2022-jp\\$ESC\\b", "charset=ISO-2022-JP");
            contentType = contentType.replaceFirst("\\bcharset=\"_iso-2022-jp\\$ESC\"\\B", "charset=ISO-2022-JP");
            contentType = contentType.replaceFirst("\\bcharset=iso-8859-10\\b", "charset=ISO-8859-10");
            contentType = contentType.replaceFirst("\\bcharset=\"\"\\B", "charset=UTF-8");
            contentType = contentType.replaceFirst("\\bcharset=\"x-ia5\"\\B", "charset=CP1250");
            contentType = contentType.replaceFirst("\\bcharset=\"macintosh\"\\B", "charset=MacCentralEurope");
            return contentType;
        }
    }
    
    private static final HashSet<String> DELIVERY_STATUS = new HashSet<>();
    
    static {
        DELIVERY_STATUS.add("Original-Envelope-Id");
        DELIVERY_STATUS.add("Reporting-MTA");
        DELIVERY_STATUS.add("DSN-Gateway");
        DELIVERY_STATUS.add("Received-From-MTA");
        DELIVERY_STATUS.add("Arrival-Date");
        DELIVERY_STATUS.add("Per-Recipient");
        DELIVERY_STATUS.add("Original-Recipient");
        DELIVERY_STATUS.add("Final-Recipient");
        DELIVERY_STATUS.add("Action");
        DELIVERY_STATUS.add("Status");
        DELIVERY_STATUS.add("Remote-MTA");
        DELIVERY_STATUS.add("Diagnostic-Code");
        DELIVERY_STATUS.add("Last-Attempt-Date");
        DELIVERY_STATUS.add("Final-Log-ID");
        DELIVERY_STATUS.add("Will-Retry-Until");
    }
    
    private boolean bounceDeliveryStatus(
            InternetHeaders headers,
            MimeMessage original
    ) throws Exception {
        if (headers == null) {
            return false;
        } else {
            String action = headers.getHeader("Action", null);
            String status = headers.getHeader("Status", null);
            InternetAddress recipient = extractInternetAddress(
                    headers.getHeader("Original-Recipient", null), true
            );
            if (action == null) {
                throw new Exception("Action not defined.");
            } else if (status == null) {
                throw new Exception("Status not defined.");
            } else if (recipient == null) {
                throw new Exception("Original-Recipient not defined.");
            } else {
                boolean bounce = false;
                if (action.equals("failed")) {
                    bounce = true;
                } else if (action.equals("delayed")) {
                    Date arrival = Core.parseEmailDateSafe(headers.getHeader("Arrival-Date", null));
                    Date last = Core.parseEmailDateSafe(headers.getHeader("Last-Attempt-Date", null));
                    if (arrival == null) {
                        bounce = true;
                    } else if (last == null) {
                        bounce = true;
                    } else if (System.currentTimeMillis() - arrival.getTime() > 3 * Server.DAY_TIME) {
                        bounce = true;
                    } else if (System.currentTimeMillis() - arrival.getTime() > 2 * Server.DAY_TIME) {
                        bounce = System.currentTimeMillis() - last.getTime() > Server.HOUR_TIME;
                    } else if (System.currentTimeMillis() - arrival.getTime() > Server.DAY_TIME) {
                        bounce = System.currentTimeMillis() - last.getTime() > 30 * Server.MINUTE_TIME;
                    }
                }
                if (bounce) {
                    InternetAddress returnPath = extractInternetAddress(
                            headers.getHeader("Return-Path", null), false
                    );
                    String diagnostic = headers.getHeader(
                            "Diagnostic-Code", null
                    );
                    if (returnPath == null) {
                        return true;
                    } else if (diagnostic == null) {
                        throw new Exception("Diagnostic-Code not defined.");
                    } else {
                        int index = diagnostic.indexOf(';') + 1;
                        String diagnosticType = diagnostic.substring(0, index).trim();
                        diagnostic = diagnostic.substring(index).trim();
                        diagnostic = diagnostic.replaceAll("[\\r\\n\\t]+", "\n");
                        
                        String remoteMTA = headers.getHeader("Remote-MTA", null);
                        if (remoteMTA != null) {
                            index = remoteMTA.indexOf(';') + 1;
                            remoteMTA = remoteMTA.substring(index).trim();
                        }

                        StringBuilder builder = new StringBuilder();
                        builder.append("This message was created automatically by mail delivery software.\n");
                        builder.append("\n");
                        builder.append("A message that you sent could not be delivered to one recipient.\n");
                        builder.append("This is a permanent error. The following address failed:\n");
                        builder.append("\n");
                        builder.append("  <");
                        builder.append(recipient.getAddress());
                        builder.append(">\n");
                        if (diagnosticType.equals("smtp;")) {
                            if (remoteMTA == null) {
                                throw new Exception("Remote-MTA not defined.");
                            } else {
                                builder.append("    SMTP error from remote mail server ");
                                builder.append(remoteMTA);
                                builder.append(":\n");
                            }
                        } else if (diagnosticType.equals("tcp;")) {
                            if (remoteMTA == null) {
                                throw new Exception("Remote-MTA not defined.");
                            } else {
                                builder.append("    TCP connection error at remote mail server ");
                                builder.append(remoteMTA);
                                builder.append(":\n");
                            }
                        } else if (diagnosticType.equals("dns;")) {
                            if (remoteMTA == null) {
                                builder.append("    DNS error to discover MX of recipient:\n");
                            } else {
                                builder.append("    DNS error to resolve address of MX ");
                                builder.append(remoteMTA);
                                builder.append(":\n");
                            }
                        } else {
                            builder.append("    Unknow error to send message to recipient:\n");
                        }
                        StringTokenizer tokenizer = new StringTokenizer(diagnostic, "\n");
                        while (tokenizer.hasMoreTokens()) {
                            builder.append("      ");
                            builder.append(tokenizer.nextToken());
                            builder.append("\n");
                        }

                        DeliveryStatus dStatus = new DeliveryStatus();
                        Enumeration<String> enumeration = headers.getAllHeaderLines();
                        while (enumeration.hasMoreElements()) {
                            String line = enumeration.nextElement();
                            index = line.indexOf(':');
                            if (index > 0 && DELIVERY_STATUS.contains(line.substring(0, index))) {
                                dStatus.getMessageDSN().addHeaderLine(line);
                            }
                        }

                        MultipartReport content = new MultipartReport();
                        content.setText(builder.toString());
                        content.setReport(dStatus);
                        if (original != null) {
                            content.setReturnedMessage(original);
                        }

                        InternetAddress[] recipients = {returnPath};
                        MimeMessage message = Core.newMessage(false);
                        message.setFrom("Mailer-Daemon@" + HOSTNAME);
                        message.addRecipients(Message.RecipientType.TO, recipients);
                        message.setSubject("Mail delivery failed: returning message to sender");
                        message.setContent(content);
                        message.saveChanges();
                        
                        Server.logDebug("sending failed bounce to <" + returnPath + ">.");

                        return ServerSMTP.sendMessage(
                                Locale.US, message,
                                returnPath, null, true
                        );
                    }
                } else {
                    return false;
                }
            }
        }
    }
    
    public boolean tryToProcessQueue() {
        return QUEUE.tryToProcessQueue();
    }
    
    public boolean processDelivery(long time) {
        return QUEUE.processDelivery(time);
    }
    
    public boolean processDelivery(TreeSet<Long> deliverySet) {
        return QUEUE.processDelivery(deliverySet);
    }
    
    public static boolean storeIncomingMessage(
            String queueID,
            String fqdn,
            String encoded
            ) {
        try {
            if (queueID == null) {
                return false;
            } else if (fqdn == null) {
                return false;
            } else if (encoded == null) {
                return false;
            } else {
                File file = new File(INCOMING, '.' + queueID + '@' + fqdn);
                byte[] decoded = Core.BASE64STANDARD.decode(encoded);
                ByteArrayInputStream baIS = new ByteArrayInputStream(decoded);
                try (GZIPInputStream gzipIS = new GZIPInputStream(baIS)) {
                    try (FileOutputStream stream = new FileOutputStream(file)) {
                        int code;
                        while ((code = gzipIS.read()) != -1) {
                            stream.write(code);
                        }
                    }
                }
                Path source = file.toPath();
                Path target = source.resolveSibling(file.getName().substring(1));
                Files.move(source, target, REPLACE_EXISTING);
                return true;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean storeDeliveryStatus(
            File deliveryFile, InternetHeaders headers
    ) {
        try {
            File file = new File(DELIVERY, '.' + deliveryFile.getName());
            try (FileWriter writer = new FileWriter(file)) {
                Enumeration<String> enumeration = headers.getAllHeaderLines();
                while (enumeration.hasMoreElements()) {
                    String line = enumeration.nextElement();
                    writer.write(line);
                    writer.write("\r\n");
                    writer.flush();
                }
            }
            Path source = file.toPath();
            Path target = deliveryFile.toPath();
            Files.move(source, target, REPLACE_EXISTING);
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean storeIncomingMessage(
            String queueID,
            String fqdn,
            byte[] message
            ) {
        try {
            if (queueID == null) {
                return false;
            } else if (fqdn == null) {
                return false;
            } else if (message == null) {
                return false;
            } else if (INCOMING.exists()) {
                File file = new File(INCOMING, '.' + queueID + '@' + fqdn);
                try (ByteArrayInputStream baIS = new ByteArrayInputStream(message)) {
                    try (FileOutputStream stream = new FileOutputStream(file)) {
                        int code;
                        while ((code = baIS.read()) != -1) {
                            stream.write(code);
                        }
                    }
                }
                Path source = file.toPath();
                Path target = source.resolveSibling(file.getName().substring(1));
                Files.move(source, target, REPLACE_EXISTING);
                return true;
            } else {
                return false;
            }
        } catch (NoSuchFileException ex) {
            // The same message was already stored by another process.
            return true;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean storeIncomingMessage(
            User.Query query,
            Message message
            ) {
        if (query == null) {
            return false;
        } else if (message == null) {
            return false;
        } else {
            String queueID = query.getQueueID();
            String fqdn = query.getFQDN();
            return storeIncomingMessage(queueID, fqdn, message);
        }
    }
    
    public static boolean storeIncomingMessage(
            String queueID,
            String fqdn,
            Message message
            ) {
        try {
            if (queueID == null) {
                return false;
            } else if (fqdn == null) {
                return false;
            } else if (message == null) {
                return false;
            } else {
                File file = new File(INCOMING, '.' + queueID + '@' + fqdn);
                try (FileOutputStream stream = new FileOutputStream(file)) {
                    message.writeTo(stream);
                }
                Path source = file.toPath();
                Path target = source.resolveSibling(file.getName().substring(1));
                Files.move(source, target, REPLACE_EXISTING);
                return true;
            }
        } catch (NoSuchFileException ex) {
            return false;
        } catch (FolderClosedIOException ex) {
            return false;
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static final File DELIVERY = new File("./delivery/");
    private static final File INCOMING = new File("./incoming/");
        
    private class QueueThread extends Thread {
        
        private QueueThread() {
            super("QUEUESMTP");
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
            wait(10 * MINUTE_TIME);
        }
        
        private final Semaphore SEMAPHORE = new Semaphore(1);
        
        public void acquire() throws InterruptedException {
            waitNotify();
            SEMAPHORE.acquire();
        }
        
        public void release() {
            SEMAPHORE.release();
        }
        
        public boolean tryToProcessQueue() {
            if (SEMAPHORE.tryAcquire()) {
                try {
                    TreeSet<Long> messageSet = new TreeSet<>();
                    for (File file : DELIVERY.listFiles()) {
                        try {
                            String name = file.getName();
                            if (!name.startsWith(".")) {
                                Long timeKey = Core.parseLong(name, 32);
                                if (timeKey != null) {
                                    messageSet.add(timeKey);
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    processDelivery(messageSet);
                    return true;
                } finally {
                    SEMAPHORE.release();
                }
            } else {
                return false;
            }
        }
        
        private final TreeSet<Long> SET = new TreeSet<>();
        
        private synchronized boolean processDelivery(TreeSet<Long> deliverySet) {
            if (deliverySet == null) {
                return false;
            } else if (SET.addAll(deliverySet)) {
                notify();
                return true;
            } else {
                return false;
            }
        }
        
        private synchronized boolean processDelivery(long time) {
            if (SET.add(time)) {
                notify();
                return true;
            } else {
                return false;
            }
        }
        
        private synchronized Long pollFirst() {
            return SET.pollFirst();
        }
        
        private synchronized boolean addDelivery(Long key) {
            if (key == null) {
                return false;
            } else {
                return SET.add(key);
            }
        }
        
        @Override
        public void run() {
            Server.logInfo("started queue thread.");
            while (keepRunning()) {
                try {
                    Server.logInfo("started queue process.");
                    Long timeKey;
                    for (File file : DELIVERY.listFiles()) {
                        if (keepRunning()) {
                            String name = file.getName();
                            timeKey = Core.parseLong(name, 32);
                            addDelivery(timeKey);
                        } else {
                            break;
                        }
                    }
                    while (keepRunning() && (timeKey = pollFirst()) != null) {
                        String deliveryID = Long.toString(timeKey, 32);
                        File deliveryFile = new File(DELIVERY, deliveryID);
                        if (deliveryFile.exists()) {
                            try {
                                InternetHeaders headers;
                                try (FileInputStream inputStream = new FileInputStream(deliveryFile)) {
                                    headers = new InternetHeaders(inputStream);
                                }
                                String action = headers.getHeader(
                                        "Action", null
                                );
                                String queueID = headers.getHeader(
                                        "Final-Log-ID", null
                                );
                                InternetAddress recipient = extractInternetAddress(
                                        headers.getHeader("Original-Recipient", null), true
                                );
                                if (action == null) {
                                    Server.logError(
                                            "The header Action: "
                                            + "cannot be parsed for "
                                            + "delivery ID " + deliveryID + "."
                                    );
                                    deliveryFile.delete();
                                } else if (queueID == null) {
                                    Server.logError(
                                            "The header Final-Log-ID: "
                                            + "cannot be parsed for "
                                            + "delivery ID " + deliveryID + "."
                                    );
                                    deliveryFile.delete();
                                } else if (recipient == null) {
                                    Server.logError(
                                            "The header Original-Recipient: "
                                            + "cannot be parsed for "
                                            + "delivery ID " + deliveryID + "."
                                    );
                                    deliveryFile.delete();
                                } else {
                                    File incomingFile = new File(INCOMING, queueID);
                                    MimeMessage message = loadMimeMessage(incomingFile);
                                    if (bounceDeliveryStatus(headers, message)) {
                                        Server.logInfo("delivery ID " + deliveryID
                                                + " was bounced back to return path."
                                        );
                                        deliveryFile.delete();
                                    } else if (!incomingFile.exists()) {
                                        Server.logError(
                                                "Devivery " + deliveryID + " failed "
                                                        + "because incoming message not found: "
                                                        + incomingFile.getName()
                                        );
                                        setHeader(headers, "Remote-MTA", HOSTNAME);
                                        setHeader(headers, "Last-Attempt-Date", Core.getEmailDate());
                                        setHeader(headers, "Action", "failed");
                                        setHeader(headers, "Status", "5.7.7");
                                        setHeader(headers, "Diagnostic-Code", "smtp; 554 5.7.7 Message integrity failure.");
                                        storeDeliveryStatus(deliveryFile, headers);
                                        if (bounceDeliveryStatus(headers, null)) {
                                            deliveryFile.delete();
                                        } else {
                                            Server.logError(
                                                    "could not bounce ID " + deliveryID
                                            );
                                        }
                                    } else if (action.equals("failed")) {
                                        Server.logError(
                                                "could not bounce ID " + deliveryID
                                        );
                                    } else {
                                        User user = User.getExact(headers.getHeader("User", null));
                                        User.Query query = User.getQuery(user, timeKey);
                                        Boolean deliver;
                                        if (query == null) {
                                            deliver = true;
                                        } else if (query.isResult("QUEUE")) {
                                            fixContentMetadata(message);
                                            deliver = mustDeliver(
                                                    timeKey, query, message
                                            );
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isWhiteKey()) {
                                            deliver = true;
                                            query.setResult("WHITE");
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isBanned()) {
                                            deliver = false;
                                            query.setResult("BLOCK");
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isBlockKey()) {
                                            deliver = false;
                                            query.setResult("BLOCK");
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isResult("HOLD")) {
                                            deliver = null;
                                        } else {
                                            deliver = true;
                                        }
                                        if (deliver == null) {
                                            Server.logWarning(
                                                    "delivery ID " + deliveryID
                                                    + " still holding to <"
                                                    + recipient.getAddress() + ">."
                                            );
                                        } else if (deliver) {
                                            String returnPath = extractAddress(
                                                    headers.getHeader("Return-Path", null), false
                                            );
                                            boolean changed = false;
                                            if (user != null && query == null) {
                                                message = loadMessageSPFBL(message);
                                                changed = true;
                                                String from = extractAddress(message.getHeader("From", null), true);
                                                String replyTo = extractAddress(message.getHeader("Reply-To", null), true);
                                                if (replyTo != null) {
                                                    replyTo = user.getInvitation(replyTo);
                                                } else if (from != null) {
                                                    replyTo = user.getInvitation(from);
                                                }
                                                if (replyTo != null) {
                                                    message.setReplyTo(InternetAddress.parse(replyTo));
                                                }
                                            }
                                            if (message.getHeader("To", null) == null) {
                                                message.addHeader("To", "Undisclosed-Recipients:;");
                                                changed = true;
                                            }
                                            String received = headers.getHeader(
                                                    "Received", null
                                            );
                                            if (received != null) {
                                                message.addHeader("Received", received);
                                            }
                                            String authentication = headers.getHeader(
                                                    "Authentication-Results", null
                                            );
                                            if (authentication != null) {
                                                message.addHeader("Authentication-Results", authentication);
                                            }
                                            String receivedSPF = headers.getHeader(
                                                    "Received-SPF", null
                                            );
                                            if (receivedSPF != null) {
                                                message.addHeader("Received-SPF", receivedSPF);
                                            }
                                            String receivedSPFBL = headers.getHeader(
                                                    "Received-SPFBL", null
                                            );
                                            if (receivedSPFBL != null) {
                                                message.addHeader("Received-SPFBL", receivedSPFBL);
                                            }
                                            if (returnPath != null) {
                                                message.addHeader("Return-Path", '<' + returnPath + '>');
                                            }
                                            if (changed) {
                                                try {
                                                    message.saveChanges();
                                                } catch (Exception ex) {
                                                    Server.logError(ex);
                                                }
                                            }
                                            try {
                                                if (ServerSMTP.sendMessage(Locale.US, message, recipient, headers, false)) {
                                                    Server.logInfo("delivery ID " + deliveryID
                                                            + " was sent to <" + recipient.getAddress() + ">."
                                                    );
                                                    deliveryFile.delete();
                                                    if (query != null) {
                                                        query.setResult("QUEUE", "ACCEPT");
                                                        User.storeDB2(timeKey, query);
                                                    }
                                                } else {
                                                    throw new Exception("Message not delivered: " + deliveryFile.getName());
                                                }
                                            } catch (Exception ex) {
                                                storeDeliveryStatus(deliveryFile, headers);
                                                if ("failed".equals(headers.getHeader("Action", null))) {
                                                    processDelivery(timeKey);
                                                }
                                            }
                                        } else {
                                            Server.logInfo("delivery ID " + deliveryID
                                                    + " wasn't sent to <" + recipient.getAddress() + ">."
                                            );
                                            deliveryFile.delete();
                                        }
                                    }
                                }
                            } catch (SMTPSendFailedException ex) {
                                switch (ex.getReturnCode() / 100) {
                                    case 5:
                                        Server.logWarning(
                                                "bounce from delivery ID "
                                                        + deliveryID
                                                        + " was permanentyly rejected."
                                        );
                                        deliveryFile.delete();
                                        break;
                                    case 4:
                                        Server.logWarning(
                                                "bounce from delivery ID "
                                                        + deliveryID
                                                        + " was temporary rejected."
                                        );
                                        break;
                                    default:
                                        Server.logError(ex);
                                        break;
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        }
                    }
                    if (keepRunning()) {
                        processExternal();
                    }
                    for (File file : INCOMING.listFiles()) {
                        if (System.currentTimeMillis() - file.lastModified() > Server.WEEK_TIME) {
                            file.delete();
                        }
                    }
                    Server.logInfo("finished queue process.");
                    acquire();
                } catch (InterruptedException ex) {
                    Server.logWarning("interrupted queue thread.");
                    break;
                } finally {
                    release();
                }
            }
            Server.logInfo("terminated queue thread.");
        }
        
        private Boolean mustDeliver(
                long timeKey,
                User.Query query,
                MimeMessage received
        ) {
            String messageID = Long.toString(timeKey, 32);
            Boolean deliver = null;
            if (query == null) {
                return true;
            } else if (query.isRecipientAbuse() && !query.hasLinkMap()) {
                // The message content must be processed.
                deliver = null;
            } else if (query.isWhiteKey()) {
                query.clearBlock(timeKey);
                query.setResult("WHITE");
                query.addBeneficial(timeKey);
                deliver = true;
            } else if (query.isSpoofingFrom()) {
                query.blockKey(timeKey, "SPOOFING");
                query.ban(timeKey, "SPOOFING");
                query.setResultFilter("BLOCK", "FROM_SPOOFING");
                query.addHarmful(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (query.isSpoofingFQDN()) {
                query.blockKey(timeKey, "SPOOFING");
                query.ban(timeKey, "SPOOFING");
                query.setResultFilter("BLOCK", "FQDN_SPOOFING");
                query.addHarmful(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (query.isFromBlocked()) {
                query.blockKey(timeKey, "FROMBLOCKED");
                query.ban(timeKey, "FROMBLOCKED");
                query.setResultFilter("BLOCK", "FROM_BLOCKED");
                query.addHarmful(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (query.isRecipientAdmin() && !query.hasLinkMap()) {
                // The message content must be processed.
                deliver = null;
            } else if (query.isSenderMailerDeamon() && !query.hasLinkMap()) {
                // The message content must be processed.
                deliver = null;
            } else if (query.isBanned()) {
                SPF.setSpam(timeKey, query.getTokenSet());
                query.clearWhite(timeKey);
                query.setResultFilter("BLOCK", "ORIGIN_BANNED;" + query.getBannedKey());
                query.addHarmful(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (query.isTrustedMailerDaemon()) {
                query.setResultFilter("ACCEPT", "MAILER_DEAMON_TRUSTED");
                query.addAcceptable();
                deliver = true;
            } else if (query.isBlockKey()) {
                SPF.setSpam(timeKey, query.getTokenSet());
                query.clearWhite(timeKey);
                query.setResult("BLOCK");
                query.addUndesirable(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (query.isWhiteKeyByAdmin()) {
                query.whiteKey(timeKey);
                query.setResultFilter("WHITE", "ORIGIN_WHITE_KEY_ADMIN");
                query.addBeneficial(timeKey);
                deliver = true;
            } else if (query.isBlockKeyByAdmin()) {
                query.blockKey(timeKey, "ADMIN");
                query.setResultFilter("BLOCK", "ORIGIN_BLOCK_KEY_ADMIN;" + query.getBlockKey());
                query.addUndesirable(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            } else if (User.isExpiredHOLD(timeKey)) {
                if (query.isFail()) {
                    query.blockKey(timeKey, "FAIL");
                    query.setResultFilter("BLOCK", "SPF_FAIL");
                    Abuse.offer(timeKey, query);
                } else if (query.isBlock()) {
                    query.blockKey(timeKey, "BLOCKED");
                    query.setResultFilter("BLOCK", "ORIGIN_BLOCKED");
                    Abuse.offer(timeKey, query);
                } else {
                    query.setResultFilter("REJECT", "HOLD_EXPIRED");
                }
                query.addUnacceptable();
                deliver = false;
            } else if (query.hasDynamicIP()) {
                query.blockKey(timeKey, "DYNAMIC");
                query.ban(timeKey, "DYNAMIC");
                query.setResultFilter("BLOCK", "IP_DYNAMIC");
                query.addHarmful(timeKey);
                Abuse.offer(timeKey, query);
                deliver = false;
            }
            TreeSet<String> processedSet = new TreeSet<>();
            if (deliver == null) {
                deliver = processContent(timeKey, query, received, processedSet);
            }
            if (deliver == null) {
                String malware;
                if (query.isRecipientAbuse()) {
                    query.setResultFilter("ACCEPT", "TO_ABUSE");
                    query.addAcceptable();
                    return true;
                } else if (query.isRecipientAdmin() && query.isSenderMailerDeamon()) {
                    query.setResultFilter("ACCEPT", "MAILER_DEAMON_TO_ADMIN");
                    query.addAcceptable();
                    return true;
                } else if (query.isTrustedMailerDaemon()) {
                    query.setResultFilter("ACCEPT", "MAILER_DEAMON_TRUSTED");
                    query.addAcceptable();
                    return true;
                } else if (query.isWhiteKey()) {
                    if (query.hasMalwareNotIgnored()) {
                        SPF.setSpam(timeKey, query.getTokenSet());
                        query.setResultFilter("REJECT", "MALWARE_NOT_IGNORED");
                        query.addHarmful(timeKey);
                        return false;
                    } else {
                        query.clearBlock(timeKey);
                        query.setResult("WHITE");
                        query.addBeneficial(timeKey);
                        return true;
                    }
                } else if (query.hasMalwareNotIgnored()) {
                    query.blockKey(timeKey, "MALWARE");
                    query.ban(timeKey, "MALWARE");
                    query.setResultFilter("BLOCK", "MALWARE_NOT_IGNORED");
                    query.addHarmful(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.hasExecutableBlocked()) {
                    query.blockKey(timeKey, "EXECUTABLE");
                    query.ban(timeKey, "EXECUTABLE");
                    query.setResultFilter("BLOCK", "EXECUTABLE_BLOCKED");
                    query.addHarmful(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.hasPhishingBlocked()) {
                    query.blockKey(timeKey, "PHISHING");
                    query.ban(timeKey, "PHISHING");
                    query.setResultFilter("BLOCK", "PHISHING_BLOCKED");
                    query.addHarmful(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;                    
                } else if (query.isWhite()) {
                    query.whiteKey(timeKey);
                    query.setResultFilter("WHITE", "ORIGIN_WHITELISTED");
                    query.addDesirable(timeKey);
                    return true;
                } else if (query.isFail() && query.isFromNotSigned()) {
                    query.blockKey(timeKey, "FAIL");
                    query.ban(timeKey, "FAIL");
                    query.setResultFilter("BLOCK", "SPF_FAIL");
                    query.addHarmful(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;                 
                } else if (query.isBlockKey()) {
                    SPF.setSpam(timeKey, query.getTokenSet());
                    query.clearWhite(timeKey);
                    query.setResult("BLOCK");
                    query.addUndesirable(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.hasSuspectFrom()) {
                    query.blockKey(timeKey, "SUSPECTFROM");
                    query.setResultFilter("BLOCK", "FROM_SUSPECT");
                    query.addUndesirable(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.getSubjectFlag() == HARMFUL) {
                    query.blockKey(timeKey, "SUBJECT");
                    query.setResultFilter("BLOCK", "SUBJECT_HARMFUL");
                    query.addUndesirable(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.isBlock()) {
                    Server.logWarning("message ID " + messageID + " is blocked.");
                    query.setResult("HOLD");
                    return null;
                } else if (query.isBlockedCIDR()) {
                    Server.logWarning("message ID " + messageID + " is blocked.");
                    query.setResult("HOLD");
                    return null;
                } else if (query.hasExecutableNotIgnored()) {
                    Server.logWarning("message ID " + messageID + " has an executable not ignored by user.");
                    query.setResult("HOLD");
                    return null;
                } else if (query.isBeneficial()) {
                    query.setResultFilter("ACCEPT", "ORIGIN_BENEFICIAL");
                    query.addDesirable(timeKey);
                    return true;
                } else if (query.isHarmful() && (System.currentTimeMillis() - timeKey) / 1000 / 60 < Core.getDeferTimeRED()) {
                    Server.logWarning("message ID " + messageID + " with bad reputation.");
                    query.setResult("HOLD");
                    return null;
                } else if (query.isSoftfail() && ((System.currentTimeMillis() - timeKey) / 1000 / 60 < Core.getDeferTimeSOFTFAIL())) {
                    Server.logWarning("message ID " + messageID + " in softfail greyliting.");
                    query.setResult("HOLD");
                    return null;
                } else if (System.currentTimeMillis() - timeKey > Server.HOUR_TIME) {
                    Server.logWarning("message ID " + messageID + " hold expired.");
                    query.setResultFilter("ACCEPT", "HOLD_EXPIRED");
                    query.addAcceptable();
                    return true;
                } else if (query.isAnyLinkSuspect(true)) {
                    Server.logWarning("message ID " + messageID + " has a suspect link.");
                    query.setResult("HOLD");
                    return null;
                } else if (query.isBodySuspect()) {
                    Server.logWarning("message ID " + messageID + " body is subject.");
                    query.setResult("HOLD");
                    return null;
                } else if ((malware = Core.checkGoogleSafeBrowsing(timeKey, query.getUserEmail(), processedSet)) != null) {
                    Server.logWarning("message ID " + messageID + " has malware " + malware + ".");
                    query.blockKey(timeKey, "MALWARE");
                    query.setMalware(timeKey, malware);
                    query.addHarmful(timeKey);
                    Abuse.offer(timeKey, query);
                    return false;
                } else if (query.isUndesirable()) {
                    Server.logWarning("message ID " + messageID + " is suspect.");
                    query.setResult("HOLD");
                    return null;
                } else {
                    query.addAcceptable();
                    return true;
                }
            } else {
                return deliver;
            }
        }
    }
    
    public static boolean isBounceMessage(
            MimeMessage message
    ) throws MessagingException {
        if (message == null) {
            return false;
        } else {
            String returnPath = message.getHeader("Return-Path", null);
            String subject = message.getSubject();
            if (Objects.equals(returnPath, "<>")) {
                if (Objects.equals(subject, "Undelivered Mail Returned to Sender")) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean reportAbuse(
            User user,
            MimeMessage message
    ) {
        try {
            Entry<Long,User.Query> entry = newQuery(user, message);
            Long timeKey = entry == null ? null : entry.getKey();
            User.Query query = entry == null ? null : entry.getValue();
            if (message == null) {
                return false;
            } else if (query == null) {
                if (message.getHeader("Received") == null) {
                    Server.logWarning("complain was ignored to not have Received headers.");
                    return true;
                } else {
                    return false;
                }
            } else if (query.isLocalRouting()) {
                Server.logWarning("local routing complaint was ignored.");
                return true;
            } else {
                if (query.isWhiteKey()) {
                    query.setSpam(timeKey);
                } else {
                    query.blockKey(timeKey, "COMPLAIN");
                }
                processContent(timeKey, query, message, new TreeSet<>());
                User.storeDB2(timeKey, query);
                query.blockExecutables(timeKey);
                query.setFilter("ABUSE_SUBMISSION");
                if (query.hasMalware()) {
                    query.banOrBlock(timeKey, "MALWARE");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.hasExecutableBlocked()) {
                    query.banOrBlock(timeKey, "EXECUTABLE");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.hasPhishingBlocked()) {
                    query.banOrBlock(timeKey, "PHISHING");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.isBanned()) {
                    query.addHarmful(timeKey);
                } else {
                    query.addUndesirable(timeKey);
                }
                String sender = query.getSender();
                String queueID = query.getQueueID();
                String client = query.getClient();
                String ip = query.getIP();
                String fqdn = query.getFQDN();
                storeIncomingMessage(queueID, client, message);
                White.dropFQDN(fqdn);
                if (!Abuse.offer(timeKey, query)) {
                    if (query.isSenderFreemail()) {
                        Block.addEmail(sender, "ABUSE_SUBMISSION");
                    } else {
                        Block.tryToDominoBlockIP(ip, "ABUSE_SUBMISSION");
                        Block.addFQDN(fqdn, "ABUSE_SUBMISSION");
                    }
                }
                return true;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    private static final Regex RECEIVED_PATTERN = new Regex("^"
            + "(PASS|SOFTFAIL|FAIL|NEUTRAL|NONE|FLAG|HOLD|WHITE) "
            + "https?://(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)(:[0-9]+)?/"
            + "([a-z]{2}/)?"
            + "([0-9a-zA-Z_-]+)"
            + "$"
    );

    private static final Regex UNSUBSCRIBE_PATTERN = new Regex(""
            + "(List-Unsubscribe: )?<"
            + "https?://(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)(:[0-9]+)?/"
            + "([a-z]{2}/)?"
            + "([0-9a-zA-Z_-]+)"
            + ">"
    );

    private static final Regex EMAIL_RIGID_PATTERN = new Regex("<"
            + "([0-9a-z][0-9a-z._-]*@"
            + "(([a-z0-9]|[a-z0-9][a-z0-9_\\-]{0,61}[a-z0-9])"
            + "(\\.([a-z0-9]|[a-z0-9][a-z0-9_\\-]{0,61}[a-z0-9]))*))"
            + ">"
    );

    private static final Regex EMAIL_RELAXED_PATTERN = new Regex("\\b"
            + "([0-9a-z][0-9a-z._-]*@"
            + "(([a-z0-9]|[a-z0-9][a-z0-9_\\-]{0,61}[a-z0-9])"
            + "(\\.([a-z0-9]|[a-z0-9][a-z0-9_\\-]{0,61}[a-z0-9]))*))"
            + "\\b"
    );

    private static final Regex LINK_PATTERN = new Regex("(?i)\\b("
            + "([0-9a-z][0-9a-z._-]*@"
            + "(([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9])"
            + "(\\.([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9]))*))"
            + "|"
            + "(https?\\:\\/\\/([a-z0-9\\._-]+|\\[[a-f0-9\\:]+\\])"
            + "(:[0-9]{1,6})?[a-z0-9\\-\\._~!\\$&\\(\\)\\*+,;\\=:\\/?@#]*)"
            + "|"
            + "(www\\.[a-z0-9\\._-]+\\.([a-z]{2,5})"
            + "(\\/[a-z0-9\\-\\._~!\\$&\\(\\)\\*+,;=:\\/?@#]*)?)"
            + "|"
            + "([a-z0-9\\._-]+\\.(com|org|net|int|edu|gov|mil|"
            + "ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|"
            + "ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|"
            + "bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|"
            + "cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|"
            + "fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|"
            + "gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|"
            + "io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|"
            + "ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|"
            + "mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|"
            + "na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|"
            + "pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|"
            + "sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|"
            + "sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|"
            + "ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|"
            + "za|zm|zw)"
            + "(\\/[a-z0-9\\-\\._~!\\$&\\(\\)\\*+,;=:\\/?@#]*))"
            + ")\\b"
    );
    
    public static boolean processComplainTicket(
            String complainer,
            Message message
    ) throws MessagingException, ProcessException {
        if (complainer == null) {
            return false;
        } else if (message == null) {
            return false;
        } else {
            String[] receivedArray = message.getHeader("Received-SPFBL");
            if (receivedArray == null) {
                return false;
            } else {
                for (String receivedSPFBL: receivedArray) {
                    receivedSPFBL = receivedSPFBL.replaceAll("[\\s\\r\\n\\t]+", " ");
                    Matcher matcher = RECEIVED_PATTERN.createMatcher(receivedSPFBL);
                    if (matcher.find()) {
                        String ticket = matcher.group(8);
                        RECEIVED_PATTERN.offerMatcher(matcher);
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
                            if (System.currentTimeMillis() - date < 1814400000L) {
                                String value = Core.decodeHuffman(byteArray, 8);
                                StringTokenizer tokenizer2 = new StringTokenizer(value, " ");
                                String operator = tokenizer2.nextToken();
                                if (operator.equals("spam")) {
                                    User user = null;
                                    String recipient = null;
                                    while (tokenizer2.hasMoreTokens()) {
                                        String token = tokenizer2.nextToken();
                                        if (token.endsWith(":")) {
                                            int index = token.length() - 1;
                                            token = token.substring(0, index);
                                            user = User.get(token);
                                        } else if (token.startsWith(">")) {
                                            recipient = token.substring(1);
                                        }
                                    }
                                    if (recipient == null) {
                                        Server.logTrace("Received-SPFBL link found.");
                                    } else {
                                        Server.logTrace("Received-SPFBL link found for " + recipient + ".");
                                    }
                                    if (user == null) {
                                        Server.logTrace("abuse report user not found.");
                                        return false;
                                    } else {
                                        Server.logTrace("abuse report user found: " + user.getEmail());
                                        User.Query query = user.getQuerySafe(date);
                                        if (query == null) {
                                            Server.logTrace("abuse report query not found.");
                                            return false;
                                        } else {
                                            processContent(date, query, message, new TreeSet<>());
                                            Abuse.offer(date, query);
                                            if (query.isWhiteKey()) {
                                                query.setSpam(date);
                                            } else {
                                                query.blockKey(date, "COMPLAIN");
                                            }
                                            User.storeDB2(date, query);
                                            Server.logInfo("abuse reported by: " + complainer);
                                            return true;
                                        }
                                    }
                                } else {
                                    Server.logTrace("abuse report not found at link.");
                                    return false;
                                }
                            } else {
                                Server.logTrace("expired Received-SPFBL link.");
                                return false;
                            }
                        } else {
                            Server.logTrace("decryption failed for Received-SPFBL link.");
                            return false;
                        }
                    } else {
                        RECEIVED_PATTERN.offerMatcher(matcher);
                        Server.logTrace("not valid Received-SPFBL header.");
                        return false;
                    }
                }
                Server.logTrace("abuse report without Received-SPFBL link.");
                return false;
            }
        }
    }
    
    private static final Regex BOUNCE1_PATTERN = new Regex(""
            + "The message you sent to ([^ ]+)/([^ ]+) was rejected because "
    );
    
    private static String[] processBounce(String headerFrom, String text) {
        if (headerFrom == null) {
            return null;
        } else if (text == null) {
            return null;
        } else {
            String deliveryStatus = null;
            String originalRecipient = null;
            String diagnostic = null;
            String returned = null;
            text = text.trim();
            if (text.startsWith("This is the mail system at host ")) {
                // Bounce from Postfix.
                diagnostic = text.toLowerCase();
            } else if (text.contains("The address may be misspelled or may not exist. Try one or more of the following:")) {
                int index = text.indexOf("Original Message Headers");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 72).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("Your message to <")) {
                // Bounce from Postfix.
                diagnostic = text.toLowerCase();
            } else if (text.startsWith("This message was created automatically by mail delivery software.")) {
                // Bounce from Exim.
                int index = text.indexOf("------ This is a copy of the message, including all the headers. ------");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 72).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("Your message did not reach some or all of the intended recipients.")) {
                // Bounce from hMailServer.
                diagnostic = text.toLowerCase();
            } else if (headerFrom.equals("mailer-daemon@googlemail.com")) {
                // Bounce from Google Mail.
                int index = text.indexOf("----- Original message -----");
                if (index > 0) {
                    diagnostic = text.substring(0, index);
                    returned = text.substring(index + 29).trim();
                } else {
                    diagnostic = text;
                }
            } else if (text.startsWith("Delivery has failed to these recipients or groups:")) {
                // Bounce from Outlook.com.
                int index = text.indexOf("Diagnostic information for administrators:");
                if (index > 0) {
                    diagnostic = text.substring(index);
                }
            } else if (text.startsWith("MailEnable: Message could not be delivered to some recipients.")) {
                // Bounce from MailEnable.
                int index = text.indexOf("Message headers follow:");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 24).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("MailEnable: Message delivery has been delayed.")) {
                // Bounce from MailEnable.
                int index = text.indexOf("Message headers follow:");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 24).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("This is the mail delivery agent at Symantec Email Security.cloud.")) {
                // Bounce from Security.cloud.
                diagnostic = text.toLowerCase();
            } else if (text.startsWith("Hi. This is the qmail-send program at ")) {
                // Bounce from Qmail.
                int index = text.indexOf("--- Below this line is a copy of the message.");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 46).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("Please scroll down for English.") && text.contains("Your original message is included as attachment.")) {
                // Bounce from Coremail.
                diagnostic = text.toLowerCase();
            } else if (text.startsWith("Failed to deliver to ")) {
                diagnostic = text.toLowerCase();
            } else if (text.startsWith("Tu system pocztowy IQ PL / This is IQ PL mail system at ")) {
                int index = text.indexOf("--- Below this line is a copy of the message.");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 46).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.contains("您的邮件不能成功的递送到以下收件，错误原因如下：")) {
                int index = text.indexOf("--- 以下是要发送的邮件信息");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 16).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.contains("您的邮件不能成功的递送到指定地址。这是一个永久的错误，因此不得不放弃继续递送。")) {
                int index = text.indexOf("--- Below this line is a copy of the message.");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 45).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.contains("您的邮件不能成功的递送到以下收件人。")) {
                int index = text.indexOf("邮件头：");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 4).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.contains("无法将您的邮件投递至以下指定地址:")) {
                int index = text.indexOf("----- Original message follows.");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 32).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("抱歉，您的邮件被退回来了……")) {
                int index = text.indexOf("---------- Forwarded message ----------");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 40).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("Delivery failed ")) {
                int index = text.indexOf("Original message follows.");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 26).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("NOTICE: Delivery Failure.")) {
                int index = text.indexOf("---------- Forwarded message ----------");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 40).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("Your message was automatically rejected:")) {
                int index = text.indexOf("---------- Forwarded message ----------");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 40).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("I'm sorry to have to inform you that your message could not be delivered to one or more recipients.")) {
                int index = text.indexOf("---------- Forwarded message ----------");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 40).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            } else if (text.startsWith("---------------------------------------------------------------------------------")) {
                Matcher matcher = BOUNCE1_PATTERN.createMatcher(text);
                if (matcher.find()) {
                    originalRecipient = matcher.group(2) + '@' + matcher.group(1);
                    diagnostic = text.toLowerCase();
                }
                BOUNCE1_PATTERN.offerMatcher(matcher);
            } else if (text.startsWith("=======================================================================\r\n=  Greetings from the MDaemon mail system at ")) {
                int index = text.indexOf("=  Session Transcript  =");
                if (index > 0) {
                    diagnostic = text.substring(0, index).toLowerCase();
                    returned = text.substring(index + 25).trim();
                } else {
                    diagnostic = text.toLowerCase();
                }
            }
            if (diagnostic != null) {
                Matcher matcher = EMAIL_RIGID_PATTERN.createMatcher(diagnostic);
                if (matcher.find()) {
                    originalRecipient = matcher.group(1);
                    EMAIL_RIGID_PATTERN.offerMatcher(matcher);
                } else {
                    EMAIL_RIGID_PATTERN.offerMatcher(matcher);
                    matcher = EMAIL_RELAXED_PATTERN.createMatcher(diagnostic);
                    if (matcher.find()) {
                        originalRecipient = matcher.group(1);
                    }
                    EMAIL_RELAXED_PATTERN.offerMatcher(matcher);
                }
                matcher = STATUS_PATTERN.createMatcher(diagnostic);
                if (matcher.find()) {
                    deliveryStatus = matcher.group(0);
                } else if (diagnostic.contains("The email account that you tried to reach does not exist.")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.contains("RESOLVER.RST.RestrictedToRecipientsPermission")) {
                    deliveryStatus = "5.7.1";
                } else if (diagnostic.contains("you may not have permission to post messages to the group.")) {
                    deliveryStatus = "5.7.1";
                } else if (diagnostic.toUpperCase().contains("rejected by system")) {
                    deliveryStatus = "5.7.1";
                } else if (diagnostic.toUpperCase().contains("spam message")) {
                    deliveryStatus = "5.7.1";
                } else if (diagnostic.toUpperCase().contains("no mailbox")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("no such user")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("undeliverable address")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("unrouteable address")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("user unknown")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("don`t exist")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("don`t exist")) {
                    deliveryStatus = "5.1.1";
                } else if (diagnostic.toUpperCase().contains("does not exist")) {
                    deliveryStatus = "5.2.2";
                } else if (diagnostic.toUpperCase().contains("quota exceeded")) {
                    deliveryStatus = "5.2.2";
                } else if (diagnostic.toUpperCase().contains("mailbox is full")) {
                    deliveryStatus = "5.2.2";
                } else if (diagnostic.toUpperCase().contains("inbox is full")) {
                    deliveryStatus = "5.2.2";
                } else {
                    deliveryStatus = "5.0.0";
                }
                STATUS_PATTERN.offerMatcher(matcher);
            }
            if (returned != null) {
                Matcher matcher = UNSUBSCRIBE_PATTERN.createMatcher(returned);
                if (matcher.find()) {
                    String hostname = matcher.group(2);
                    if (Core.isMyHostname(hostname) || Core.isMyHostname("localhost")) {
                        try {
                            String ticket = matcher.group(8);
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
                                if (System.currentTimeMillis() - date < 1814400000L) {
                                    String value = Core.decodeHuffman(byteArray, 8);
                                    StringTokenizer tokenizer2 = new StringTokenizer(value, " ");
                                    String operator = tokenizer2.nextToken();
                                    if (operator.equals("unsubscribe") && tokenizer2.hasMoreTokens()) {
                                        originalRecipient = tokenizer2.nextToken();
                                        Server.logInfo("list unsubscribe: " + originalRecipient);
                                    }
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                }
                UNSUBSCRIBE_PATTERN.offerMatcher(matcher);
            }
            if (deliveryStatus == null) {
                return null;
            } else if (originalRecipient == null) {
                return null;
            } else {
                String[] result = {deliveryStatus, originalRecipient};
                return result;
            }
        }
    }
    
    private static String[] extractContentType(Part part)
            throws MessagingException {
        if (part == null) {
            return null;
        } else {
            String type = part.getContentType();
            StringTokenizer tokenizer = new StringTokenizer(type, ";");
            type = tokenizer.nextToken().toLowerCase().trim();
            String charset = "UTF-8";
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken().trim();
                if (token.toLowerCase().startsWith("charset=")) {
                    charset = token.substring(8);
                    break;
                }
            }
            String[] result = {type, charset};
            return result;
        }
    }
    
    private static String extractFilename(Part part)
            throws MessagingException {
        if (part == null) {
            return null;
        } else {
            String filename = null;
            try {
                filename = part.getFileName();
            } catch (javax.mail.internet.ParseException ex) {
                String[] dispositionArray = part.getHeader("Content-Disposition");
                if (dispositionArray != null && dispositionArray.length > 0) {
                    String disposition = dispositionArray[0];
                    StringTokenizer tokenizer = new StringTokenizer(disposition, ";");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken().trim();
                        if (token.startsWith("filename=")) {
                            token = token.substring(9);
                            token = token.replace('"', ' ');
                            token = token.replaceAll("\\s+", " ");
                            filename = token.trim();
                            break;
                        }
                    }
                }
            }
            return filename;
        }
    }
    
    private static ArrayList<Part> extractPartList(Message message)
            throws IOException, MessagingException {
        if (message == null) {
            return null;
        } else if (message.getSize() == 0) {
            return null;
        } else {
            fixContentMetadata(message);
            ArrayList<Part> partList = new ArrayList<>(3);
            LinkedList<Object> contentStack = new LinkedList<>();
            contentStack.push(message.getContent());
            while (!contentStack.isEmpty()) {
                try {
                    Object content = contentStack.pop();
                    if (content instanceof MimeMultipart) {
                        MimeMultipart multipart = (MimeMultipart) content;
                        for (int index = multipart.getCount() - 1; index >= 0; index--) {
                            BodyPart part = multipart.getBodyPart(index);
                            contentStack.push(part);
                        }
                    } else if (content instanceof MimeBodyPart) {
                        BodyPart part = (MimeBodyPart) content;
                        fixContentMetadata(part);
                        if (part.getContent() instanceof MimeMultipart) {
                            MimeMultipart multipart = (MimeMultipart) part.getContent();
                            contentStack.push(multipart);
                        } else {
                            partList.add(part);
                            if (part.getContent() instanceof MimeMessage) {
                                MimeMessage forwarded = (MimeMessage) part.getContent();
                                fixContentMetadata(forwarded);
                                contentStack.push(forwarded.getContent());
                            }
                        }
                    }
                } catch (javax.mail.internet.ParseException ex) {
                    // Do nothing.
                } catch (com.sun.mail.util.DecodingException ex) {
                    // Do nothing.
                } catch (java.io.IOException ex) {
                    // Do nothing.
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            if (partList.isEmpty()) {
                partList.add(message);
            }
            return partList;
        }
    }
    
    public static TreeSet<String> extractContent(
            Message message,
            boolean trusted
    ) {
        try {
            ArrayList<Part> partList = extractPartList(message);
            if (partList == null) {
                return null;
            } else {
                String bodyText = null;
                TreeSet<String> contentSet = new TreeSet<>();
                TreeSet<String> urlSet = new TreeSet<>();
                TreeSet<String> passwordSet = new TreeSet<>();
                passwordSet.add("infected");
                while (!partList.isEmpty()) {
                    Part part = partList.remove(0);
                    String filename = extractFilename(part);
                    String[] contentType = extractContentType(part);
                    String type = contentType[0];
                    String charset = contentType[1];
                    if (type.equals("text/plain") || type.equals("text")) {
                        try {
                            String text = null;
                            Object content = part.getContent();
                            if (content instanceof String) {
                                text = (String) content;
                            } else if (content instanceof InputStream) {
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                InputStream in = (InputStream) content;
                                int nread;
                                while ((nread = in.read()) >= 0) {
                                    baos.write(nread);
                                }
                                text = baos.toString(charset);
                            } else {
                                throw new Exception("Content type not reconized: " + type + " " + content.getClass());
                            }
                            if (bodyText == null) {
                                bodyText = new String(text.getBytes("UTF-8"), "UTF-8");
                            }
                            for (String token : text.split("[\\s\\t\\r\\n]+")) {
                                passwordSet.add(token);
                            }
                            Matcher matcher = LINK_PATTERN.createMatcher(text);
                            while (matcher.find()) {
                                String link = matcher.group();
                                if (isValidEmail(link)) {
                                    contentSet.add(link.toLowerCase());
                                } else if (link.startsWith("http://") || link.startsWith("https://")) {
                                    urlSet.add(link);
                                } else {
                                    urlSet.add("http://" + link);
                                }
                            }
                            LINK_PATTERN.offerMatcher(matcher);
                        } catch (UnsupportedEncodingException ex) {
                            Server.logError("unsupported encoding " + part.getContentType());
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    } else if (type.equals("text/html")) {
                        try {
                            String text;
                            Object content = part.getContent();
                            if (content instanceof String) {
                                text = (String) content;
                            } else if (content instanceof SharedByteArrayInputStream) {
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                SharedByteArrayInputStream in = (SharedByteArrayInputStream) content;
                                int nread;
                                while ((nread = in.read()) >= 0) {
                                    baos.write(nread);
                                }
                                text = baos.toString(charset);
                            } else {
                                throw new Exception("class not reconized " + content.getClass());
                            }
                            Document document = Jsoup.parse(text);
                            Elements scriptElements = document.getElementsByTag("script");
                            if (!scriptElements.isEmpty()) {
                                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                messageDigest.update(text.getBytes());
                                String md5 = Core.md5Hex(messageDigest.digest());
                                String signature = md5 + "." + text.length() + ".html";
                                Server.logInfo("executable attachment found: " + signature);
                                contentSet.add(signature);
                            }
                            Element body = document.body();
                            if (body != null) {
                                text = body.text();
                                Elements imgElements = body.getElementsByTag("img");
                                if (!trusted && !imgElements.isEmpty() && text.isEmpty()) {
                                    contentSet.add("MALWARE=SPFBL.HTML.body.img");
                                }
                                Elements aElements = body.getElementsByTag("a");
                                for (int index = 0; index < aElements.size(); index++) {
                                    Element element = aElements.get(index);
                                    String href = element.attr("href");
                                    if (href.matches("^(mailto|https?):.+")) {
                                        urlSet.add(href);
                                    }
                                }
                            }
                            if (bodyText == null) {
                                bodyText = new String(text.getBytes("UTF-8"), "UTF-8");
                            }
                            for (String token : text.split("[\\s\\t\\r\\n]+")) {
                                passwordSet.add(token);
                            }
                            Matcher matcher = LINK_PATTERN.createMatcher(text);
                            while (matcher.find()) {
                                String link = matcher.group();
                                if (isValidEmail(link)) {
                                    contentSet.add(link.toLowerCase());
                                } else if (link.startsWith("http://") || link.startsWith("https://")) {
                                    urlSet.add(link);
                                } else {
                                    urlSet.add("http://" + link);
                                }
                            }
                            LINK_PATTERN.offerMatcher(matcher);
                        } catch (UnsupportedEncodingException ex) {
                            Server.logError("unsupported encoding " + part.getContentType());
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    } else if (type.startsWith("application/")) {
                        try {
                            int length = part.getSize();
                            if (filename != null && length < 2097152) {
                                int index = filename.lastIndexOf('.') + 1;
                                String extension = filename.substring(index);
                                extension = extension.toLowerCase();
                                if (extension.equals("pdf")) {
                                    PDDocument document;
                                    try (InputStream inputStream = part.getInputStream()) {
                                        document = PDDocument.load(inputStream);
                                        document = document.isEncrypted() ? null : document;
                                    } catch (InvalidPasswordException ex) {
                                        document = null;
                                    }
                                    if (document == null) {
                                        // Encrypted PDF.
                                        length = 0;
                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                        try (InputStream inputStream = part.getInputStream()) {
                                            int code;
                                            while ((code = inputStream.read()) != -1) {
                                                length++;
                                                messageDigest.update((byte) code);
                                            }
                                        }
                                        String md5 = Core.md5Hex(messageDigest.digest());
                                        String signature = md5 + "." + length + "." + extension;
                                        Server.logInfo("potencial executable attachment found: " + signature);
                                        contentSet.add(signature);
                                    } else {
                                        try {
                                            PDPage pdfpage = document.getPage(0);
                                            List<PDAnnotation> annotations = pdfpage.getAnnotations();
                                            for (int j = 0; j < annotations.size(); j++) {
                                                PDAnnotation annot = annotations.get(j);
                                                if (annot instanceof PDAnnotationLink) {
                                                    PDAnnotationLink link = (PDAnnotationLink) annot;
                                                    PDAction action = link.getAction();
                                                    if (action instanceof PDActionURI) {
                                                        PDActionURI uri = (PDActionURI) action;
                                                        urlSet.add(uri.getURI());
                                                    }
                                                }
                                            }
                                            if (bodyText == null) {
                                                PDFTextStripper tStripper = new PDFTextStripper();
                                                tStripper.setStartPage(1);
                                                tStripper.setEndPage(3);
                                                String text = tStripper.getText(document);
                                                bodyText = new String(text.getBytes("UTF-8"), "UTF-8");
                                            }
                                        } finally {
                                            document.close();
                                        }
                                    }
                                } else if (extension.equals("doc")) {
                                    boolean executable;
                                    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                    try (InputStream inputStream = part.getInputStream()) {
                                        executable = Core.isAutoExecutableOfficeFile(
                                                extension, inputStream, messageDigest
                                        );
                                    }
                                    if (executable) {
                                        String md5 = Core.md5Hex(messageDigest.digest());
                                        String signature = md5 + "." + length + "." + extension;
                                        Server.logInfo("executable attachment found: " + signature);
                                        contentSet.add(signature);
                                        contentSet.add("MALWARE=SPFBL.Document.AutoOpen.doc");
                                    }
                                } else if (extension.equals("xls")) {
                                    boolean executable;
                                    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                    try (InputStream inputStream = part.getInputStream()) {
                                        executable = Core.isAutoExecutableOfficeFile(
                                                extension, inputStream, messageDigest
                                        );
                                    }
                                    if (executable) {
                                        String md5 = Core.md5Hex(messageDigest.digest());
                                        String signature = md5 + "." + length + "." + extension;
                                        Server.logInfo("executable attachment found: " + signature);
                                        contentSet.add(signature);
                                        contentSet.add("MALWARE=SPFBL.Document.AutoOpen.xls");
                                    }
                                } else if (Core.EXECUTABLE_SET.contains(extension)) {
                                    if (Core.HARMFUL_SET.contains(extension)) {
                                        contentSet.add("MALWARE=SPFBL.Executable." + extension);
                                    }
                                    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                    try (InputStream inputStream = part.getInputStream()) {
                                        int code;
                                        while ((code = inputStream.read()) != -1) {
                                            messageDigest.update((byte) code);
                                        }
                                    }
                                    String md5 = Core.md5Hex(messageDigest.digest());
                                    String signature = md5 + "." + length + "." + extension;
                                    Server.logInfo("executable attachment found: " + signature);
                                    contentSet.add(signature);
                                } else if (Core.COMPACTED_SET.contains(extension)) {
                                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                                    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                    try (InputStream inputStream = part.getInputStream()) {
                                        int code;
                                        while ((code = inputStream.read()) != -1) {
                                            outputStream.write(code);
                                            messageDigest.update((byte) code);
                                        }
                                    }
                                    Server.logTrace("PASSWORD SET " + passwordSet);
                                    boolean compacted = true;
                                    if (extension.equals("zip")) {
                                        try {
                                            byte[] byteArray = outputStream.toByteArray();
                                            ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
                                            try {
                                                ZipInputStream zis = new ZipInputStream(inputStream);
                                                ZipEntry entry;
                                                while ((entry = zis.getNextEntry()) != null) {
                                                    String filename2 = entry.getName();
                                                    int index2 = filename2.lastIndexOf('.') + 1;
                                                    String extension2 = filename2.substring(index2);
                                                    extension2 = extension2.toLowerCase();
                                                    if (Core.EXECUTABLE_SET.contains(extension2)) {
                                                        long length2 = entry.getSize();
                                                        MessageDigest messageDigest2 = MessageDigest.getInstance("MD5");
                                                        int code;
                                                        while ((code = zis.read()) != -1) {
                                                            messageDigest2.update((byte) code);
                                                        }
                                                        String md5 = Core.md5Hex(messageDigest2.digest());
                                                        String signature = md5 + "." + length2 + "." + extension2;
                                                        Server.logInfo("compacted executable found: " + signature);
                                                        contentSet.add(signature);
                                                    }
                                                }
                                                compacted = false;
                                            } catch (ZipException ex) {
                                                // TODO: implement decrypt algorithm.
                                                contentSet.add("MALWARE=SPFBL.ZIP.Encrypted");
                                            }
                                        } catch (Exception ex) {
                                            Server.logError(ex);
                                        }
                                    }
                                    if (compacted) {
                                        String md5 = Core.md5Hex(messageDigest.digest());
                                        String signature = md5 + "." + length + "." + extension;
                                        Server.logInfo("compacted attachment found: " + signature);
                                        contentSet.add(signature);
                                    }
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    } else if (type.startsWith("image/")) {
                        // Do nothing.
                    } else if (type.startsWith("text/")) {
                        // Do nothing.
                    } else if (type.startsWith("video/")) {
                        // Do nothing.
                    } else {
                        Server.logError("attachment content type not reconized: " + type + "\n" + part.getContent());
                    }
                }
                TreeSet<String> processedSet = new TreeSet<>();
                int connCount = 0;
                while (!urlSet.isEmpty() && processedSet.size() < 256) {
                    String link = urlSet.pollFirst();
                    try {
                        // Decode Google redirection.
                        if (link.startsWith("https://www.google.com/url?q=http")) {
                            link = link.substring(29, link.length());
                            link = URLDecoder.decode(link, "UTF-8");
                        } else if (link.startsWith("http://www.google.com/url?q=http")) {
                            link = link.substring(28, link.length());
                            link = URLDecoder.decode(link, "UTF-8");
                        }
                        // Process link.
                        URL url = new URL(link);
                        if (url.getProtocol().equals("mailto")) {
                            String email = url.getPath();
                            if (isValidEmail(email)) {
                                contentSet.add(email.toLowerCase());
                            }
                        } else if (processedSet.add(link)) {
                            boolean check;
                            String signatureURL = Core.getSignatureURL(link);
                            String host = url.getHost().toLowerCase();
                            if (signatureURL == null) {
                                check = false;
                            } else if (Block.containsExact(signatureURL)) {
                                contentSet.add(signatureURL);
                                check = false;
                            } else if (Core.SHORTENER_SET.contains(host)) {
                                contentSet.add(signatureURL);
                                check = true;
                            } else if (connCount > 16) {
                                contentSet.add(host);
                                check = false;
                            } else if (Ignore.containsFQDN(host)) {
                                contentSet.add(host);
                                check = false;
                            } else if (Provider.containsFQDN(host)) {
                                contentSet.add(host);
                                check = false;
                            } else {
                                check = true;
                            }
                            if (check) {
                                try {
                                    Locale locale = Locale.getDefault();
                                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                                    conn.setConnectTimeout(5000);
                                    conn.setReadTimeout(5000);
                                    conn.addRequestProperty("Accept-Language", locale.toLanguageTag() + "," + locale.getLanguage() + ";q=0.8");
                                    conn.addRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0");
                                    conn.setInstanceFollowRedirects(false);
                                    connCount++;
                                    int code = conn.getResponseCode();
                                    if (code == 200) {
                                        contentSet.add(host);
                                        int length = conn.getContentLength();
                                        String type = conn.getContentType();
                                        if (type != null && length < 1048576) {
                                            StringTokenizer tokenizer = new StringTokenizer(type, ";");
                                            if (tokenizer.hasMoreTokens()) {
                                                type = tokenizer.nextToken();
                                            }
                                            type = type.trim();
                                            if (type.startsWith("text/")) {
                                                // Do nothing.
                                            } else if (type.startsWith("image/")) {
                                                // Do nothing.
                                            } else if (type.startsWith("message/")) {
                                                // Do nothing.
                                            } else if (type.startsWith("font/")) {
                                                // Do nothing.
                                            } else if (type.startsWith("application/")) {
                                                String filename = null;
                                                String disposition = conn.getHeaderField("Content-Disposition");
                                                if (disposition != null) {
                                                    tokenizer = new StringTokenizer(disposition, ";");
                                                    while (tokenizer.hasMoreTokens()) {
                                                        String token = tokenizer.nextToken().trim();
                                                        if (token.startsWith("filename=")) {
                                                            try {
                                                                Server.logTrace("Content-Disposition: " + disposition);
                                                                int begin = token.indexOf('=') + 1;
                                                                filename = token.substring(begin).trim();
                                                                if (filename.charAt(0) == '\'') {
                                                                    int end = filename.indexOf('\'', 1);
                                                                    if (end > 0) {
                                                                        filename = filename.substring(1, end).trim();
                                                                    }
                                                                } else if (filename.charAt(0) == '"') {
                                                                    int end = filename.indexOf('"', 1);
                                                                    if (end > 0) {
                                                                        filename = filename.substring(1, end).trim();
                                                                    }
                                                                }
                                                                Server.logTrace("Filename: " + filename);
                                                                break;
                                                            } catch (Exception ex) {
                                                                Server.logError(ex);
                                                            }
                                                        }
                                                    }
                                                    if (filename == null) {
                                                        Server.logError("cannot get filename at disposition: " + disposition);
                                                    }
                                                }
                                                if (filename == null) {
                                                    filename = url.getFile();
                                                    if (filename == null) {
                                                        Server.logError("cannot get filename at URL: " + url);
                                                    }
                                                }
                                                if (filename != null) {
                                                    int index = filename.lastIndexOf('.') + 1;
                                                    String extension = filename.substring(index);
                                                    extension = extension.toLowerCase();
                                                    if (extension.equals("doc")) {
                                                        boolean executable;
                                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                        try (InputStream inputStream = conn.getInputStream()) {
                                                            executable = Core.isAutoExecutableOfficeFile(
                                                                    extension, inputStream, messageDigest
                                                            );
                                                        }
                                                        if (executable) {
                                                            String md5 = Core.md5Hex(messageDigest.digest());
                                                            String signature = md5 + "." + length + "." + extension;
                                                            Server.logInfo("executable attachment found: " + signature);
                                                            contentSet.add(signature);
                                                            contentSet.add("MALWARE=SPFBL.Document.AutoOpen.doc");
                                                        }
                                                    } else if (extension.equals("xls")) {
                                                        boolean executable;
                                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                        try (InputStream inputStream = conn.getInputStream()) {
                                                            executable = Core.isAutoExecutableOfficeFile(
                                                                    extension, inputStream, messageDigest
                                                            );
                                                        }
                                                        if (executable) {
                                                            String md5 = Core.md5Hex(messageDigest.digest());
                                                            String signature = md5 + "." + length + "." + extension;
                                                            Server.logInfo("executable attachment found: " + signature);
                                                            contentSet.add(signature);
                                                            contentSet.add("MALWARE=SPFBL.Document.AutoOpen.xls");
                                                        }
                                                    } else if (Core.EXECUTABLE_SET.contains(extension)) {
                                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                        try (InputStream inputStream = conn.getInputStream()) {
                                                            while ((code = inputStream.read()) != -1) {
                                                                messageDigest.update((byte) code);
                                                            }
                                                        }
                                                        String md5 = Core.md5Hex(messageDigest.digest());
                                                        String signatureFile = md5 + "." + length + "." + extension;
                                                        Server.logInfo("executable download found: " + signatureFile);
                                                        contentSet.add(signatureFile);
                                                        contentSet.add(signatureURL);
                                                        if (Block.containsExact(signatureFile)) {
                                                            if (Block.addExact(signatureURL)) {
                                                                Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                            }
                                                        }
                                                    } else if (Core.COMPACTED_SET.contains(extension)) {
                                                        Server.logTrace("PASSWORD SET " + passwordSet);
                                                        // TODO: implement decompression algorithm.
                                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                        try (InputStream inputStream = conn.getInputStream()) {
                                                            while ((code = inputStream.read()) != -1) {
                                                                messageDigest.update((byte) code);
                                                            }
                                                        }
                                                        String md5 = Core.md5Hex(messageDigest.digest());
                                                        String signatureFile = md5 + "." + length + "." + extension;
                                                        Server.logInfo("compacted download found: " + signatureFile);
                                                        contentSet.add(signatureFile);
                                                        contentSet.add(signatureURL);
                                                        if (Block.containsExact(signatureFile)) {
                                                            if (Block.addExact(signatureURL)) {
                                                                Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                Server.logError("HTTP content type not reconized: " + type);
                                            }
                                        }
                                    } else if (code == HttpURLConnection.HTTP_MOVED_TEMP
                                            || code == HttpURLConnection.HTTP_MOVED_PERM
                                            || code == HttpURLConnection.HTTP_SEE_OTHER) {
                                        String location = conn.getHeaderField("Location");
                                        if (location == null) {
                                            contentSet.add(host);
                                        } else {
                                            try {
                                                location = URLDecoder.decode(location, "UTF-8");
                                                if (location.contains(":")) {
                                                    url = new URL(location);
                                                } else {
                                                    url = new URL(url, location);
                                                    location = url.toString();
                                                }
                                                if (url.getProtocol().equals("mailto")) {
                                                    String email = url.getPath();
                                                    if (isValidEmail(email)) {
                                                        contentSet.add(email.toLowerCase());
                                                    } else {
                                                        contentSet.add(host);
                                                    }
                                                } else {
                                                    String signatureLocation = Core.getSignatureURL(location);
                                                    host = url.getHost().toLowerCase();
                                                    if (Block.containsSignatureBlockURL(signatureLocation)) {
                                                        contentSet.add(signatureLocation);
                                                        if (Block.addExact(signatureURL)) {
                                                            Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureLocation + "'.");
                                                            contentSet.add(signatureURL);
                                                        }
                                                    } else if (Core.SHORTENER_SET.contains(host)) {
                                                        contentSet.add(signatureLocation);
                                                        if (!trusted) {
                                                            contentSet.add("MALWARE=SPFBL.Shortener.evasion");
                                                        }
                                                    } else {
                                                        urlSet.add(location);
                                                    }
                                                }
                                            } catch (MalformedURLException | IllegalArgumentException ex) {
                                                contentSet.add(host);
                                                Server.logWarning("malformed redirection URL " + location);
                                            } catch (Exception ex) {
                                                contentSet.add(host);
                                                Server.logError(ex);
                                            }
                                        }
                                    } else {
                                        contentSet.add(host);
                                    }
                                } catch (NoRouteToHostException ex) {
                                    contentSet.add(host);
                                } catch (UnknownHostException ex) {
                                    contentSet.add(host);
                                } catch (ConnectException ex) {
                                    contentSet.add(host);
                                } catch (SocketException ex) {
                                    contentSet.add(host);
                                } catch (SocketTimeoutException ex) {
                                    contentSet.add(host);
                                } catch (SSLHandshakeException ex) {
                                    contentSet.add(host);
                                } catch (MalformedURLException ex) {
                                    contentSet.add(host);
                                } catch (SSLException ex) {
                                    contentSet.add(host);
                                } catch (Exception ex) {
                                    Server.logError(ex);
                                }
                            }
                        }
                    } catch (MalformedURLException ex) {
                        Server.logError("malformed URL " + link);
                    }
                }
                return contentSet;
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Boolean processContent(
            long time,
            User.Query query,
            Message message,
            TreeSet<String> processedSet
    ) {
        try {
            if (query == null) {
                return null;
            } else if (message == null) {
                return null;
            } else if (message.getSize() == 0) {
                return null;
            } else if (query.hasLinkMap()) {
                return null;
            } else {
                ArrayList<Part> partList = extractPartList(message);
                if (partList == null) {
                    return null;
                } else {
                    String originalRecipient = null;
                    String deliveryStatus = "";
                    boolean bounce = false;
                    boolean abuse = false;
                    boolean trusted = query.isWhiteKey();
                    TreeSet<String> passwordSet = new TreeSet<>();
                    passwordSet.add("infected");
                    TreeSet<String> contentSet = new TreeSet<>();
                    TreeSet<String> urlSet = new TreeSet<>();
                    while (!partList.isEmpty()) {
                        Part part = partList.remove(0);
                        String filename = extractFilename(part);
                        String[] contentType = extractContentType(part);
                        String type = contentType[0];
                        String charset = contentType[1];
                        if (type.equals("text/plain") || type.equals("text")) {
                            try {
                                String text = null;
                                Object content = part.getContent();
                                if (content instanceof String) {
                                    text = (String) content;
                                } else if (content instanceof InputStream) {
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                    InputStream in = (InputStream) content;
                                    int nread;
                                    while ((nread = in.read()) >= 0) {
                                        baos.write(nread);
                                    }
                                    text = baos.toString(charset);
                                } else {
                                    throw new Exception("Content type not reconized: " + type + " " + content.getClass());
                                }
                                if (!query.hasBody()) {
                                    query.setBody(text.getBytes("UTF-8"), "UTF-8");
                                }
                                for (String token : text.split("[\\s\\t\\r\\n]+")) {
                                    passwordSet.add(token);
                                }
                                Matcher matcher = LINK_PATTERN.createMatcher(text);
                                while (matcher.find()) {
                                    String link = matcher.group();
                                    if (isValidEmail(link)) {
                                        contentSet.add(link.toLowerCase());
                                    } else if (link.startsWith("http://") || link.startsWith("https://")) {
                                        urlSet.add(link);
                                    } else {
                                        urlSet.add("http://" + link);
                                    }
                                }
                                LINK_PATTERN.offerMatcher(matcher);
                                if (query.isSenderMailerDeamon()) {
                                    String[] result = processBounce(
                                            query.getFrom(), text
                                    );
                                    if (result != null) {
                                        deliveryStatus = result[0];
                                        originalRecipient = result[1];
                                    }
                                }
                            } catch (UnsupportedEncodingException ex) {
                                Server.logError("unsupported encoding " + part.getContentType());
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        } else if (type.equals("text/html")) {
                            try {
                                String text;
                                Object content = part.getContent();
                                if (content instanceof String) {
                                    text = (String) content;
                                } else if (content instanceof SharedByteArrayInputStream) {
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                    SharedByteArrayInputStream in = (SharedByteArrayInputStream) content;
                                    int nread;
                                    while ((nread = in.read()) >= 0) {
                                        baos.write(nread);
                                    }
                                    text = baos.toString(charset);
                                } else {
                                    throw new Exception("class not reconized " + content.getClass());
                                }
                                Document document = Jsoup.parse(text);
                                Elements scriptElements = document.getElementsByTag("script");
                                if (!scriptElements.isEmpty()) {
                                    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                    messageDigest.update(text.getBytes());
                                    String md5 = Core.md5Hex(messageDigest.digest());
                                    String signature = md5 + "." + text.length() + ".html";
                                    Server.logInfo("executable attachment found: " + signature);
                                    contentSet.add(signature);
                                }
                                Element body = document.body();
                                if (body != null) {
                                    text = body.text();
                                    if (query.isSenderMailerDeamon()) {
                                        String[] result = processBounce(
                                                query.getFrom(), text
                                        );
                                        if (result != null) {
                                            deliveryStatus = result[0];
                                            originalRecipient = result[1];
                                        }
                                    }
                                    Elements imgElements = body.getElementsByTag("img");
                                    if (!trusted && !imgElements.isEmpty() && text.isEmpty()) {
                                        contentSet.add("MALWARE=SPFBL.HTML.body.img");
                                    }
                                    Elements aElements = body.getElementsByTag("a");
                                    for (int index = 0; index < aElements.size(); index++) {
                                        Element element = aElements.get(index);
                                        String href = element.attr("href");
                                        if (href.matches("^(mailto|https?):.+")) {
                                            urlSet.add(href);
                                        }
                                    }
                                }
                                if (!query.hasBody()) {
                                    query.setBody(text.getBytes("UTF-8"), "UTF-8");
                                }
                                for (String token : text.split("[\\s\\t\\r\\n]+")) {
                                    passwordSet.add(token);
                                }
                                Matcher matcher = LINK_PATTERN.createMatcher(text);
                                while (matcher.find()) {
                                    String link = matcher.group();
                                    if (isValidEmail(link)) {
                                        contentSet.add(link.toLowerCase());
                                    } else if (link.startsWith("http://") || link.startsWith("https://")) {
                                        urlSet.add(link);
                                    } else {
                                        urlSet.add("http://" + link);
                                    }
                                }
                                LINK_PATTERN.offerMatcher(matcher);
                            } catch (UnsupportedEncodingException ex) {
                                Server.logError("unsupported encoding " + part.getContentType());
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        } else if (type.startsWith("application/")) {
                            try {
                                int length = part.getSize();
                                if (filename != null && length < 2097152) {
                                    int index = filename.lastIndexOf('.') + 1;
                                    String extension = filename.substring(index);
                                    extension = extension.toLowerCase();
                                    if (extension.equals("pdf")) {
                                        PDDocument document;
                                        try (InputStream inputStream = part.getInputStream()) {
                                            document = PDDocument.load(inputStream);
                                            document = document.isEncrypted() ? null : document;
                                        } catch (InvalidPasswordException ex) {
                                            document = null;
                                        }
                                        if (document == null) {
                                            // Encrypted PDF.
                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                            try (InputStream inputStream = part.getInputStream()) {
                                                int code;
                                                while ((code = inputStream.read()) != -1) {
                                                    messageDigest.update((byte) code);
                                                }
                                            }
                                            String md5 = Core.md5Hex(messageDigest.digest());
                                            String signature = md5 + "." + length + "." + extension;
                                            Server.logInfo("potencial executable attachment found: " + signature);
                                            contentSet.add(signature);
                                        } else {
                                            try {
                                                PDPage pdfpage = document.getPage(0);
                                                List<PDAnnotation> annotations = pdfpage.getAnnotations();
                                                for (int j = 0; j < annotations.size(); j++) {
                                                    PDAnnotation annot = annotations.get(j);
                                                    if (annot instanceof PDAnnotationLink) {
                                                        PDAnnotationLink link = (PDAnnotationLink) annot;
                                                        PDAction action = link.getAction();
                                                        if (action instanceof PDActionURI) {
                                                            PDActionURI uri = (PDActionURI) action;
                                                            urlSet.add(uri.getURI());
                                                        }
                                                    }
                                                }
                                                if (query.isTextBodyEmpty()) {
                                                    PDFTextStripper tStripper = new PDFTextStripper();
                                                    tStripper.setStartPage(1);
                                                    tStripper.setEndPage(3);
                                                    String text = tStripper.getText(document);
                                                    query.setBody(text.getBytes("UTF-8"), "UTF-8");
                                                }
                                            } finally {
                                                document.close();
                                            }
                                        }
                                    } else if (extension.equals("doc")) {
                                        boolean executable;
                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                        try (InputStream inputStream = part.getInputStream()) {
                                            executable = Core.isAutoExecutableOfficeFile(
                                                    extension, inputStream, messageDigest
                                            );
                                        }
                                        if (executable) {
                                            String md5 = Core.md5Hex(messageDigest.digest());
                                            String signature = md5 + "." + length + "." + extension;
                                            Server.logInfo("executable attachment found: " + signature);
                                            contentSet.add(signature);
                                            contentSet.add("MALWARE=SPFBL.Document.AutoOpen.doc");
                                        }
                                    } else if (extension.equals("xls")) {
                                        boolean executable;
                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                        try (InputStream inputStream = part.getInputStream()) {
                                            executable = Core.isAutoExecutableOfficeFile(
                                                    extension, inputStream, messageDigest
                                            );
                                        }
                                        if (executable) {
                                            String md5 = Core.md5Hex(messageDigest.digest());
                                            String signature = md5 + "." + length + "." + extension;
                                            Server.logInfo("executable attachment found: " + signature);
                                            contentSet.add(signature);
                                            contentSet.add("MALWARE=SPFBL.Document.AutoOpen.xls");
                                        }
                                    } else if (Core.EXECUTABLE_SET.contains(extension)) {
                                        contentSet.add("MALWARE=SPFBL.Executable." + extension);
                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                        try (InputStream inputStream = part.getInputStream()) {
                                            int code;
                                            while ((code = inputStream.read()) != -1) {
                                                messageDigest.update((byte) code);
                                            }
                                        }
                                        String md5 = Core.md5Hex(messageDigest.digest());
                                        String signature = md5 + "." + length + "." + extension;
                                        Server.logInfo("executable attachment found: " + signature);
                                        contentSet.add(signature);
                                    } else if (Core.COMPACTED_SET.contains(extension)) {
                                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                        try (InputStream inputStream = part.getInputStream()) {
                                            int code;
                                            while ((code = inputStream.read()) != -1) {
                                                outputStream.write(code);
                                                messageDigest.update((byte) code);
                                            }
                                        }
                                        Server.logTrace("PASSWORD SET " + passwordSet);
                                        boolean compacted = true;
                                        if (extension.equals("zip")) {
                                            try {
                                                byte[] byteArray = outputStream.toByteArray();
                                                ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
                                                try {
                                                    ZipInputStream zis = new ZipInputStream(inputStream);
                                                    ZipEntry entry;
                                                    while ((entry = zis.getNextEntry()) != null) {
                                                        String filename2 = entry.getName();
                                                        int index2 = filename2.lastIndexOf('.') + 1;
                                                        String extension2 = filename2.substring(index2);
                                                        extension2 = extension2.toLowerCase();
                                                        if (Core.EXECUTABLE_SET.contains(extension2)) {
                                                            long length2 = entry.getSize();
                                                            MessageDigest messageDigest2 = MessageDigest.getInstance("MD5");
                                                            int code;
                                                            while ((code = zis.read()) != -1) {
                                                                messageDigest2.update((byte) code);
                                                            }
                                                            String md5 = Core.md5Hex(messageDigest2.digest());
                                                            String signature = md5 + "." + length2 + "." + extension2;
                                                            Server.logInfo("compacted executable found: " + signature);
                                                            contentSet.add(signature);
                                                        }
                                                    }
                                                    compacted = false;
                                                } catch (ZipException ex) {
                                                    // TODO: implement decrypt algorithm.
                                                    if (!query.isRecipientAbuse()) {
                                                        contentSet.add("MALWARE=SPFBL.Encrypted.zip");
                                                    }
                                                }
                                            } catch (Exception ex) {
                                                Server.logError(ex);
                                            }
                                        } else if (extension.equals("rar")) {
                                            try {
                                                byte[] byteArray = outputStream.toByteArray();
                                                ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
//                                                try {
                                                    Archive archive = new Archive(inputStream);
                                                    FileHeader fileHeader;
                                                    while ((fileHeader = archive.nextFileHeader()) != null) {
                                                        String filename2 = fileHeader.getFileName();
                                                        int index2 = filename2.lastIndexOf('.') + 1;
                                                        String extension2 = filename2.substring(index2);
                                                        extension2 = extension2.toLowerCase();
                                                        if (Core.EXECUTABLE_SET.contains(extension2)) {
                                                            long length2 = fileHeader.getUnpSize();
                                                            MessageDigest messageDigest2 = MessageDigest.getInstance("MD5");
                                                            try (InputStream is = archive.getInputStream(fileHeader)) {
                                                                int code;
                                                                while ((code = is.read()) != -1) {
                                                                    messageDigest2.update((byte) code);
                                                                }
                                                            }
                                                            String md5 = Core.md5Hex(messageDigest2.digest());
                                                            String signature = md5 + "." + length2 + "." + extension2;
                                                            Server.logInfo("compacted executable found: " + signature);
                                                            contentSet.add(signature);
                                                        }
                                                    }
                                                    compacted = false;
//                                                } catch (RarException ex) {
//                                                    // TODO: implement decrypt algorithm.
//                                                    if (!query.isRecipientAbuse()) {
//                                                        contentSet.add("MALWARE=SPFBL.Encrypted.rar");
//                                                    }
//                                                }
                                            } catch (Exception ex) {
                                                Server.logError(ex);
                                            }
                                        }
                                        if (compacted) {
                                            String md5 = Core.md5Hex(messageDigest.digest());
                                            String signature = md5 + "." + length + "." + extension;
                                            Server.logInfo("compacted attachment found: " + signature);
                                            contentSet.add(signature);
                                        }
                                    } else if (extension.equals("eml")) {
                                        if (type.equals("application/octet-stream") && query.isRecipientAbuse()) {
                                            part.setHeader("Content-Type", "message/rfc822");
                                            partList.add(part);
                                        }
                                    }
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        } else if (type.startsWith("image/")) {
                            // Do nothing.
                        } else if (type.startsWith("text/")) {
                            // Do nothing.
                        } else if (type.equals("message/rfc822") || type.equals("message/global") || type.equals("message/rfc822-headers") || type.equals("text/rfc822-headers")) {
                            try {
                                MimeMessage forwarded;
                                if (part.getContent() instanceof MimeMessage) {
                                    forwarded = (MimeMessage) part.getContent();
                                } else {
                                    forwarded = new SimpleMimeMessage(null, part.getInputStream());
                                }
                                fixContentMetadata(forwarded);
                                if (query.isRecipientAbuse()) {
                                    String complainer = query.getTrueSender();
                                    User user;
                                    if (processComplainTicket(complainer, forwarded)) {
                                        abuse = true;
                                    } else if ((user = User.get(complainer)) == null) {
                                        Server.logTrace("abuse report user not found.");
                                        boolean sameDomain = false;
                                        String receivedFrom = extractAddress(forwarded.getHeader("From", null), true);
                                        if (receivedFrom == null) {
                                            receivedFrom = extractAddress(forwarded.getHeader("Return-Path", null), false);
                                        }
                                        if (receivedFrom != null) {
                                            int index = receivedFrom.indexOf('@');
                                            receivedFrom = receivedFrom.substring(index);
                                            Address[] recipients;
                                            try {
                                                recipients = forwarded.getAllRecipients();
                                            } catch (AddressException ex) {
                                                recipients = null;
                                            } catch (Exception ex) {
                                                recipients = null;
                                                Server.logError(ex);
                                            }
                                            if (recipients != null) {
                                                for (Address address : recipients) {
                                                    if (address instanceof InternetAddress) {
                                                        InternetAddress internetAddress = (InternetAddress) address;
                                                        String recipient = internetAddress.getAddress().toLowerCase();
                                                        if (recipient.endsWith(receivedFrom)) {
                                                            sameDomain = true;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        abuse = sameDomain;
                                    } else if (reportAbuse(user, forwarded)) {
                                        Server.logInfo("abuse reported by: " + user.getEmail());
                                        query.whiteKey(time);
                                        abuse = true;
                                    } else if (isBounceMessage(forwarded)) {
                                        // Consider reported.
                                        abuse = true;
                                    } else {
                                        Server.logTrace("abuse report failed.");
                                    }
                                }
                                String listUnsubscribe = forwarded.getHeader("List-Unsubscribe", null);
                                if (listUnsubscribe != null) {
                                    Matcher matcher = UNSUBSCRIBE_PATTERN.createMatcher(listUnsubscribe);
                                    if (matcher.find()) {
                                        String hostname = matcher.group(2);
                                        if (Core.isMyHostname(hostname) || Core.isMyHostname("localhost")) {
                                            String ticket = matcher.group(8);
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
                                                if (System.currentTimeMillis() - date < 1814400000L) {
                                                    String value = Core.decodeHuffman(byteArray, 8);
                                                    StringTokenizer tokenizer2 = new StringTokenizer(value, " ");
                                                    String operator = tokenizer2.nextToken();
                                                    if (operator.equals("unsubscribe") && tokenizer2.hasMoreTokens()) {
                                                        originalRecipient = tokenizer2.nextToken();
                                                        Server.logInfo("list unsubscribe: " + originalRecipient);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    UNSUBSCRIBE_PATTERN.offerMatcher(matcher);
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        } else if (type.equals("message/delivery-status")) {
                            try {
                                DeliveryStatus dStatus = new DeliveryStatus(part.getInputStream());
                                int count = dStatus.getRecipientDSNCount();
                                for (int index = 0; index < count; index++) {
                                    InternetHeaders headers = dStatus.getRecipientDSN(index);
                                    String recipient = headers.getHeader("Original-Recipient", null);
                                    if (recipient == null) {
                                        recipient = headers.getHeader("Final-Recipient", null);
                                    }
                                    String status = headers.getHeader("Status", null);
                                    if (status == null) {
                                        Server.logError("delivery status not reconized: " + dStatus);
                                    } else if (recipient == null || status.length() == 0) {
                                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                        dStatus.writeTo(baos);
                                        Server.logError("delivery status not reconized: " + baos);
                                    } else if (originalRecipient == null && query.isSigned(recipient)) {
                                        int index2 = recipient.indexOf(';') + 1;
                                        originalRecipient = recipient.substring(index2);
                                        deliveryStatus = status;
                                    }
                                    String diagnostic = headers.getHeader("Diagnostic-Code", null);
                                    if (diagnostic != null) {
                                        diagnostic = diagnostic.toLowerCase();
                                        Matcher matcher = STATUS_PATTERN.createMatcher(diagnostic);
                                        if (matcher.find()) {
                                            deliveryStatus = matcher.group(0);
                                        } else if (diagnostic.contains("recipient not found")) {
                                            deliveryStatus = "5.1.1";
                                        }
                                        STATUS_PATTERN.offerMatcher(matcher);
                                    }
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        } else if (type.equals("message/feedback-report")) {
                            try {
                                DataSource source = part.getDataHandler().getDataSource();
                                MimeMultipart feedback = new MimeMultipart(source);
                                type = feedback.getContentType();
                                Server.logError("attachment content type not reconized: " + type + "\n" + feedback.getPreamble());
                            } catch (javax.mail.internet.ParseException ex) {
    //                            Server.logError("mime part not reconized: " + type + " " + part.getClass());
                            } catch (MessagingException ex) {
                                Server.logError(ex);
                            }
                        } else if (type.equals("message/disposition-notification")) {
                            try {
                                DataSource source = part.getDataHandler().getDataSource();
                                InputStream stream = source.getInputStream();
                                DispositionNotification notification = new DispositionNotification(stream);
                                Server.logError("attachment content type not reconized: " + type + "\n" + notification);
                            } catch (javax.mail.internet.ParseException ex) {
    //                            Server.logError("mime part not reconized: " + type + " " + part.getClass());
                            } catch (MessagingException ex) {
                                Server.logError(ex);
                            }
                        } else if (type.equals("message/disposition-notification")) {
                            // Do nothing.
                        } else if (query.hasClientQueueID()) {
                            Server.logError("attachment content type not reconized in message " + query.getClientQueueID() + ": " + type + "\n" + part.getContent());
                        } else {
                            Server.logError("attachment content type not reconized: " + type + "\n" + part.getContent());
                        }
                    }
                    if (deliveryStatus.length() > 0) {
                        if (originalRecipient == null) {
                            Server.logError("original recipient not found at delivery status " + deliveryStatus);
                        } else if (deliveryStatus.startsWith("4.")) {
                            Server.logInfo("delivery temporary error: " + deliveryStatus + " " + originalRecipient);
                            bounce = true;
                        } else if (deliveryStatus.equals("5.0.0")) {
                            if (Defer.defer(">" + originalRecipient, Core.getDeferTimeHOLD())) {
                                Server.logInfo("delivery refused: " + deliveryStatus + " " + originalRecipient);
                            } else {
                                Server.logInfo("delivery not welcome: " + deliveryStatus + " " + originalRecipient);
                                NoReply.addSafe(originalRecipient);
                            }
                            bounce = true;
                        } else if (deliveryStatus.equals("5.1.1") || deliveryStatus.equals("5.1.10") || deliveryStatus.equals("5.5.1")) {
                            Server.logInfo("delivery inexistent: " + deliveryStatus + " " + originalRecipient);
                            Trap.addInexistentForever(originalRecipient);
                            bounce = true;
                        } else if (deliveryStatus.equals("5.2.2")) {
                            Server.logInfo("delivery mailbox full: " + deliveryStatus + " " + originalRecipient);
                            if (!Defer.defer(">" + originalRecipient, Core.getDeferTimeHOLD())) {
                                NoReply.addSafe(originalRecipient);
                            }
                            bounce = true;
                        } else if (deliveryStatus.equals("5.4.14")) {
                            Server.logInfo("delivery mail loop: " + deliveryStatus + " " + originalRecipient);
                            if (!Defer.defer(">" + originalRecipient, Core.getDeferTimeHOLD())) {
                                NoReply.addSafe(originalRecipient);
                            }
                            bounce = true;
                        } else if (deliveryStatus.equals("5.7.1")) {
                            Server.logInfo("delivery not authorized: " + deliveryStatus + " " + originalRecipient);
                            NoReply.addSafe(originalRecipient);
                            bounce = true;
                        } else if (deliveryStatus.equals("5.4.1")) {
                            Server.logInfo("relay not authorized: " + deliveryStatus + " " + originalRecipient);
                            NoReply.addSafe(originalRecipient);
                            bounce = true;
                        } else {
                            Server.logInfo("delivery not defined: " + deliveryStatus + " " + originalRecipient);
                            bounce = true;
                        }
                    }
                    if (!abuse && query.isRecipientAbuse()) {
                        String[] messageIDs = message.getHeader("In-Reply-To");
                        if (messageIDs != null) {
                            String messageID = messageIDs[0];
                            int index = messageID.indexOf('<');
                            if (index >= 0) {
                                messageID = messageID.substring(index + 1);
                                index = messageID.indexOf('>');
                                if (index > 0) {
                                    messageID = messageID.substring(0, index);
                                }
                            }
                            User user = query.getUser();
                            Entry<Long,User.Query> entry = user.getByMessageID(messageID);
                            if (entry != null) {
                                long originalTime = entry.getKey();
                                User.Query originalQuery = entry.getValue();
                                if (originalQuery.isWhiteKey()) {
                                    originalQuery.setSpam(originalTime);
                                } else {
                                    originalQuery.blockKey(originalTime, "COMPLAIN");
                                }
                                User.storeDB2(originalTime, originalQuery);
                                Abuse.offer(originalTime, originalQuery);
                                Server.logInfo("abuse reported by: " + query.getTrueSender());
                                abuse = true;
                            }
                        }
                    }
                    String messageID = Long.toString(time, 32);
                    if (abuse) {
                        contentSet.clear();
                        if (query.isWhiteKey()) {
                            query.setResult("WHITE");
                        } else {
                            query.setResult("ACCEPT");
                        }
                        Server.logInfo("abuse report ID " + messageID + " was discarded.");
                        return false;
                    } else if (bounce) {
                        contentSet.clear();
                        query.setResult("ACCEPT");
                        if (query.isRecipientAdmin()) {
                            Server.logInfo("delivery status ID " + messageID + " was discarded.");
                            return false;
                        } else {
                            Server.logInfo("delivery status ID " + messageID + " was forwarded.");
                            return true;
                        }
                    }
                    int connCount = 0;
                    while (!urlSet.isEmpty() && processedSet.size() < 256) {
                        String link = urlSet.pollFirst();
                        try {
                            // Decode Google redirection.
                            if (link.startsWith("https://www.google.com/url?q=http")) {
                                link = link.substring(29, link.length());
                                link = URLDecoder.decode(link, "UTF-8");
                            } else if (link.startsWith("http://www.google.com/url?q=http")) {
                                link = link.substring(28, link.length());
                                link = URLDecoder.decode(link, "UTF-8");
                            }
                            // Process link.
                            URL url = new URL(link);
                            if (url.getProtocol().equals("mailto")) {
                                String email = url.getPath();
                                if (isValidEmail(email)) {
                                    contentSet.add(email.toLowerCase());
                                }
                            } else if (processedSet.add(link)) {
                                boolean check;
                                String signatureURL = Core.getSignatureURL(link);
                                String host = url.getHost().toLowerCase();
                                if (signatureURL == null) {
                                    check = false;
                                } else if (Block.containsExact(signatureURL)) {
                                    contentSet.add(signatureURL);
                                    check = false;
                                } else if (Core.SHORTENER_SET.contains(host)) {
                                    contentSet.add(signatureURL);
                                    check = true;
                                } else if (connCount > 16) {
                                    contentSet.add(host);
                                    check = false;
                                } else if (Ignore.containsFQDN(host)) {
                                    contentSet.add(host);
                                    check = false;
                                } else if (Provider.containsFQDN(host)) {
                                    contentSet.add(host);
                                    check = false;
                                } else {
                                    check = true;
                                }
                                if (check) {
                                    try {
                                        Locale locale = query.getLocale();
                                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                                        conn.setConnectTimeout(5000);
                                        conn.setReadTimeout(5000);
                                        conn.addRequestProperty("Accept-Language", locale.toLanguageTag() + "," + locale.getLanguage() + ";q=0.8");
                                        conn.addRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0");
                                        conn.setInstanceFollowRedirects(false);
                                        connCount++;
                                        int code = conn.getResponseCode();
                                        if (code == 200) {
                                            contentSet.add(host);
                                            int length = conn.getContentLength();
                                            String type = conn.getContentType();
                                            if (type != null && length < 1048576) {
                                                StringTokenizer tokenizer = new StringTokenizer(type, ";");
                                                if (tokenizer.hasMoreTokens()) {
                                                    type = tokenizer.nextToken();
                                                }
                                                type = type.trim();
                                                if (type.startsWith("text/")) {
                                                    // Do nothing.
                                                } else if (type.startsWith("image/")) {
                                                    // Do nothing.
                                                } else if (type.startsWith("message/")) {
                                                    // Do nothing.
                                                } else if (type.startsWith("font/")) {
                                                    // Do nothing.
                                                } else if (type.startsWith("application/")) {
                                                    String filename = null;
                                                    String disposition = conn.getHeaderField("Content-Disposition");
                                                    if (disposition != null) {
                                                        tokenizer = new StringTokenizer(disposition, ";");
                                                        while (tokenizer.hasMoreTokens()) {
                                                            String token = tokenizer.nextToken().trim();
                                                            if (token.startsWith("filename=")) {
                                                                try {
                                                                    Server.logTrace("Content-Disposition: " + disposition);
                                                                    int begin = token.indexOf('=') + 1;
                                                                    filename = token.substring(begin).trim();
                                                                    if (filename.charAt(0) == '\'') {
                                                                        int end = filename.indexOf('\'', 1);
                                                                        if (end > 0) {
                                                                            filename = filename.substring(1, end).trim();
                                                                        }
                                                                    } else if (filename.charAt(0) == '"') {
                                                                        int end = filename.indexOf('"', 1);
                                                                        if (end > 0) {
                                                                            filename = filename.substring(1, end).trim();
                                                                        }
                                                                    }
                                                                    Server.logTrace("Filename: " + filename);
                                                                    break;
                                                                } catch (Exception ex) {
                                                                    Server.logError(ex);
                                                                }
                                                            }
                                                        }
                                                        if (filename == null) {
                                                            Server.logError("cannot get filename at disposition: " + disposition);
                                                        }
                                                    }
                                                    if (filename == null) {
                                                        filename = url.getFile();
                                                        if (filename == null) {
                                                            Server.logError("cannot get filename at URL: " + url);
                                                        }
                                                    }
                                                    if (filename != null) {
                                                        int index = filename.lastIndexOf('.') + 1;
                                                        String extension = filename.substring(index);
                                                        extension = extension.toLowerCase();
                                                        if (extension.equals("doc")) {
                                                            boolean executable;
                                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                            try (InputStream inputStream = conn.getInputStream()) {
                                                                executable = Core.isAutoExecutableOfficeFile(
                                                                        extension, inputStream, messageDigest
                                                                );
                                                            }
                                                            if (executable) {
                                                                String md5 = Core.md5Hex(messageDigest.digest());
                                                                String signature = md5 + "." + length + "." + extension;
                                                                Server.logInfo("executable attachment found: " + signature);
                                                                contentSet.add(signature);
                                                                contentSet.add("MALWARE=SPFBL.Document.AutoOpen.doc");
                                                            }
                                                        } else if (extension.equals("xls")) {
                                                            boolean executable;
                                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                            try (InputStream inputStream = conn.getInputStream()) {
                                                                executable = Core.isAutoExecutableOfficeFile(
                                                                        extension, inputStream, messageDigest
                                                                );
                                                            }
                                                            if (executable) {
                                                                String md5 = Core.md5Hex(messageDigest.digest());
                                                                String signature = md5 + "." + length + "." + extension;
                                                                Server.logInfo("executable attachment found: " + signature);
                                                                contentSet.add(signature);
                                                                contentSet.add("MALWARE=SPFBL.Document.AutoOpen.xls");
                                                            }
                                                        } else if (Core.EXECUTABLE_SET.contains(extension)) {
                                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                            try (InputStream inputStream = conn.getInputStream()) {
                                                                while ((code = inputStream.read()) != -1) {
                                                                    messageDigest.update((byte) code);
                                                                }
                                                            }
                                                            String md5 = Core.md5Hex(messageDigest.digest());
                                                            String signatureFile = md5 + "." + length + "." + extension;
                                                            Server.logInfo("executable download found: " + signatureFile);
                                                            contentSet.add(signatureFile);
                                                            contentSet.add(signatureURL);
                                                            if (Block.containsExact(signatureFile)) {
                                                                if (Block.addExact(signatureURL)) {
                                                                    Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                                }
                                                            }
                                                        } else if (Core.COMPACTED_SET.contains(extension)) {
                                                            Server.logTrace("PASSWORD SET " + passwordSet);
                                                            // TODO: implement decompression algorithm.
                                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                            try (InputStream inputStream = conn.getInputStream()) {
                                                                while ((code = inputStream.read()) != -1) {
                                                                    messageDigest.update((byte) code);
                                                                }
                                                            }
                                                            String md5 = Core.md5Hex(messageDigest.digest());
                                                            String signatureFile = md5 + "." + length + "." + extension;
                                                            Server.logInfo("compacted download found: " + signatureFile);
                                                            contentSet.add(signatureFile);
                                                            contentSet.add(signatureURL);
                                                            if (Block.containsExact(signatureFile)) {
                                                                if (Block.addExact(signatureURL)) {
                                                                    Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    Server.logError("HTTP content type not reconized: " + type);
                                                }
                                            }
                                        } else if (
                                                code == HttpURLConnection.HTTP_MOVED_TEMP ||
                                                code == HttpURLConnection.HTTP_MOVED_PERM ||
                                                code == HttpURLConnection.HTTP_SEE_OTHER
                                                ) {
                                            String location = conn.getHeaderField("Location");
                                            if (location == null) {
                                                contentSet.add(host);
                                            } else {
                                                try {
                                                    location = URLDecoder.decode(location, "UTF-8");
                                                    if (location.contains(":")) {
                                                        url = new URL(location);
                                                    } else {
                                                        url = new URL(url, location);
                                                        location = url.toString();
                                                    }
                                                    if (url.getProtocol().equals("mailto")) {
                                                        String email = url.getPath();
                                                        if (isValidEmail(email)) {
                                                            contentSet.add(email.toLowerCase());
                                                        } else {
                                                            contentSet.add(host);
                                                        }
                                                    } else {
                                                        String signatureLocation = Core.getSignatureURL(location);
                                                        host = url.getHost().toLowerCase();
                                                        if (Block.containsSignatureBlockURL(signatureLocation)) {
                                                            contentSet.add(signatureLocation);
                                                            if (Block.addExact(signatureURL)) {
                                                                Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureLocation + "'.");
                                                                contentSet.add(signatureURL);
                                                            }
                                                        } else if (Core.SHORTENER_SET.contains(host)) {
                                                            contentSet.add(signatureLocation);
                                                            if (!trusted) {
                                                                contentSet.add("MALWARE=SPFBL.Shortener.evasion");
                                                            }
                                                        } else {
                                                            urlSet.add(location);
                                                        }
                                                    }
                                                } catch (MalformedURLException | IllegalArgumentException ex) {
                                                    contentSet.add(host);
                                                    Server.logWarning("malformed redirection URL " + location);
                                                } catch (Exception ex) {
                                                    contentSet.add(host);
                                                    Server.logError(ex);
                                                }
                                            }
                                        } else {
                                            contentSet.add(host);
                                        }
                                    } catch (NoRouteToHostException ex) {
                                        contentSet.add(host);
                                    } catch (UnknownHostException ex) {
                                        contentSet.add(host);
                                    } catch (ConnectException ex) {
                                        contentSet.add(host);
                                    } catch (SocketException ex) {
                                        contentSet.add(host);
                                    } catch (SocketTimeoutException ex) {
                                        contentSet.add(host);
                                    } catch (SSLHandshakeException ex) {
                                        contentSet.add(host);
                                    } catch (MalformedURLException ex) {
                                        contentSet.add(host);
                                    } catch (SSLException ex) {
                                        contentSet.add(host);
                                    } catch (Exception ex) {
                                        Server.logError(ex);
                                    }
                                }
                            }
                        } catch (MalformedURLException ex) {
                            Server.logError("malformed URL " + link);
                        }
                    }
                    query.setLinkSet(time, contentSet);
                    return null;
                }
            }
        } catch (com.sun.mail.util.DecodingException ex) {
            return null;
        } catch (javax.mail.internet.ParseException ex) {
            if (ex.getMessage().equals("Missing start boundary")) {
                return null;
            } else {
                Server.logError(ex);
                return null;
            }
        } catch (UnsupportedEncodingException ex) {
            Server.logError("#" + Long.toString(time, 32) + " " + ex.getMessage());
            return null;
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    private static final Flags DELETEDS = new Flags(Flags.Flag.DELETED);
    private static final Flags SEENS = new Flags(Flags.Flag.SEEN);
    private static final Flags FLAGGEDS = new Flags(Flags.Flag.FLAGGED);
    
    private static boolean isExpired(long timeKey) {
        return System.currentTimeMillis() - timeKey > 5 * Server.DAY_TIME;
    }
    
    private static String getMessageID(Message message) throws MessagingException {
        if (message == null) {
            return null;
        } else {
            String[] idArray = message.getHeader("Message-ID");
            return getMessageID(idArray);
        }
    }
    
    private static String getMessageID(String[] idArray) {
        if (idArray == null) {
            return null;
        } else {
            for (String messageID : idArray) {
                messageID = extractMessageID(messageID);
                if (messageID != null) {
                    return messageID;
                }
            }
            return null;
        }
    }
    
    private static Entry<Long,User.Query> getQueryEntry(User user, String[] idArray) {
        if (user == null) {
            return null;
        } else if (idArray == null) {
            return null;
        } else {
            for (String messageID : idArray) {
                messageID = extractMessageID(messageID);
                Long timeKey = user.getTimeByIdentification(messageID);
                if (timeKey != null) {
                    User.Query query = user.getQuery(timeKey);
                    return new AbstractMap.SimpleImmutableEntry<>(timeKey, query);
                }
            }
            return null;
        }
    }
    
    private static Entry<Long,User.Query> getQueryEntry(User user, Message message) {
        if (message == null) {
            return null;
        } else {
            try {
                String[] headerArray = message.getHeader("Received-SPFBL");
                Entry<Long,User.Query> entry = getQueryEntry(headerArray);
                if (entry == null) {
                    headerArray = message.getHeader("Message-ID");
                    entry = getQueryEntry(user, headerArray);
                }
                return entry;
            } catch (MessagingException ex) {
                return null;
            }
        }
    }
    
    public static Entry<Long,User.Query> getQueryEntry(String[] receivedArray) {
        if (receivedArray == null) {
            return null;
        } else {
            for (String receivedSPFBL : receivedArray) {
                try {
                    receivedSPFBL = receivedSPFBL.replaceAll("[\\s\\r\\n\\t]+", " ");
                    Matcher matcher = RECEIVED_PATTERN.createMatcher(receivedSPFBL);
                    if (matcher.find()) {
                        String ticket = matcher.group(8);
                        RECEIVED_PATTERN.offerMatcher(matcher);
                        byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                        if (byteArray.length > 8) {
                            long timeKey = byteArray[7] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[6] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[5] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[4] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[3] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[2] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[1] & 0xFF;
                            timeKey <<= 8;
                            timeKey += byteArray[0] & 0xFF;
                            if (System.currentTimeMillis() - timeKey < 1814400000L) {
                                String value = Core.decodeHuffman(byteArray, 8);
                                StringTokenizer tokenizer2 = new StringTokenizer(value, " ");
                                String operator = tokenizer2.nextToken();
                                if (operator.equals("spam")) {
                                    User user = null;
                                    while (tokenizer2.hasMoreTokens()) {
                                        String token = tokenizer2.nextToken();
                                        if (token.endsWith(":")) {
                                            int index = token.length() - 1;
                                            token = token.substring(0, index);
                                            user = User.get(token);
                                            break;
                                        }
                                    }
                                    if (user != null) {
                                        User.Query query = user.getQuery(timeKey);
                                        if (query != null) {
                                            return new AbstractMap.SimpleImmutableEntry<>(timeKey, query);
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        RECEIVED_PATTERN.offerMatcher(matcher);
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            return null;
        }
    }
    
    private static boolean offerAbuse(long timeKey, User.Query query) {
        if (Abuse.offer(timeKey, query)) {
            return true;
        } else {
            if (Block.tryToDominoBlockIP(query.getIP(), "ABUSE")) {
                Block.addSafe(query.getFQDN());
            }
            return false;
        }
    }
    
    private static void processExternal() {
        try {
            File imapFolder = new File("./external/");
            if (imapFolder.exists()) {
                for (File file : imapFolder.listFiles()) {
                    if (Core.isRunning()) {
                        Server.logInfo("processing external file '" + file.getName() + "'.");
                        Properties props = new Properties();
                        try (FileInputStream fis = new FileInputStream(file)) {
                            props.load(fis);
                        }
                        String recipient = props.getProperty("mail.imaps.user");
                        User user = User.get(recipient);
                        if (user == null) {
                            Server.logError("user not found for address '" + recipient + "'.");
                        } else {
                            String password = props.getProperty("mail.imaps.password");
                            String host = props.getProperty("mail.imaps.host");
                            String folder = props.getProperty("mail.imaps.folder");
                            Session session = Session.getDefaultInstance(props, null);
                            try (Store store = session.getStore("imaps")) {
                                store.connect(host, recipient, password);
                                Folder inbox = store.getFolder("Inbox");
                                Folder junk = store.getFolder(folder);
                                // Process Inbox.
//                                inbox.open(Folder.READ_WRITE);
//                                int count = inbox.getMessageCount();
//                                for (int index = 1; Core.isRunning() && index <= count; index++) {
//                                    try {
//                                        Message message = inbox.getMessage(index);
//                                        if (!message.isSet(SEEN)) {
//                                            Entry<Long,User.Query> entry = getQueryEntry(user, message);
//                                            Long timeKey;
//                                            Query query;
//                                            if (entry == null) {
//                                                entry = newQuery(user, recipient, message);
//                                                timeKey = entry == null ? null : entry.getKey();
//                                                query = entry == null ? null : entry.getValue();
//                                                String messageID = getMessageID(message);
//                                                user.putIdentification(messageID, timeKey);
//                                            } else {
//                                                timeKey = entry.getKey();
//                                                query = entry.getValue();
//                                            }
//                                            if (timeKey != null && query != null) {
//                                                String result = query.processFilter(
//                                                        timeKey, null, Action.FLAG
//                                                );
//                                                if (result == null) {
//                                                    boolean seen = message.isSet(SEEN);
//                                                    processContent(
//                                                            timeKey, query, message,
//                                                            new TreeSet<>()
//                                                    );
//                                                    if (!seen) {
//                                                        message.setFlag(SEEN, seen);
//                                                    }
//                                                    result = query.processFilter(
//                                                            timeKey, null, Action.FLAG
//                                                    );
//                                                }
//                                                System.out.println(query + " => " + result);
//                                            }
//                                        }
//                                    } catch (MessageRemovedException ex) {
//                                        // Do nothing.
//                                    }
//                                }
//                                inbox.close(true);
                                // Process Junk.
                                junk.open(Folder.READ_WRITE);
                                int count = junk.getMessageCount();
                                for (int index = 1; Core.isRunning() && index <= count; index++) {
                                    try {
                                        boolean spamFlag = false;
                                        boolean phishingFlag = false;
                                        Message message = junk.getMessage(index);
                                        Flags flags = message.getFlags();
                                        for (String flag : flags.getUserFlags()) {
                                            if (flag.equals("$Phishing")) {
                                                phishingFlag = true;
                                            } else if (flag.equals("$Spam")) {
                                                spamFlag = true;
                                            }
                                        }
                                        Entry<Long,User.Query> entry = getQueryEntry(user, message);
                                        Long timeKey;
                                        User.Query query;
                                        if (entry == null) {
                                            entry = newQuery(user, recipient, message);
                                            timeKey = entry == null ? Server.getNewUniqueTime() : entry.getKey();
                                            query = entry == null ? null : entry.getValue();
                                            String messageID = getMessageID(message);
                                            user.putIdentification(messageID, timeKey);
                                        } else {
                                            timeKey = entry.getKey();
                                            query = entry.getValue();
                                        }
                                        if (timeKey == null) {
                                            timeKey = Server.getNewUniqueTime();
                                        }
                                        if (query == null) {
                                            if (phishingFlag) {
                                                storeIncomingMessage(query, message);
                                                Abuse.offer(recipient, timeKey, message);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else if (spamFlag) {
                                                storeIncomingMessage(query, message);
                                                Abuse.offer(recipient, timeKey, message);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else if (isExpired(timeKey)) {
                                                storeIncomingMessage(query, message);
                                                Abuse.offer(recipient, timeKey, message);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else {
                                                junk.setFlags(index, index, SEENS, true);
                                            }
                                        } else if (phishingFlag) {
                                            query.banOrBlock(timeKey, "USER_PHISHING");
                                            query.setResultFilter("BLOCK", "USER_PHISHING");
                                            query.addHarmful(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (spamFlag) {
                                            query.blockKey(timeKey, "USER_SPAM");
                                            query.setResultFilter("BLOCK", "USER_SPAM");
                                            query.addUndesirable(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (query.isWhiteKey()) {
                                            Message[] messageArray = {message};
                                            junk.copyMessages(messageArray, inbox);
                                            junk.setFlags(index, index, DELETEDS, true);
                                            query.setResult("WHITE");
                                            query.setRecipientAdvised();
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isBanned()) {
                                            query.setResultFilter("BLOCK", "ORIGIN_BANNED;" + query.getBannedKey());
                                            query.addHarmful(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (query.isBlockKey()) {
                                            query.setResult("BLOCK");
                                            query.addUndesirable(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (query.isWhiteKeyByAdmin()) {
                                            query.whiteKey(timeKey);
                                            Message[] messageArray = {message};
                                            junk.copyMessages(messageArray, inbox);
                                            junk.setFlags(index, index, DELETEDS, true);
                                            query.setResultFilter("WHITE", "ORIGIN_WHITE_KEY_ADMIN");
                                            query.setRecipientAdvised();
                                            User.storeDB2(timeKey, query);
                                        } else if (query.isBlockKeyByAdmin()) {
                                            query.setResultFilter("BLOCK", "ORIGIN_BLOCK_KEY_ADMIN;" + query.getBlockKey());
                                            query.addUndesirable(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (isExpired(timeKey)) {
                                            query.setResultFilter("BLOCK", "HOLD_EXPIRED");
                                            query.blockKey(timeKey, "EXPIRED");
                                            query.addUndesirable(timeKey);
                                            storeIncomingMessage(query, message);
                                            User.storeDB2(timeKey, query);
                                            offerAbuse(timeKey, query);
                                            junk.setFlags(index, index, DELETEDS, true);
                                        } else if (!query.isResult("FLAG")) {
                                            Boolean deliver = processContent(
                                                    timeKey, query, message,
                                                    new TreeSet<>()
                                            );
                                            String result = query.processFilter(
                                                    timeKey, null, Action.FLAG
                                            );
                                            if (Objects.equals(deliver, true)) {
                                                query.whiteKey(timeKey);
                                                Message[] messageArray = {message};
                                                junk.copyMessages(messageArray, inbox);
                                                junk.setFlags(index, index, DELETEDS, true);
                                                query.setResult("WHITE");
                                                User.storeDB2(timeKey, query);
                                            } else if (Objects.equals(result, "WHITE")) {
                                                Message[] messageArray = {message};
                                                junk.copyMessages(messageArray, inbox);
                                                junk.setFlags(index, index, DELETEDS, true);
                                                query.setResult("WHITE");
                                                User.storeDB2(timeKey, query);
                                            } else if (Objects.equals(result, "BLOCK")) {
                                                query.setResult("BLOCK");
                                                query.addUndesirable(timeKey);
                                                storeIncomingMessage(query, message);
                                                User.storeDB2(timeKey, query);
                                                offerAbuse(timeKey, query);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else if (Objects.equals(result, "REJECT")) {
                                                query.setResult("REJECT");
                                                query.addUnacceptable();
                                                User.storeDB2(timeKey, query);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else if (Objects.equals(deliver, false)) {
                                                query.setResult("REJECT");
                                                query.addUndesirable(timeKey);
                                                storeIncomingMessage(query, message);
                                                User.storeDB2(timeKey, query);
                                                offerAbuse(timeKey, query);
                                                junk.setFlags(index, index, DELETEDS, true);
                                            } else {
                                                query.setResult("FLAG");
                                                junk.setFlags(index, index, SEENS, true);
                                                User.storeDB2(timeKey, query);
                                            }
                                        }
                                    } catch (MessageRemovedException ex) {
                                        // Do nothing.
                                    }
                                }
                                junk.close(true);
                            } catch (MailConnectException ex) {
                                Server.logError("Couldn't connect to IMAP server.");
                            } catch (FolderClosedException ex) {
                                Server.logError("IMAP folder closed by server.");
                            } catch (MessagingException ex) {
                                Throwable cause = ex.getCause();
                                String message;
                                if (cause == null) {
                                    message = ex.getMessage();
                                } else {
                                    message = cause.getMessage();
                                }
                                if (cause instanceof SocketTimeoutException) {
                                    Server.logError("IMAP socket timeout.");
                                } else if (cause instanceof ConnectionException) {
                                    Server.logError("IMAP socket timeout.");
                                } else {
                                    Server.logError(message);
                                    throw ex;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    public static TreeSet<String> getAbusingSet() {
        // TODO: service abuse control.
        return new TreeSet<>();
    }
    
    private static final Regex FORGED_FROM_PATTERN = new Regex("^"
            + "From:"
            + "\"("
            + "[0-9a-zA-Z_-][0-9a-zA-Z._+-]*"
            + "@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
            + "(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + ")\""
            + "@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
            + "(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + "$"
    );

    private static final Regex IN_REPLY_TO_PATTERN = new Regex("\\<"
            + "([0-9a-zA-Z_-]+={0,2})"
            + "@"
            + "(([a-z0-9_]|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9])"
            + "(\\.([a-z0-9_]|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9]))*)"
            + "\\>"
    );
        
    public static final int SIZE = 16777216;
    
    private class Connection extends Thread {
        
        private Socket SOCKET = null;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        private long TIME = 0;
        private boolean SUBMISSION = false;
        private String helo = null;

        public Connection(int id) {
            String name = "ESMTPS" + Core.formatCentena(id);
            Server.logInfo("creating " + name + "...");
            setName(name);
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(getName() + " thread allocation.");
        }
        
        private void process(Socket socket, long time, boolean submission) {
            SOCKET = socket;
            TIME = time;
            SUBMISSION = submission;
            SEMAPHORE.release();
        }
        
        @Override
        public void interrupt() {
            Server.logInfo("closing " + getName() + "...");
            SOCKET = null;
            SEMAPHORE.release();
        }
        
        private boolean drop() {
            if (TIME == 0) {
                return false;
            } else if (SOCKET == null) {
                return false;
            } else if (SOCKET.isClosed()) {
                return false;
            } else if ((System.currentTimeMillis() - TIME) < Server.MINUTE_TIME) {
                return false;
            } else {
                try {
                    SOCKET.close();
                    return true;
                } catch (IOException ex) {
                    return false;
                }
            }
        }

        public Socket getSocket() {
            try {
                SEMAPHORE.acquire();
                return SOCKET;
            } catch (InterruptedException ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        public void resetTime() {
            TIME = 0;
        }
        
        private void processSubmission() {
            SimpleImmutableEntry<Query,MimeMessage> entry;
            while ((entry = submissionList.poll()) != null) {
                Query query = entry.getKey();
                Server.logTrace("abuse submission " + query.getClientQueueID() + " digest started.");
                MimeMessage message = entry.getValue();
                long timeKey = Server.getNewUniqueTime();
                if (query.isWhiteKey()) {
                    query.setSpam(timeKey);
                } else {
                    query.blockKey(timeKey, "ABUSE_SUBMISSION");
                }
                processContent(timeKey, query, message, new TreeSet<>());
                User.storeDB2(timeKey, query);
                query.blockExecutables(timeKey);
                query.setFilter("ABUSE_SUBMISSION");
                if (query.hasMalware()) {
                    query.banOrBlockForAdmin(timeKey, "MALWARE");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.hasExecutableBlocked()) {
                    query.banOrBlockForAdmin(timeKey, "EXECUTABLE");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.hasPhishingBlocked()) {
                    query.banOrBlockForAdmin(timeKey, "PHISHING");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.isSpoofingFrom()) {
                    query.banOrBlockForAdmin(timeKey, "SPOOFING");
                    query.blockExecutables(timeKey);
                    query.blockPhishings(timeKey);
                    query.addHarmful(timeKey);
                } else if (query.isBanned()) {
                    query.addHarmful(timeKey);
                } else {
                    query.addUndesirable(timeKey);
                }
                String sender = query.getSender();
                String queueID = query.getQueueID();
                String client = query.getClient();
                String ip = query.getIP();
                String fqdn = query.getFQDN();
                storeIncomingMessage(queueID, client, message);
                White.dropFQDN(fqdn);
                if (!Abuse.offer(timeKey, query)) {
                    if (query.isSenderFreemail()) {
                        Block.addEmail(sender, "ABUSE_SUBMISSION");
                    } else {
                        Block.tryToDominoBlockIP(ip, "ABUSE_SUBMISSION");
                        Block.addFQDN(fqdn, "ABUSE_SUBMISSION");
                    }
                }
                Server.logTrace("abuse submission " + query.getClientQueueID() + " digest finished.");
            }
        }

        /**
         * Process a SMTP connection.
         */
        @Override
        public void run() {
            try {
                Socket socket;
                KeyStore keyStore;
                SSLSession sslSession;
                while ((socket = getSocket()) != null) {
                    String command = null;
                    try {
                        InetAddress ipAddress = socket.getInetAddress();
                        String origin = ipAddress.getHostAddress();
                        keyStore = null;
                        sslSession = null;
                        try {
                            if (!SUBMISSION && !HOSTNAME.equals("localhost") && Subnet.isReservedIP(ipAddress.getHostAddress())) {
                                String response = "530 This service is not able to accept connections from a reserved IP\r\n";
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(response.getBytes("ISO-8859-1"));
                                Server.logInfo(origin + ": dropped connection from reserved IP.");
                            } else if (!setIP(ipAddress)) {
                                String response = "451 The connection has been aborted due to a server error\r\n";
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(response.getBytes("ISO-8859-1"));
                                Server.logError(origin + ": dropped connection for unknow IP version.");
                            } else {
                                long commandTime = System.currentTimeMillis();
                                origin = getOrigin();
                                InputStream inputStream = socket.getInputStream();
                                InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                String response = processBanner();
                                OutputStream outputStream = socket.getOutputStream();
                                outputStream.write(response.getBytes("ISO-8859-1"));
                                Server.logQuery(
                                        commandTime, getTag(),
                                        origin, null, "HANDSHAKE", response
                                );
                                boolean active = response.startsWith("220 ");
                                boolean startTLS = false;
                                while (active && (command = bufferedReader.readLine()) != null) {
                                    commandTime = System.currentTimeMillis();
                                    command = command.trim();
                                    if (command.toUpperCase().startsWith("HELO ")) {
                                        keyStore = null;
                                        response = processHELO(command.substring(5));
                                        if (response.startsWith("500 ")) {
                                            active = false;
                                        } else {
                                            origin = getOrigin();
                                        }
                                    } else if (command.toUpperCase().startsWith("EHLO ")) {
                                        if (keyStore == null && !Block.containsCIDR(ipAddress)) {
                                            keyStore = Core.loadKeyStore(HOSTNAME);
                                        }
                                        response = processEHLO(command.substring(5),
                                                !SUBMISSION && sslSession == null && keyStore != null
                                                );
                                        if (response.startsWith("500 ")) {
                                            active = false;
                                        } else {
                                            origin = getOrigin();
                                        }
                                    } else if (extended && command.toUpperCase().equals("HELP")) {
                                        response = processHELP(keyStore);
                                    } else if (extended && command.toUpperCase().equals("STARTTLS")) {
                                        if (SUBMISSION) {
                                            response = "502 Already started TLS session\r\n";
                                        } else if (sslSession != null) {
                                            response = "502 Already started TLS session\r\n";
                                        } else if (keyStore == null) {
                                            active = false;
                                            response = "504 5.7.4 SPFBL TLS unavailable. "
                                                    + "See http://spfbl.net/en/feedback\r\n";
                                            addAbuse();
                                        } else {
                                            startTLS = true;
                                            response = "220 Ready to start TLS\r\n";
                                        }
                                    } else if (extended && command.toUpperCase().startsWith("AUTH ")) {
                                        response = processAUTH(command.substring(5));
                                        if (response.startsWith("504 ")) {
                                            active = false;
                                        }
                                    } else if (command.toUpperCase().startsWith("MAIL FROM:")) {
                                        response = processFROM(command.substring(10));
                                        if (response.startsWith("451 ")) {
                                            active = false;
                                        } else if (response.startsWith("550 ")) {
                                            active = false;
                                        } else if (response.startsWith("552 ")) {
                                            active = false;
                                        } else if (response.startsWith("530 ")) {
                                            active = false;
                                        }
                                    } else if (command.toUpperCase().startsWith("RCPT TO:")) {
                                        response = processRCPT(command.substring(8));
                                        if (response.startsWith("500 ")) {
                                            active = false;
                                        }
                                    } else if (command.toUpperCase().equals("DATA")) {
                                        response = processDATA();
                                        if (response.startsWith("503 ")) {
                                            active = false;
                                        }
                                    } else if (command.toUpperCase().equals("RSET")) {
                                        response = processRSET();
                                    } else if (command.toUpperCase().startsWith("VRFY ")) {
                                        response = "502 Command not implemented\r\n";
                                    } else if (command.toUpperCase().equals("NOOP")) {
                                        response = "250 OK\r\n";
                                    } else if (command.toUpperCase().equals("QUIT")) {
                                        active = false;
                                        response = "221 " + HOSTNAME + " closing connection\r\n";
                                    } else {
                                        response = "500 unrecognized command\r\n";
                                    }
                                    outputStream.write(response.getBytes("ISO-8859-1"));
                                    long tlsTime = 0;
                                    if (startTLS) {
                                        try {
                                            tlsTime = System.currentTimeMillis();
                                            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                                            kmf.init(keyStore, HOSTNAME.toCharArray());
                                            KeyManager[] km = kmf.getKeyManagers();
                                            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                                            tmf.init(keyStore);
                                            TrustManager[] tm = tmf.getTrustManagers();
                                            SSLContext sslContext = SSLContext.getInstance("TLS");
                                            sslContext.init(km, tm, null);
                                            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
                                            SSLSocket sslsocket = (SSLSocket) socketFactory.createSocket(
                                                    socket, HOSTNAME, 25, true
                                            );
                                            sslsocket.setUseClientMode(false);
                                            inputStream = sslsocket.getInputStream();
                                            inputStreamReader = new InputStreamReader(inputStream, "ISO-8859-1");
                                            bufferedReader = new BufferedReader(inputStreamReader);
                                            outputStream = sslsocket.getOutputStream();
                                            sslSession = sslsocket.getSession();
                                        } catch (Exception ex) {
                                            Server.logError(ex);
                                        }
                                    } else if (hasQueueID()) {
                                        response = queueMessage(
                                                bufferedReader, sslSession, origin
                                        );
                                        if (response.startsWith("55")) {
                                            active = false;
                                        }
                                        outputStream.write(response.getBytes("ISO-8859-1"));
                                        resetTime();
                                    }
                                    Server.logQuery(
                                            commandTime, getTag(),
                                            origin, null, command, response
                                    );
                                    if (startTLS) {
                                        try {
                                            if (sslSession == null) {
                                                String message = origin + ": "
                                                        + "TLS session failed.";
                                                Server.log(
                                                        tlsTime, ERROR, getTag(),
                                                        null, message, null
                                                );
                                            } else {
                                                String message = origin + ": "
                                                        + sslSession.getProtocol()
                                                        + " session started with cipher "
                                                        + sslSession.getCipherSuite();
                                                Server.log(
                                                        tlsTime, INFO, getTag(),
                                                        null, message, null
                                                );
                                                // TODO: certificate validation.
                                            }
                                        } finally {
                                            startTLS = false;
                                        }
                                    }
                                }
                            }
                            Server.logInfo(origin + ": closed connection.");
                        } catch (SSLException ex) {
                            // Conexão interrompida.
                            Server.logInfo(origin + ": interrupted SSL handshake.");
                        } catch (SocketException ex) {
                            // Conexão interrompida.
                            Server.logInfo(origin + ": interrupted connection.");
                        } finally {
                            // Fecha conexão logo após resposta.
                            socket.close();
                            dropConnections();
                        }
                    } catch (Exception ex) {
                        if (command != null) {
                            Server.logError(command);
                        }
                        Server.logError(ex);
                    } finally {
                        processSubmission();
                        offerConnection(this);
                    }
                }
            } finally {
                Server.logTrace(getName() + " thread closed.");
            }
        }
        
        /**
         * Transaction parameters.
         */
        private boolean extended = true;
        private boolean authenticated = false;
        private String abuse = null;
        private String ip = null;
        private String fqdn = null;
        private String sender = null;
        private SPF.Qualifier qualifier = null;
        private final TreeMap<String,User> recipientMap = new TreeMap<>();
        private Long queueID = null;
        private String from = null;
        private String replyTo = null;
        private String messageID = null;
        private Date date = null;
        private URL unsubscribe = null;
        private final ArrayList<DKIM.Signature> signatureList = new ArrayList<>(1);
        private final TreeSet<String> signerSet = new TreeSet<>();
        private String subject = null;
        private boolean wanted = false;
        private LinkedList<SimpleImmutableEntry<Query,MimeMessage>> submissionList = new LinkedList<>();
        
        private TreeSet<String> getTokenSet(User user, String recipient) {
            TreeSet<String> resultSet = new TreeSet<>();
            if (qualifier == Qualifier.PASS && Provider.isFreeMail(sender)) {
                resultSet.add(sender);
            } else if (!Subnet.isReservedIP(ip)) {
                resultSet.add(ip);
                if (fqdn != null) {
                    resultSet.add('.' + fqdn);
                }
                String domain = Domain.extractHost(sender, true);
                if (domain != null) {
                    resultSet.add(domain);
                }
                if (user != null) {
                    resultSet.add(user.getEmail() + ':');
                }
                if (recipient != null) {
                    resultSet.add('>' + recipient);
                }
            }
            return resultSet;
        }
        
        private boolean setIP(InetAddress ipAddress) {
            submissionList.clear();
            if (ipAddress instanceof Inet4Address) {
                extended = true;
                ip = SubnetIPv4.normalizeIPv4(ipAddress.getHostAddress());
                abuse = SUBMISSION ? null : Abuse.getEmailFqdnOrIPv4(ip);
                helo = null;
                authenticated = false;
                reset();
                return true;
            } else if (ipAddress instanceof Inet6Address) {
                extended = true;
                ip = SubnetIPv6.normalizeIPv6(ipAddress.getHostAddress());
                abuse = SUBMISSION ? null : Abuse.getEmailFqdnOrIPv6(ip);
                helo = null;
                authenticated = false;
                reset();
                return true;
            } else {
                extended = false;
                ip = null;
                abuse = null;
                helo = null;
                authenticated = false;
                return false;
            }
        }
        
        private boolean hasQueueID() {
            return queueID != null;
        }
        
        private String getOrigin() {
            String origin = ip;
            if (fqdn != null) {
                origin += ' ' + fqdn;
            } else if (helo != null) {
                origin += ' ' + helo;
            }
            if (abuse != null) {
                origin += ' ' + abuse;
            }
            return origin;
        }
        
        private long addAbuse() {
            long timeKey = Server.getNewUniqueTime();
            TreeSet<String> tokenSet = getTokenSet(null, null);
            SPF.setSpam(timeKey, tokenSet);
            return timeKey;
        }
        
        private User.Query addQuery(
                User user, String recipient, String subaddress,
                String result, String filter, boolean abuse
        ) {
            if (user == null) {
                return null;
            } else if (result == null) {
                return null;
            } else {
                long timeKey = Server.getNewUniqueTime();
                TreeSet<String> localSet = getTokenSet(user, recipient);
                User.Query query = user.addQuery(
                        timeKey, HOSTNAME,
                        ip, helo, fqdn, sender, qualifier,
                        recipient, subaddress, localSet, result, filter
                );
                if (abuse) {
                    query.setSpam(timeKey);
                }
                return query;
            }
        }
        
        private void reset() {
            fqdn = null;
            sender = null;
            qualifier = null;
            recipientMap.clear();
            queueID = null;
            from = null;
            replyTo = null;
            messageID = null;
            date = null;
            unsubscribe = null;
            signatureList.clear();
            signerSet.clear();
            subject = null;
            wanted = false;
        }
        
        private String processRSET() {
            reset();
            return "250 Reset OK\r\n";
        }
        
        private String processBanner() {
            if (Block.isBannedIP(ip)) {
                addAbuse();
                Abuse.addHarmful(abuse);
                CIDR.addHarmful(ip);
                return "550 5.7.1 SPFBL permanently banned. "
                        + "See http://spfbl.net/en/feedback\r\n";
            } else {
                return "220 " + HOSTNAME + " ESMTP "
                        + "SPFBL " + Core.getSubVersion() + "\r\n";
            }
        }
        
        private void processFQDN() {
            if (SUBMISSION) {
                fqdn = null;
                abuse = Abuse.getEmailIP(ip);
            } else if (FQDN.isFQDN(ip, helo)) {
                fqdn = Domain.normalizeHostname(helo, false);
                abuse = Abuse.getEmail(ip, fqdn, sender, qualifier);
            } else if (FQDN.addFQDN(ip, helo, true)) {
                fqdn = Domain.normalizeHostname(helo, false);
                abuse = Abuse.getEmail(ip, fqdn, sender, qualifier);
            } else {
                fqdn = null;
                abuse = Abuse.getEmailIP(ip);
            }
        }
        
        private String processHELO(String value) {
            extended = false;
            helo = value.trim();
            processFQDN();
            if (Block.isBannedFQDN(fqdn)) {
                addAbuse();
                Abuse.addHarmful(abuse);
                CIDR.addHarmful(ip);
                FQDN.addHarmful(fqdn);
                return "550 5.7.1 SPFBL permanently banned. "
                        + "See http://spfbl.net/en/feedback\r\n";
            } else {
                return "250 " + HOSTNAME + " Hello " + helo + " [" + ip + "]\r\n";
            }
        }
        
        private String processEHLO(String value, boolean startTLS) {
            extended = true;
            helo = value.trim();
            processFQDN();
            if (Block.isBannedFQDN(fqdn)) {
                addAbuse();
                Abuse.addHarmful(abuse);
                CIDR.addHarmful(ip);
                FQDN.addHarmful(fqdn);
                return "550 5.7.1 SPFBL permanently banned. "
                        + "See http://spfbl.net/en/feedback\r\n";
            } else {
                return "250-" + HOSTNAME + " Hello " + helo + " [" + ip + "]\r\n"
                        + "250-SIZE " + SIZE + "\r\n"
                        + (startTLS ? "250-STARTTLS\r\n" : "")
                        + (SUBMISSION ? "250-AUTH PLAIN\r\n" : "")
                        + "250 HELP\r\n";
            }
        }
        
        private String processAUTH(String value) {
            if (SUBMISSION) {
                authenticated = false;
                User user = null;
                if (value.startsWith("PLAIN ")) {
                    value = value.substring(6).trim();
                    value = new String(Core.BASE64STANDARD.decode(value));
                    StringTokenizer tokenizer = new StringTokenizer(value, "\0");
                    if (tokenizer.countTokens() == 2) {
                        String email = tokenizer.nextToken();
                        String password = tokenizer.nextToken();
                        user = User.getExact(email);
                        if (user != null && user.isValidPassword(password)) {
                            authenticated = true;
                            return "235 2.7.0 Authentication successful.\r\n";
                        }
                    }
                }
                if (user != null) {
                    addAbuse();
                    Abuse.addHarmful(abuse);
                    CIDR.addHarmful(ip);
                    return "535 5.7.1 SPFBL authentication failed.\r\n";
                }
            }
            if (!Abuse.reportAuthFraud(TIME, HOSTNAME, ip)) {
                Block.addSafe(ip);
                Block.addSafe(fqdn);
            }
            addAbuse();
            Reputation.addHarmful(null, null, abuse, ip, fqdn, helo, sender, qualifier, null);
            return "504 5.7.4 SPFBL authentication not supported. "
                    + "See http://spfbl.net/en/feedback\r\n";
        }
        
        private String processFROM(String value) {
            if (helo == null) {
                return "503 hostname not yet given\r\n";
            } else if (SUBMISSION && !authenticated) {
                addAbuse();
                Block.addSafe(ip);
                Block.addSafe(fqdn);
                Abuse.addHarmful(abuse);
                CIDR.addHarmful(ip);
                return "530 5.5.1 SPFBL authentication required. "
                        + "See http://spfbl.net/en/feedback\r\n";
            } else if (sender == null) {
                try {
                    reset();
                    int size = 0;
                    if (value.contains(" SIZE=")) {
                        try {
                            int index = value.lastIndexOf('=');
                            size = Integer.parseInt(value.substring(index + 1));
                            index = value.lastIndexOf(' ', index);
                            value = value.substring(0, index);
                        } catch (NumberFormatException ex) {
                            Server.logError(ex);
                        }
                    }
                    if (size > SIZE) {
                        return "552 Message too big for this system.\r\n";
                    } else {
                        String address;
                        if (value.trim().equals("<>")) {
                            address = null;
                        } else {
                            InternetAddress[] parsed = InternetAddress.parse(value);
                            if (parsed.length  == 0) {
                                address = null;
                            } else {
                                address = parsed[0].getAddress();
                            }
                        }
                        if (address == null) {
                            sender = "";
                            return "250 OK\r\n";
                        } else if (!Domain.isMailFrom(address)) {
                            return "501 Malformed mail address: " + value + "\r\n";
                        } else if (authenticated) {
                            sender = address;
                            return "250 SPFBL check authenticated.\r\n";
                        } else if (Generic.containsGeneric(address)) {
                            // Don't query SPF from generic domain
                            // to avoid high SMTP latency.
                            sender = address.toLowerCase();
                            return "250 SPFBL check generic.\r\n";
                        } else {
                            long time = System.currentTimeMillis();
                            SPF spf = SPF.getSPF(address);
                            if (spf == null) {
                                sender = null;
                                return "451 4.5.1 SPFBL registry not found.\r\n";
                            } else if (spf.isDefinitelyInexistent()) {
                                sender = null;
                                addAbuse();
                                Reputation.addUnacceptable(null, null, abuse, ip, fqdn, helo, sender, qualifier, null);
                                return "550 5.7.1 SPFBL non-existent domain. "
                                        + "See http://spfbl.net/en/feedback\r\n";
                            } else if (spf.isInexistent()) {
                                sender = null;
                                return "451 4.5.1 SPFBL non-existent domain.\r\n";
                            } else {
                                try {
                                    qualifier = spf.getQualifier(ip, address, helo);
                                    if (qualifier == SPF.Qualifier.PASS) {
                                        sender = address.toLowerCase();
                                        abuse = Abuse.getEmail(ip, fqdn, sender, qualifier);
                                        return "250 SPFBL check passed.\r\n";
                                    } else if (spf.isTemporary()) {
                                        sender = null;
                                        qualifier = null;
                                        return "451 4.5.1 SPFBL temporary error.\r\n";
                                    } else if (Core.isTestingVersion() && Core.isMyHostname("localhost")) {
                                        sender = address.toLowerCase();
                                        return "250 OK\r\n";
                                    } else if (fqdn == null && qualifier == SPF.Qualifier.FAIL) {
                                        sender = null;
                                        qualifier = null;
                                        addAbuse();
                                        Reputation.addUnacceptable(null, null, abuse, ip, fqdn, helo, sender, qualifier, null);
                                        return "550 5.7.1 SPFBL check failed. "
                                                + "See http://spfbl.net/en/feedback\r\n";
                                    } else if (fqdn == null && abuse == null && Block.containsCIDR(ip)) {
                                        sender = null;
                                        qualifier = null;
                                        addAbuse();
                                        Reputation.addUnacceptable(null, null, abuse, ip, fqdn, helo, sender, qualifier, null);
                                        return "550 5.7.1 SPFBL invalid identification. "
                                                + "See http://spfbl.net/en/feedback\r\n";
                                    } else if (qualifier == SPF.Qualifier.SOFTFAIL && Defer.defer(address, Core.getDeferTimeSOFTFAIL())) {
                                        sender = null;
                                        qualifier = null;
                                        return "451 4.7.1 SPFBL softfail greylisting.\r\n";
                                    } else {
                                        sender = address.toLowerCase();
                                        return "250 OK\r\n";
                                    }
                                } catch (ProcessException ex) {
                                    if (ex.isErrorMessage("HOST NOT FOUND")) {
                                        sender = null;
                                        qualifier = null;
                                        return "550 5.7.0 SPFBL permanenty error.\r\n";
                                    } else if (ex.isErrorMessage("TIMEOUT")) {
                                        sender = null;
                                        qualifier = null;
                                        return "451 4.5.1 SPFBL temporary error.\r\n";
                                    } else {
                                        throw ex;
                                    }
                                }
                            }
                        }
                    }
                } catch (AddressException ex) {
                    return "501 Malformed mail address: " + value + "\r\n";
                } catch (ProcessException ex) {
                    Server.logError(ex);
                    return "451 4.5.1 SPFBL temporary error.\r\n";
                }
            } else {
                return "503 Sender already given.\r\n";
            }
        }
        
        private String processRCPT(String value) {
            if (sender == null) {
                return "503 Sender not yet given.\r\n";
            } else {
                try {
                    InternetAddress[] addresses = InternetAddress.parse(value);
                    String recipient = addresses[0].getAddress();
                    if (authenticated) {
                        if (!isValidEmail(recipient)) {
                            return "501 Invalid recipient address.\r\n";
                        } else if (recipientMap.containsKey(recipient)) {
                            return "250 Already accepted.\r\n";
                        } else {
                            recipientMap.put(recipient, null);
                            return "250 Accepted.\r\n";
                        }
                    } else {
                        String subaddress = "";
                        int index1 = recipient.indexOf('+');
                        int index2 = recipient.lastIndexOf('@');
                        if (index1 > 0 && index2 > 0) {
                            // Subaddress Extension.
                            // https://tools.ietf.org/html/rfc5233.html
                            String part = recipient.substring(0, index1);
                            subaddress = recipient.substring(index1+1, index2);
                            String domain = recipient.substring(index2);
                            recipient = part + domain;
                        }
                        recipient = recipient.toLowerCase();
                        if (recipient.equals("postmaster")) {
                            recipient = POSTMASTER;
//                        } else if (recipient.equals("postmaster@" + HOSTNAME)) {
//                            recipient = POSTMASTER;
//                        } else if (recipient.equals("abuse@" + HOSTNAME)) {
//                            recipient = POSTMASTER;
//                        } else if (recipient.equals("mailer-daemon@" + HOSTNAME)) {
//                            recipient = POSTMASTER;
                        } else if (recipient.endsWith("@" + HOSTNAME)) {
                            recipient = POSTMASTER;
                        }
                        if (!isValidEmail(recipient)) {
                            return "501 Invalid recipient address.\r\n";
                        } else if (recipientMap.containsKey(recipient)) {
                            return "250 Already accepted.\r\n";
                        } else {
                            int index = recipient.indexOf('@');
                            String domain = recipient.substring(index);
                            User user = User.get("postmaster" + domain);
                            Long trapTime = Trap.getTime(recipient);
                            if (user == null || !user.hasTransport()) {
                                addAbuse();
                                Reputation.addHarmful(null, user, abuse, ip, fqdn, helo, sender, qualifier, recipient);
                                return "550 5.7.1 SPFBL relay not permitted. "
                                        + "See http://spfbl.net/en/feedback\r\n";
                            } else if (trapTime != null && System.currentTimeMillis() < trapTime) {
                                addQuery(user, recipient, subaddress, "INEXISTENT", "RECIPIENT_INEXISTENT", false);
                                Reputation.addUnacceptable(null, user, abuse, ip, fqdn, helo, sender, qualifier, recipient);
                                return "551 5.1.1 SPFBL inexistent recipient. "
                                        + "See http://spfbl.net/en/feedback\r\n";
                            } else if (user.isInvitation(recipient, subaddress)) {
                                wanted = true;
                                recipientMap.put(recipient, user);
                                return "250 Invited.\r\n";
                            } else if (trapTime == null && White.containsKey(user, ip, fqdn, sender, qualifier)) {
                                wanted = true;
                                recipientMap.put(recipient, user);
                                return "250 Welcome.\r\n";
                            } else if (Core.isTestingVersion() && Subnet.isReservedIP(ip)) {
                                recipientMap.put(recipient, user);
                                return "250 Accepted.\r\n";
                            } else if (Block.isBanned(user, ip, helo, fqdn, sender, qualifier, recipient)) {
                                long timeKey = addAbuse();
                                Abuse.reportAbuseSafe(
                                        timeKey, HOSTNAME, user, sender, recipient,
                                        ip, fqdn, qualifier, null
                                );
                                Reputation.addHarmful(null, user, abuse, ip, fqdn, helo, sender, qualifier, recipient);
                                return "550 5.7.1 SPFBL permanently banned. "
                                        + "See http://spfbl.net/en/feedback\r\n";
                            } else if (subaddress.equals("antibot")) {
                                addQuery(user, recipient, subaddress, "GREYLIST", "GREYLIST_ANTIBOT", false);
                                return "501 5.1.6 This is an anti-bot recipient. "
                                        + "Reply your message to " + recipient + ".\r\n";
                            } else if (qualifier == null || qualifier == SPF.Qualifier.PASS) {
                                recipientMap.put(recipient, user);
                                return "250 Accepted.\r\n";
                            } else if (qualifier == SPF.Qualifier.FAIL) {
                                addQuery(user, recipient, subaddress, "FAIL", "SPF_FAIL", true);
                                Reputation.addUnacceptable(null, user, abuse, ip, fqdn, helo, sender, qualifier, recipient);
                                return "550 5.7.1 SPFBL check failed. See http://spfbl.net/en/feedback\r\n";
                            } else if (fqdn == null && abuse == null && Block.containsCIDR(ip)) {
                                addQuery(user, recipient, subaddress, "INVALID", "ENVELOPE_INVALID", true);
                                return "550 5.7.1 SPFBL invalid identification. "
                                        + "See http://spfbl.net/en/feedback\r\n";
                            } else {
                                recipientMap.put(recipient, user);
                                return "250 Accepted.\r\n";
                            }
                        }
                    }
                } catch (AddressException ex) {
                    return "501 Malformed mail address: " + value + "\r\n";
                }
            }
        }
        
        private String processDATA() {
            if (recipientMap.isEmpty()) {
                return "503 Valid RCPT command must precede DATA.\r\n";
            } else {
                queueID = Server.getNewUniqueTime();
                return "354 Enter message, ending with \".\" on a line by itself.\r\n";
            }
        }
        
        private String getTag() {
            return extended ? "ESMTP" : "BSMTP";
        }
        
        private String queueMessage(
                BufferedReader bufferedReader,
                SSLSession sslSession,
                String origin
        ) throws SocketException {
            if (queueID == null) {
                return "554 Transaction failed.\r\n";
            } else if (authenticated) {
                ArrayList<File> fileList = new ArrayList<>();
                File incomingFile = new File(INCOMING, '.' + Long.toString(queueID,32) + '@' + HOSTNAME);
                fileList.add(incomingFile);
                try {
                    String line;
                    int size = 0;
                    try (FileOutputStream stream = new FileOutputStream(incomingFile)) {
                        while ((line = bufferedReader.readLine()) != null && !line.equals(".")) {
                            byte[] byteArray = line.getBytes("ISO-8859-1");
                            size += byteArray.length + 2;
                            if (size > SIZE) {
                                break;
                            } else {
                                stream.write(byteArray);
                                stream.write('\r');
                                stream.write('\n');
                                stream.flush();
                            }
                        }
                    }
                    if (size > SIZE) {
                        incomingFile.delete();
                        return "552 Message too big for this system.\r\n";
                    } else if (size == 0 || line == null || !line.equals(".")) {
                        incomingFile.delete();
                        return "554 Transaction failed.\r\n";
                    } else {
                        TreeSet<Long> deliverySet = new TreeSet<>();
                        User user = User.getUserFor(sender);
                        for (String recipient : recipientMap.keySet()) {
                            long deliveryTime = Server.getNewUniqueTime();
                            deliverySet.add(deliveryTime);
                            String deliveryKey = Long.toString(deliveryTime, 32);
                            File deliveryFile = new File(DELIVERY, '.' + deliveryKey);
                            fileList.add(deliveryFile);
                            try (FileWriter writer = new FileWriter(deliveryFile)) {
                                whiteUser(writer, user);
                                whiteReturnPathSMTP(writer);
                                whiteReceivedSMTP(writer, sslSession, recipient);
                                whiteDeliveryStatusSMTP(writer, recipient);
                            }
                        }
                        for (int i = fileList.size()-1 ; i >= 0; i--) {
                            File file = fileList.get(i);
                            Path source = file.toPath();
                            Path target = source.resolveSibling(file.getName().substring(1));
                            fileList.add(target.toFile());
                            Files.move(source, target, REPLACE_EXISTING);
                        }
                        processDelivery(deliverySet);
                        return "250 OK <" + Long.toString(queueID,32) + "@" + HOSTNAME + ">\r\n";
                    }
                } catch (SocketException ex) {
                    for (File file : fileList) {
                        file.delete();
                    }
                    throw ex;
                } catch (Exception ex) {
                    for (File file : fileList) {
                        file.delete();
                    }
                    Server.logError(ex);
                    return "451 Requested action aborted: local error in processing.\r\n";
                } finally {
                    reset();
                }
            } else {
                ArrayList<File> fileList = new ArrayList<>();
                File incomingFile = new File(INCOMING, '.' + Long.toString(queueID,32) + '@' + HOSTNAME);
                fileList.add(incomingFile);
                try {
                    String line;
                    int size = 0;
                    int received = 0;
                    boolean compliant = true;
                    try (FileOutputStream stream = new FileOutputStream(incomingFile)) {
                        StringBuilder headerBuilder = new StringBuilder();
                        while ((line = bufferedReader.readLine()) != null) {
                            byte[] byteArray = line.getBytes("ISO-8859-1");
                            size += byteArray.length + 2;
                            if (size > SIZE) {
                                break;
                            } else {
                                stream.write(byteArray);
                                stream.write('\r');
                                stream.write('\n');
                                stream.flush();
                                if ((line.isEmpty() || Character.isAlphabetic(line.charAt(0))) && headerBuilder.length() > 0) {
                                    String header = headerBuilder.toString();
                                    if (header.startsWith("DKIM-Signature:")) {
                                        try {
                                            DKIM.Signature signature = new DKIM.Signature(header);
                                            signatureList.add(signature); 
                                       } catch (Exception ex) {
                                            Server.logError(ex);
                                            Server.logError(header);
                                        }
                                    } else {
                                        for (DKIM.Signature signature : signatureList) {
                                            signature.putHeader(header);
                                        }
                                        if (header.startsWith("Received:")) {
                                            received++;
                                        } else if (header.startsWith("From:")) {
                                            Matcher matcher = FORGED_FROM_PATTERN.createMatcher(header);
                                            if (matcher.find()) {
                                                from = matcher.group(1);
                                                compliant = false;
                                            } else if (from == null) {
                                                String value = header.substring(5).trim();
                                                if (value.isEmpty()) {
                                                    compliant = false;
                                                } else {
                                                    from = extractAddress(value, true);
                                                    if (from == null) {
                                                        Server.logError("header not reconized: " + header);
                                                    } else if (from.equals("MAILER-DAEMON")) {
                                                        if (fqdn == null) {
                                                            from = "mailer-daemon@" + helo;
                                                        } else {
                                                            from = "mailer-daemon@" + fqdn;
                                                        }
                                                    }
                                                }
                                            } else {
                                                compliant = false;
                                            }
                                            FORGED_FROM_PATTERN.offerMatcher(matcher);
                                        } else if (header.startsWith("Reply-To:")) {
                                            if (replyTo == null) {
                                                replyTo = extractAddress(header.substring(9), true);
                                                if (replyTo == null) {
                                                    Server.logError("header not reconized: " + header);
                                                }
                                            } else {
                                                compliant = false;
                                            }
                                        } else if (header.startsWith("Subject:")) {
                                            String text;
                                            if (header.length() > 8) {
                                                text = extractSubject(header.substring(8));
                                            } else {
                                                text = "";
                                            }
                                            if (subject == null) {
                                                subject = text;
                                            } else {
                                                compliant = false;
                                            }
                                        } else if (header.startsWith("Message-ID:")) {
                                            if (messageID == null) {
                                                messageID = extractMessageID(header.substring(11));
                                                if (messageID == null) {
                                                    Server.logError("header not reconized: " + header);
                                                }
                                            } else {
                                                compliant = false;
                                            }
                                        } else if (header.startsWith("Date:")) {
                                            if (date == null) {
                                                date = extractDate(header.substring(5));
                                                if (date == null) {
                                                    Server.logError("header not reconized: " + header);
                                                }
                                            } else {
                                                compliant = false;
                                            }
                                        } else if (header.startsWith("List-Unsubscribe:")) {
                                            if (unsubscribe == null) {
                                                String value = header.substring(17).trim();
                                                if (isValidEmail(value)) {
                                                    unsubscribe = new URL("mailto:" + value);
                                                } else {
                                                    URL url = extractUnsubscribe(value);
                                                    if (url == null) {
                                                        Server.logError("header not reconized: " + header);
                                                    } else if (url.getProtocol().matches("^https?$")) {
                                                        unsubscribe = url;
                                                    }
                                                }
                                            } else {
                                                compliant = false;
                                            }
                                        } else if (header.startsWith("In-Reply-To:")) {
                                            String inReplyTo = header.substring(12).trim();
                                            Matcher matcher = IN_REPLY_TO_PATTERN.createMatcher(inReplyTo);
                                            if (matcher.find()) {
                                                String hostname = matcher.group(2);
                                                if (hostname.equals(HOSTNAME)) {
                                                    String ticket = matcher.group(1);
                                                    String fromReply = Core.decryptURLSafe(ticket);
                                                    if (fromReply != null) {
                                                        for (String recipient : recipientMap.keySet()) {
                                                            if (fromReply.equals(recipient)) {
                                                                wanted = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            IN_REPLY_TO_PATTERN.offerMatcher(matcher);
                                        }
                                    }
                                    headerBuilder.setLength(0);
                                }
                                if (line.isEmpty()) {
                                    break;
                                } else {
                                    headerBuilder.append(line);
                                    headerBuilder.append('\r');
                                    headerBuilder.append('\n');
                                }
                            }
                        }
                        if (from == null) {
                            compliant = false;
                        } else if (subject == null) {
                            compliant = false;
                        }
                    }
                    if (size > SIZE) {
                        incomingFile.delete();
                        return "552 Message too big for this system.\r\n";
                    } else if (size == 0 || !line.isEmpty()) {
                        incomingFile.delete();
                        return "554 Transaction failed.\r\n";
                    } else if (!compliant) {
                        incomingFile.delete();
                        return "554 Message headers are not RFC compliant.\r\n";
                    } else if (received > 32) {
                        incomingFile.delete();
                        return "554 Too many hoops.\r\n";
                    } else {
                        for (DKIM.Signature signature : signatureList) {
                            long signerTime = System.currentTimeMillis();
                            String domain = signature.getDomain();
                            if (signature.isHeaderValidSafe() && signerSet.add(domain)) {
                                String message = origin
                                        + ": DKIM signer "
                                        + domain
                                        + " added";
                                Server.log(
                                        signerTime, INFO,
                                        getTag(), null,
                                        message, null
                                );
                            }
                        }
                        if (!Generic.containsGeneric(from)) {
                            int index = from.indexOf('@') + 1;
                            String domain = from.substring(index);
                            if (!signerSet.contains(domain)) {
                                long signerTime = System.currentTimeMillis();
                                if (SPF.getQualifier(ip, from, helo, false) == SPF.Qualifier.PASS) {
                                    if (signerSet.add(domain)) {
                                        String message = origin
                                                + ": SPF signer "
                                                + domain
                                                + " added";
                                        Server.log(
                                                signerTime, INFO,
                                                getTag(), null,
                                                message, null
                                        );
                                    }
                                }
                            }
                        }
                        TreeMap<Long,User.Query> queryMap = new TreeMap<>();
                        boolean white = false;
                        boolean block = false;
                        String subaddress = null;
                        for (String recipient : recipientMap.keySet()) {
                            long timeKey = Server.getNewUniqueTime();
                            User user = recipientMap.get(recipient);
                            TreeSet<String> localSet = getTokenSet(user, recipient);
                            Long trapTime = Trap.getTime(recipient);
                            String result = trapTime == null ? "QUEUE" : "TRAP";
                            User.Query query = user.newQuery(
                                    HOSTNAME,
                                    ip, helo, fqdn,
                                    sender, qualifier,
                                    recipient, subaddress,
                                    localSet, result,
                                    from, replyTo,
                                    date, unsubscribe,
                                    signerSet, subject,
                                    messageID, Long.toString(queueID,32),
                                    new Date()
                            );
                            if (wanted) {
                                query.whiteKey(timeKey);
                            }
                            if (query.isWhiteKey()) {
                                Block.clearSafe(timeKey, null, user, ip, helo, sender, fqdn, qualifier, recipient, "WHITE");
                                if (trapTime == null) {
                                    white = true;
                                } else {
                                    Reputation.addUnacceptable(null, user, abuse, ip, fqdn, helo, sender, qualifier, recipient);
                                }
                            } else if (query.isBlockKey()) {
                                block = true;
                            }
                            queryMap.put(timeKey, query);
                        }
                        if (block && !white) {
                            Path source = incomingFile.toPath();
                            Path target = source.resolveSibling(incomingFile.getName().substring(1));
                            Files.move(source, target, REPLACE_EXISTING);
                            incomingFile = target.toFile();
                            fileList.add(incomingFile);
                            for (long timeKey : queryMap.keySet()) {
                                User.Query query = queryMap.get(timeKey);
                                if (query.isBlockKey()) {
                                    query.setResult("BLOCK");
                                    query.addUndesirable(timeKey);
                                    Abuse.offer(timeKey, query);
                                } else {
                                    query.setResultFilter("REJECT", "ORIGIN_BLOCKED");
                                    query.addUnacceptable();
                                }
                                User.storeDB2(timeKey, query);
                            }
                            return "550 5.7.1 SPFBL permanently blocked. "
                                    + "See http://spfbl.net/en/feedback\r\n";
                        } else {
                            try (FileOutputStream stream = new FileOutputStream(incomingFile, true)) {
                                while ((line = bufferedReader.readLine()) != null && !line.equals(".")) {
                                    line = line.startsWith(".") ? line.substring(1) : line;
                                    byte[] byteArray = line.getBytes("ISO-8859-1");
                                    size += byteArray.length + 2;
                                    if (size > SIZE) {
                                        break;
                                    } else {
                                        stream.write(byteArray);
                                        stream.write('\r');
                                        stream.write('\n');
                                        stream.flush();
                                        for (DKIM.Signature signature : signatureList) {
                                            signature.bodyDigestUpdate(line);
                                        }
                                    }
                                }
                            }
                            if (size > SIZE) {
                                incomingFile.delete();
                                return "552 Message too big for this system.\r\n";
                            } else if (line == null) {
                                incomingFile.delete();
                                return "554 Transaction failed.\r\n";
                            } else if (!line.equals(".")) {
                                incomingFile.delete();
                                return "554 Transaction failed.\r\n";
                            } else {
                                for (DKIM.Signature signature : signatureList) {
                                    long dkimTime = System.currentTimeMillis();
                                    String domain = signature.getDomain();
                                    String result = signature.getResult();
                                    Core.Level level;
                                    String message = origin + ": DKIM " + domain;
                                    switch (result) {
                                        case "pass":
                                            level = INFO;
                                            message += " signature passed";
                                            break;
                                        case "fail":
                                            level = WARN;
                                            message += " signature failed";
                                            break;
                                        case "permerror":
                                            level = ERROR;
                                            message += " permanent error";
                                            break;
                                        default:
                                            level = ERROR;
                                            message += " temporary error";
                                    }
                                    Server.log(
                                            dkimTime, level,
                                            getTag(), null,
                                            message, null
                                    );
                                }
                                boolean submitted = false;
                                if (queryMap.size() == 1) {
                                    try {
                                        long timeKey = queryMap.firstKey();
                                        User.Query query = queryMap.get(timeKey);
                                        if (query.isRecipientAbuse()) {
                                            String sender = query.getSender();
                                            String from = query.getFrom();
                                            User complainer = null;
                                            if (query.isSigned(sender)) {
                                                complainer = User.get(sender);
                                            }
                                            if (query.isSigned(from)) {
                                                complainer = User.get(from);
                                            }
                                            if (complainer != null) {
                                                // This message can be an abuse SUBMISSION.
                                                MimeMessage message = loadMimeMessage(incomingFile);
                                                ArrayList<Part> partList = extractPartList(message);
                                                if (partList != null) {
                                                    for (Part part : partList) {
                                                        String[] contentType = extractContentType(part);
                                                        String type = contentType[0];
                                                        if (type.equals("message/rfc822") || type.equals("message/global") || type.equals("message/rfc822-headers") || type.equals("text/rfc822-headers")) {
                                                            if (part.getContent() instanceof MimeMessage) {
                                                                message = (MimeMessage) part.getContent();
                                                            } else {
                                                                message = new SimpleMimeMessage(null, part.getInputStream());
                                                            }
                                                            if (processComplainTicket(complainer.getEmail(), message)) {
                                                                submitted = true;
                                                            } else {
                                                                Entry<Long,User.Query> entry = newQuery(complainer, message);
                                                                query = entry == null ? null : entry.getValue();
                                                                if (query == null) {
                                                                    if (message.getHeader("Received") == null) {
                                                                        return "554 5.7.7 Abuse submission rejected because it don't have the received headers.\r\n";
                                                                    } else {
                                                                        return "554 5.7.7 Abuse submission rejected because it was unable to parse the received headers.\r\n";
                                                                    }
                                                                } else if (query.isLocalRouting()) {
                                                                    return "554 5.7.1 Abuse submission rejected because it's not allowed to report local routing messages.\r\n";
//                                                                } else if (query.isBounceMessage() && query.hasFrom()) {
//                                                                    return "554 5.7.1 Abuse submission rejected because it's not allowed to report bounced messages.\r\n";
                                                                } else {
                                                                    submissionList.add(new SimpleImmutableEntry(query,message));
                                                                    submitted = true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } catch (Exception ex) {
                                        Server.logError(ex);
                                        submitted = false;
                                    }
                                }
                                if (submitted) {
                                    incomingFile.delete();
                                    return "250 Abuse submission accepted\r\n";
                                } else {
                                    TreeSet<Long> deliverySet = new TreeSet<>();
                                    for (long timeKey : queryMap.keySet()) {
                                        User.Query query = queryMap.get(timeKey);
                                        if (query.isResult("TRAP")) {
                                            query.addUndesirable(timeKey);
                                            // Discard spamtrap.
                                            if (Math.random() > 0.8d) {
                                                query.blockKey(timeKey, query.getRecipient() + ";SPAMTRAP");
                                            }
                                        } else {
                                            deliverySet.add(timeKey);
                                            User user = query.getUser();
                                            TreeSet<String> tokenSet = query.getTokenSet();
                                            String recipient = query.getRecipient();
                                            String deliveryKey = Long.toString(timeKey, 32);
                                            File deliveryFile = new File(DELIVERY, '.' + deliveryKey);
                                            fileList.add(deliveryFile);
                                            try (FileWriter writer = new FileWriter(deliveryFile)) {
                                                whiteUser(writer, user);
                                                whiteReturnPathSMTP(writer);
                                                whiteReceivedSPF(writer);
                                                whiteAuthenticationResults(writer);
                                                whiteReceivedSMTP(writer, sslSession, recipient);
                                                whiteReceivedSPFBL(writer, user, timeKey, tokenSet);
                                                whiteDeliveryStatusSMTP(writer, recipient);
                                            }
                                        }
                                        User.storeDB2(timeKey, query);
                                    }
                                    for (int i = fileList.size()-1 ; i >= 0; i--) {
                                        File file = fileList.get(i);
                                        Path source = file.toPath();
                                        Path target = source.resolveSibling(file.getName().substring(1));
                                        fileList.add(target.toFile());
                                        Files.move(source, target, REPLACE_EXISTING);
                                    }
                                    processDelivery(deliverySet);
                                    return "250 OK <" + Long.toString(queueID,32) + "@" + HOSTNAME + ">\r\n";
                                }
                            }
                        }
                    }
                } catch (SocketException ex) {
                    for (File file : fileList) {
                        file.delete();
                    }
                    throw ex;
                } catch (Exception ex) {
                    for (File file : fileList) {
                        file.delete();
                    }
                    Server.logError(ex);
                    return "451 Requested action aborted: local error in processing.\r\n";
                } finally {
                    reset();
                }
            }
        }
        
        private String processHELP(KeyStore keyStore) {
            if (SUBMISSION) {
                return "214-Commands supported:\r\n"
                        + (keyStore == null
                        ? "214 HELO EHLO MAIL AUTH RCPT SIZE DATA NOOP QUIT RSET HELP\r\n"
                        : "214 STARTTLS HELO EHLO MAIL AUTH RCPT SIZE DATA NOOP QUIT RSET HELP\r\n");
            } else {
                return "214-Commands supported:\r\n"
                        + (keyStore == null
                        ? "214 HELO EHLO MAIL RCPT SIZE DATA NOOP QUIT RSET HELP\r\n"
                        : "214 STARTTLS HELO EHLO MAIL RCPT SIZE DATA NOOP QUIT RSET HELP\r\n");
            }
        }
        
        private void whiteAuthenticationResults(FileWriter writer) throws IOException {
            writer.write("Authentication-Results: ");
            writer.write(HOSTNAME);
            writer.write(";\r\n");
            writer.write("\tspf=");
            if (qualifier == null) {
                writer.write("none");
            } else if (sender.isEmpty()) {
                writer.write(qualifier.getResult());
            } else {
                writer.write(qualifier.getResult());
                writer.write(" smtp.mailfrom=");
                writer.write(sender);
            }
            for (DKIM.Signature signature : signatureList) {
                writer.write(";\r\n\tdkim=");
                writer.write(signature.getResult());
                if (signature.hasIdentity()) {
                    writer.write(" header.i=");
                    writer.write(signature.getIdentity());
                }
            }
            writer.write("\r\n");
        }
        
        private void whiteReceivedSPF(FileWriter writer) throws IOException {
            if (sender.length() > 0) {
                writer.write("Received-SPF: ");
                writer.write(qualifier == null ? "none" : qualifier.getResult());
                writer.write(" (");
                writer.write(HOSTNAME);
                writer.write(": domain of ");
                writer.write(sender);
                if (qualifier == SPF.Qualifier.PASS) {
                    writer.write(" designates ");
                } else {
                    writer.write(" does not designate ");
                }
                writer.write(ip);
                writer.write(" as permitted sender)\r\n\t");
                writer.write("client-ip=");
                writer.write(ip);
                writer.write("; envelope-from=");
                writer.write(sender);
                writer.write("; helo=");
                writer.write(helo);
                writer.write(";\r\n");
                writer.flush();
            }
        }
        
        private void whiteReceivedSPFBL(
                FileWriter writer,
                User user, long timeKey,
                TreeSet<String> tokenSet
        ) throws IOException {
            try {
                String url = Core.getURL(user);
                String ticket = SPF.createTicket(timeKey, tokenSet);
                writer.write("Received-SPFBL: ");
                if (qualifier == null) {
                    writer.write("NONE");
                } else {
                    writer.write(qualifier.name());
                }
                writer.append(' ');
                if (url != null) {
                    writer.write(url);
                }
                writer.write(ticket);
                writer.write('\r');
                writer.write('\n');
                writer.flush();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void whiteUser(
                FileWriter writer,
                User user
        ) throws IOException {
            if (user != null) {
                writer.write("User: ");
                writer.write(user.getEmail());
                writer.write("\r\n");
                writer.flush();
            }
        }
        
        private void whiteReturnPathSMTP(
                FileWriter writer
        ) throws IOException {
            if (authenticated || qualifier == Qualifier.PASS) {
                writer.write("Return-Path: <");
                writer.write(sender);
                writer.write(">\r\n");
                writer.flush();
            } else {
                writer.write("Return-Path: <>\r\n");
                writer.flush();
            }
        }
        
        private void whiteReceivedSMTP(
                FileWriter writer,
                SSLSession sslSession,
                String recipient
        ) throws IOException {
            writer.write("Received: from ");
            if (fqdn == null) {
                writer.write(helo);
            } else {
                writer.write(fqdn);
            }
            writer.write(" ([");
            writer.write(ip);
            writer.write("] helo=");
            writer.write(helo);
            writer.write(") by ");
            writer.write(HOSTNAME);
            writer.write("\r\n\t");
            if (!extended) {
                writer.write("with smtp ");
            } else if (sslSession == null) {
                writer.write("with esmtp ");
            } else {
                Certificate[] certificates = sslSession.getLocalCertificates();
                X509Certificate certificate = (X509Certificate) certificates[0];
                RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
                writer.write("with esmtp (");
                writer.write(sslSession.getProtocol());
                writer.write(':');
                writer.write(sslSession.getCipherSuite());
                writer.write(':');
                writer.write(Integer.toString(publicKey.getModulus().bitLength() / 8));
                writer.write(") ");
            }
            writer.write("(SPFBL ");
            writer.write(Core.getSubVersion());
            writer.write(")\r\n\t");
            writer.write("(envelope-from <");
            writer.write(sender);
            writer.write(">)\r\n\t");
            writer.write("id ");
            writer.write(Long.toString(queueID,32));
            writer.write(" for ");
            writer.write(recipient);
            writer.write(";\r\n\t");
            writer.write(Core.getEmailDate(queueID));
            writer.write("\r\n");
            writer.flush();
        }
        
        private void whiteDeliveryStatusSMTP(
                FileWriter writer,
                String recipient
        ) throws IOException {
            writer.write("Reporting-MTA: dns; ");
            writer.write(HOSTNAME);
            writer.write("\r\n");
            writer.flush();
            writer.write("Arrival-Date: ");
            writer.write(Core.getEmailDate(queueID));
            writer.write("\r\n");
            writer.flush();
            writer.write("Final-Log-ID: ");
            writer.write(Long.toString(queueID,32));
            writer.write('@');
            writer.write(HOSTNAME);
            writer.write("\r\n");
            writer.flush();
            writer.write("Original-Recipient: rfc822; ");
            writer.write(recipient);
            writer.write("\r\n");
            writer.flush();
            writer.write("Final-Recipient: rfc822; ");
            writer.write(recipient);
            writer.write("\r\n");
            writer.flush();
            writer.write("Action: relayed\r\n");
            writer.flush();
            writer.write("Status: 2.0.0\r\n");
            writer.flush();
        }
    }
    
    private static final InternetAddress MAILER_DAEMON = createMailerDaemonAddress();
    
    private static InternetAddress createMailerDaemonAddress() {
        try {
            return new InternetAddress("MAILER-DAEMON", "Mail Delivery System");
        } catch (UnsupportedEncodingException ex) {
            return null;
        }
    }
    
    public static InternetAddress extractInternetAddress(String value, boolean valid) {
        if (value == null) {
            return null;
        } else if (value.startsWith("rfc822;")) {
            return extractInternetAddress(value.substring(7).trim(), valid);
        } else {
            try {
                try {
                    value = MimeUtility.decodeText(value.trim());
                } catch (UnsupportedEncodingException ex) {
                    Server.logTrace("malformed email address: " + value);
                }
                InternetAddress[] addresses;
                if (value.startsWith("Mail Delivery System <Mailer-Daemon@")) {
                    addresses = new InternetAddress[1];
                    addresses[0] = MAILER_DAEMON;
                } else if (value.contains("System Administrator") && !value.contains("<")) {
                    addresses = new InternetAddress[1];
                    addresses[0] = MAILER_DAEMON;
                } else {
                    addresses = InternetAddress.parse(value);
                }
                if (addresses.length == 0) {
                    return null;
                } else {
                    InternetAddress address = addresses[0];
                    String email = address.getAddress().toLowerCase();
                    String emailUpper = email.toUpperCase();
                    if (emailUpper.equals("MAILER-DAEMON")) {
                        return address;
                    } else if (emailUpper.startsWith("SRS0=") || emailUpper.startsWith("SRS0+")) {
                        int index1 = email.lastIndexOf('@');
                        int index2 = email.lastIndexOf('=', index1);
                        if (index2 > 0) {
                            int index3 = email.lastIndexOf('=', index2-1);
                            if (index3 > 0) {
                                String part = email.substring(index2+1, index1);
                                String domain = email.substring(index3+1, index2);
                                email = part + '@' + domain;
                            }
                        }
                    }
                    if (valid && isValidEmail(email)) {
                        address.setAddress(email.toLowerCase());
                        return address;
                    } else if (!valid && Domain.isMailFrom(email)) {
                        address.setAddress(email);
                        return address;
                    } else {
                        return null;
                    }
                }
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    private static String extractAddress(String[] array, boolean valid) {
        if (array == null) {
            return null;
        } else {
            for (String value : array) {
                String address = extractAddress(value, valid);
                if (address != null) {
                    return address;
                }
            }
            return "";
        }
    }
    
    public static String extractEmail(String value, boolean valid) {
        if (value == null) {
            return null;
        } else {
            int endIndex = value.lastIndexOf('>');
            if (endIndex == -1) {
                return null;
            } else {
                int beginIndex = value.lastIndexOf('<', endIndex);
                if (beginIndex == -1) {
                    return null;
                } else {
                    value = value.substring(beginIndex, endIndex + 1);
                    value = value.replace("\"", "");
                    value = value.replace("!", "");
                    value = value.replace(".@", "@");
                    InternetAddress address = extractInternetAddress(value, valid);
                    if (address == null) {
                        return null;
                    } else {
                        return address.getAddress();
                    }
                }
            }
        }
    }
    
    public static String extractAddress(String value, boolean valid) {
        if (value == null) {
            return null;
        } else if (value.startsWith("rfc822;")) {
            return extractAddress(value.substring(7).trim(), valid);
        } else {
            value = Core.tryToDecodeMIME(value.trim());
            InternetAddress address = extractInternetAddress(value, valid);
            if (address == null) {
                return extractEmail(value, valid);
            } else {
                return address.getAddress();
            }
        }
    }
    
    private static String extractSubject(String value) {
        try {
            value = MimeUtility.decodeText(value.trim());
        } catch (UnsupportedEncodingException ex) {
            Server.logTrace("malformed encoded subject: " + value);
        }
        return Dictionary.normalizeCharacters(value);
    }
    
    public static String extractMessageID(MimeMessage message) {
        if (message == null) {
            return null;
        } else {
            try {
                String[] array = message.getHeader("Message-ID");
                return ServerSMTP.extractMessageID(array);
            } catch (MessagingException ex) {
                return null;
            }
        }
    }
    
    public static String extractMessageID(String[] array) {
        if (array == null) {
            return null;
        } else {
            for (String value : array) {
                String messageID = extractMessageID(value);
                if (messageID != null) {
                    return messageID;
                }
            }
            return null;
        }
    }
    
    private static String extractMessageID(String value) {
        if (value == null) {
            return null;
        } else {
            int index1 = value.indexOf('<');
            int index2 = value.indexOf('>');
            if (index1 >= 0 && index2 > 0) {
                value = value.substring(index1 + 1, index2);
                return value.replaceAll("[\\r\\n\\t]+", "");
            } else if (index1 > -1 || index2 > -1) {
                return null;
            } else {
                return value.replaceAll("[\\r\\n\\t]+", "");
            }
        }
    }
    
    private static Date extractDate(String value) {
        if (value == null) {
            return null;
        } else {
            return Core.parseEmailDateSafe(value.trim());
        }
    }
    
    private static URL extractUnsubscribe(Message message) {
        if (message == null) {
            return null;
        } else {
            try {
                String[] values = message.getHeader("List-Unsubscribe");
                if (values == null) {
                    return null;
                } else {
                    for (String value : values) {
                        URL url = extractUnsubscribe(value);
                        if (url != null) {
                            return url;
                        }
                    }
                }
                return null;
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    private static URL extractUnsubscribe(String value) {
        try {
            StringTokenizer tokenizer = new StringTokenizer(value, ",");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                int index = token.indexOf('<');
                if (index >= 0) {
                    token = token.substring(index + 1);
                    index = token.indexOf('>');
                    if (index > 0) {
                        token = token.substring(0, index);
                        token = token.replaceFirst("^mailto;", "mailto:");
                        return new URL(token);
                    }
                }
            }
            return null;
        } catch (MalformedURLException ex) {
            Server.logTrace("malformed unsubscribe URL: " + value);
            return null;
        }
    }
    
    @Override
    protected void close() throws Exception {
        Connection connection;
        while ((connection = last()) != null) {
            connection.interrupt();
        }
        if (SERVERS != null) {
            Server.logInfo("unbinding querie SMTPS socket on port " + PORTS + "...");
            SERVERS.close();
        }
        Server.logInfo("unbinding ESMTP server socket on port 25...");
        QUEUE.terminate();
        SERVER.close();
    }

    private static byte CONNECTION_LIMIT = 8;

    public static void setConnectionLimit(String limit) {
        if (limit != null && limit.length() > 0) {
            try {
                setConnectionLimit(Integer.parseInt(limit));
            } catch (Exception ex) {
                Server.logError("invalid ESMTP connection limit '" + limit + "'.");
            }
        }
    }

    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid ESMTP connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }

    private final LinkedList<Connection> CONNECTION_QUEUE = new LinkedList<>();
    private final LinkedList<Connection> CONNECTION_LIST = new LinkedList<>();
    
    private synchronized Connection poll() {
        return CONNECTION_QUEUE.poll();
    }
    
    private synchronized Connection last() {
        return CONNECTION_LIST.pollLast();
    }
    
    private synchronized Connection create() {
        Connection connection = null;
        int id = CONNECTION_LIST.size();
        if (id < CONNECTION_LIMIT) {
            connection = new Connection(id+1);
            connection.start();
            CONNECTION_LIST.add(connection);
        }
        return connection;
    }
    
    private synchronized boolean offerConnection(Connection connection) {
        if (connection == null) {
            return false;
        } else {
            if (CONNECTION_LIST.isEmpty()) {
                CONNECTION_QUEUE.offer(connection);
                ServerSMTP.this.notify();
                return true;
            } else if (CONNECTION_QUEUE.size() < 2) {
                CONNECTION_QUEUE.offer(connection);
                ServerSMTP.this.notify();
                return true;
            } else if (connection == CONNECTION_LIST.getLast()) {
                connection.interrupt();
                CONNECTION_LIST.removeLast();
                return false;
            } else {
                CONNECTION_QUEUE.offer(connection);
                ServerSMTP.this.notify();
                return true;
            }
        }
    }
    
    private Connection pollConnection() {
        Connection connection = poll();
        if (connection == null) {
            try {
                synchronized (ServerSMTP.this) {
                    ServerSMTP.this.wait(1000);
                }
            } catch (InterruptedException ex) {
                // Do nothing.
            }
            if ((connection = poll()) == null) {
                connection = create();
            }
        }
        return connection;
    }
    
    private long LAST = System.currentTimeMillis();
    
    private synchronized void dropConnections() {
        if ((System.currentTimeMillis() - LAST) > 10000) {
            LAST = System.currentTimeMillis();
            for (Connection connection : CONNECTION_LIST) {
                connection.drop();
            }
        }
    }
}
